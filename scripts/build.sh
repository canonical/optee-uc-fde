#!/bin/bash

# This script helps build the necessary pieces to emulate an armv8 system that
# uses OP-TEE as the implementation of the Trusted Execution Environment.
#
# First, we build a FIP (firmware image package) that contains the OP-TEE
# kernel, a trusted application (built in via early TA), and u-boot. This FIP
# image is given to QEMU as the system's firmware.
#
# Next, we build a disk image that contains a Linux kernel, an initrd, and a
# u-boot script. This disk image is given to QEMU as a storage device. The
# u-boot instance in the FIP image will automatically find the u-boot script
# from the disk image and boot the system.
#
# $PWD/op-tee-emulation/artifacts will be populated with the built kernel,
# initrd, FIP, and disk image. Removing any of these files will cause them to be
# rebuilt when re-running this script.
#
# Required packages: u-boot-tools qemu-utils qemu-system-arm git bison flex
# python3-pyelftools

set -exu

root=$(pwd)/op-tee-emulation
artifacts="${root}/artifacts"
mkdir -p "${root}" "${artifacts}"
cd "${root}"

function setup_toolchain() {
    # this check isn't super robust, this directory might exist if we were
    # stopping while downloading the toolchains.
    if [ -d "${root}/toolchains" ]; then
        export PATH="${root}/toolchains/aarch32/bin:${root}/toolchains/aarch64/bin:${PATH}"
        return 0
    fi

    test -d build || git clone https://github.com/OP-TEE/build.git --depth=1
    pushd ./build
    make -f toolchain.mk -j"$(nproc)"
    popd

    export PATH="${root}/toolchains/aarch32/bin:${root}/toolchains/aarch64/bin:${PATH}"
}

function build_firmware() {
    if [ -f  "${artifacts}/qemu_fw.bios" ]; then
        return 0
    fi

    test -d u-boot || git clone https://github.com/u-boot/u-boot.git --depth=1
    test -d optee_os || git clone https://github.com/OP-TEE/optee_os.git --depth=1
    test -d optee_examples || git clone https://github.com/linaro-swg/optee_examples.git --depth=1
    test -d arm-trusted-firmware || git clone https://github.com/ARM-software/arm-trusted-firmware.git --depth=1

    # build u-boot, which will be used as the secondary bootloader
    pushd ./u-boot
    git clean -xdff
    make qemu_arm64_defconfig
    make CROSS_COMPILE=aarch64-linux-gnu- -j"$(nproc)"
    popd

    # build optee_os. we will rebuild this once we've built the trusted
    # application, since we're using early TA.
    pushd ./optee_os
    git clean -xdff

    # here we use PLATFORM=vexpress-qemu_armv8a. this platform is specific to
    # the device we're targeting, and in this case we're targeting QEMU's virt
    # platform, with the cortex-a57 CPU. setting this value results in op-tee
    # being compiled/configured to work specifically with the emulated device.
    make PLATFORM=vexpress-qemu_armv8a CFG_TEE_CORE_LOG_LEVEL=4 DEBUG=1 CFG_EARLY_CONSOLE=y -j"$(nproc)"
    popd

    # build the trusted application. this is just the secure-world side. the
    # client side isn't used in this example, but it wouldn't be built into the
    # firmware anyways
    #
    # note that building the TA requires that optee_os has been built already
    # (see TA_DEV_KIT_DIR). once we build the TA, we build optee_os again, which
    # embeds the TA into the op-tee kernel.
    pushd ./optee_examples/hello_world/ta
    git clean -xdff
    make CROSS_COMPILE=aarch64-linux-gnu- PLATFORM=vexpress-qemu_armv8a \
        TA_DEV_KIT_DIR="${root}/optee_os/out/arm-plat-vexpress/export-ta_arm64/" -j"$(nproc)"
    popd

    # build optee_os again, this time we're passing in the trusted application
    # as an early TA with EARLY_TA_PATHS.
    pushd ./optee_os
    make PLATFORM=vexpress-qemu_armv8a CFG_TEE_CORE_LOG_LEVEL=4 DEBUG=1 CFG_EARLY_CONSOLE=y CFG_EARLY_TA=y \
        EARLY_TA_PATHS="${root}/optee_examples/hello_world/ta/8aaaf200-2450-11e4-abe2-0002a5d5c51b.elf" -j"$(nproc)"
    popd

    # build the trusted firmware. the main output of this is the FIP image,
    # which contains the op-tee kernel, the trusted application, and u-boot.
    pushd ./arm-trusted-firmware
    git clean -xdff
    make CROSS_COMPILE=aarch64-linux-gnu- PLAT=qemu DEBUG=1 SPD=opteed \
        BL32="${root}/optee_os/out/arm-plat-vexpress/core/tee-header_v2.bin" \
        BL32_EXTRA1="${root}/optee_os/out/arm-plat-vexpress/core/tee-pager_v2.bin" \
        BL32_EXTRA2="${root}/optee_os/out/arm-plat-vexpress/core/tee-pageable_v2.bin" \
        BL33="${root}/u-boot/u-boot.bin" \
        all fip -j"$(nproc)"
    popd

    cp "${root}/arm-trusted-firmware/build/qemu/debug/qemu_fw.bios" "${artifacts}/qemu_fw.bios"
}

function build_kernel_and_initrd() {
    if [ -f  "${artifacts}/vmlinux" ] && [ -f  "${artifacts}/initrd.img" ]; then
        return 0
    fi

    rm -f "${artifacts}/vmlinux" "${artifacts}/initrd.img"

    # TODO: convert this to use an Ubuntu rootfs and kernel

    # buildroot.config tells buildroot that we want to use an optee_client from
    # a tarball. this lets us use the tip of all the op-tee repos.
    test -d optee_client || git clone https://github.com/OP-TEE/optee_client.git --depth=1
    tar --exclude-vcs -cvf optee_client.tar -C optee_client/ .

    test -d buildroot || git clone git://git.buildroot.net/buildroot.git --depth=1

    pushd ./buildroot
    git clean -xdff

    # this config contains some information specific to the toolchain that we
    # configured things to use earlier. specifically,
    # BR2_TOOLCHAIN_EXTERNAL_GCC_11 and BR2_TOOLCHAIN_EXTERNAL_HEADERS_4_20.
    # things might break if the downloaded toolchain no longer matches this
    # config.
    #
    # buildroot.config is "make qemu_aarch64_virt_defconfig" with a few changes:
    #   - uses an externally provided toolchain, downloaded by setup_toolchain
    #   - installs tee-supplicant, which runs on boot
    #   - enables CONFIG_TEE and CONFIG_OPTEE in the kernel. these are set in
    #     ${root}/../configs/kernel-fragment.config
    cp "${root}/../configs/buildroot.config" .config
    ./utils/add-custom-hashes
    make -j"$(nproc)"

    cp ./output/images/Image "${artifacts}/vmlinux"

    # TODO: use a FIT image here, rather than separate initrd and kernel, that
    # is more in line with how we'd do this in production
    mkimage -A arm64 -T ramdisk -d ./output/images/rootfs.cpio "${artifacts}/initrd.img"

    popd
}

function build_disk_image() {
    cat > boot.cmd << 'EOF'
virtio dev 0
setenv fdt_addr_r 0x40000000
ext4load virtio 0:1 ${kernel_addr_r} /vmlinux
ext4load virtio 0:1 ${ramdisk_addr_r} /initrd.img
setenv bootargs "console=ttyAMA0,38400 keep_bootcon"
booti ${kernel_addr_r} ${ramdisk_addr_r} ${fdt_addr_r}
EOF

    rm -f ./boot.scr
    # this converts the boot.cmd text file into a format that u-boot understands
    mkimage -A arm64 -T script -d boot.cmd boot.scr

    rm -f ./disk.img
    qemu-img create -f raw disk.img 512M
    echo ",," | sfdisk --label=gpt ./disk.img

    loopback=$(sudo losetup -Pf --show ./disk.img)
    sudo mkfs.ext4 "${loopback}p1"

    mountpoint=$(mktemp -d)
    sudo mount "${loopback}p1" "${mountpoint}"

    sudo cp "${artifacts}/initrd.img" "${mountpoint}"
    sudo cp "${artifacts}/vmlinux" "${mountpoint}"

    # u-boot scans for a boot.scr file at the root of each partition, and it
    # will be loaded automatically on boot.
    sudo cp ./boot.scr "${mountpoint}"

    sudo umount "${mountpoint}"
    sudo losetup -d "${loopback}"

    mv disk.img "${artifacts}/disk.img"
}

setup_toolchain
build_firmware
build_kernel_and_initrd
build_disk_image
