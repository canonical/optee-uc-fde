# Expects to be called with the following environment variables set:
#
#  devtype              e.g. virtio/mmc/scsi etc
#  devnum               The device number of the given type
#  distro_bootpart      The partition containing the boot files
#                       (introduced in u-boot mainline 2016.01)
#  prefix               Prefix within the boot partition to the boot files
#
# The U-Boot environment is stored in the raw ubuntu-boot-state partition.
# The boot script reads and writes it using block-level I/O (rather than
# filesystem commands), since there is no filesystem on that partition.
# At runtime, snapd handles persistence from Linux userspace.

fdt addr ${fdtcontroladdr}

setenv qemu_fdt_addr 0x40000000
setenv fit_addr_r 0x50000000

setenv kernel_filename kernel.img
setenv kernel_bootpart ${distro_bootpart}

# Env size: two copies of 0x2000 (8 KiB) each = 0x4000 total = 32 sectors
setenv env_size_bytes 0x2000
setenv env_total_sectors 0x20

# Find the ubuntu-boot-state partition and read the environment
part number ${devtype} ${devnum} ubuntu-boot-state bootstate_part
part start ${devtype} ${devnum} ${bootstate_part} bootstate_start

${devtype} read ${kernel_addr_r} ${bootstate_start} ${env_total_sectors}

setenv kernel_vars "snap_kernel snap_try_kernel kernel_status"
setenv recovery_vars "snapd_recovery_mode snapd_recovery_system snapd_recovery_kernel"
setenv snapd_recovery_mode "install"
# Tell snapd which disk holds the boot-state partition so it does not
# have to scan all disks.  On QEMU virt the virtio disk is /dev/vda.
setenv snapd_standard_params "panic=-1 systemd.gpt_auto=0 snapd.debug=1 snapd_system_disk=vda systemd.journald.forward_to_console=1 console=ttyAMA0"

env import -c ${kernel_addr_r} ${env_size_bytes} ${recovery_vars}

if test "${snapd_recovery_mode}" = "run"; then
  setenv snapd_recovery_mode_verified "run"
elif test "${snapd_recovery_mode}" = "install"; then
  setenv snapd_recovery_mode_verified "install"
elif test "${snapd_recovery_mode}" = "recover"; then
  setenv snapd_recovery_mode_verified "recover"
else
  setenv snapd_recovery_mode_verified "install"
fi

if test "${snapd_recovery_system}" ~= "^[a-zA-Z0-9-_]*$"; then
  setenv snapd_recovery_system_verified "${snapd_recovery_system}"
fi

setenv bootargs "${bootargs} snapd_recovery_mode=${snapd_recovery_mode_verified} snapd_recovery_system=${snapd_recovery_system_verified} ${snapd_standard_params}"

if test -z "${fk_image_locations}"; then
  setenv fk_image_locations ${prefix}
fi

if test "${snapd_recovery_mode}" = "run"; then
  setexpr kernel_bootpart ${distro_bootpart} + 1

  env import -c ${kernel_addr_r} ${env_size_bytes} ${kernel_vars}
  setenv kernel_name "${snap_kernel}"

  if test -n "${kernel_status}"; then
    if test "${kernel_status}" = "try"; then
      if test -n "${snap_try_kernel}"; then
        setenv kernel_status trying
        setenv kernel_name "${snap_try_kernel}"
      fi
    elif test "${kernel_status}" = "trying"; then
      setenv kernel_status ""
    fi
    env export -c ${kernel_addr_r} ${env_size_bytes} ${kernel_vars}
    ${devtype} write ${kernel_addr_r} ${bootstate_start} ${env_total_sectors}
  fi

  for pathprefix in ${fk_image_locations}; do
    setenv kernel_prefix "${pathprefix}uboot/ubuntu/${kernel_name}/"
  done
else
  for pathprefix in ${fk_image_locations}; do
    setenv kernel_prefix "${pathprefix}systems/${snapd_recovery_system}/kernel/"
  done
fi

load ${devtype} ${devnum}:${kernel_bootpart} ${fit_addr_r} ${kernel_prefix}${kernel_filename}

# we use the kernel and initrd from the FIT on disk, and the device tree
# provided by the firmware/qemu
bootm ${fit_addr_r} ${fit_addr_r} ${qemu_fdt_addr}
