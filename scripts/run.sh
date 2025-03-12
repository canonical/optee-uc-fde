#!/bin/bash

# This script should be used to run the system that is built by build.sh. One
# can login to the booted system as the root user. If all goes well,
# tee-supplicant should be running, and /dev/tee0 and /dev/teepriv0 should be
# available.

set -ex

artifacts=$(pwd)/op-tee-emulation/artifacts

qemu-system-aarch64 -nographic -machine virt,secure=on \
    -cpu cortex-a57 \
    -smp 2 -m 1024 -bios "${artifacts}/qemu_fw.bios" \
    -drive file="${artifacts}/disk.img",if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -d unimp
