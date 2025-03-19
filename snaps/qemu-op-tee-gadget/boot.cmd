# Expects to be called with the following environment variables set:
#
#  devtype              e.g. mmc/scsi etc
#  devnum               The device number of the given type
#  distro_bootpart      The partition containing the boot files
#                       (introduced in u-boot mainline 2016.01)
#  prefix               Prefix within the boot partiion to the boot files

fdt addr ${fdtcontroladdr}

setenv fit_addr_r 0x50000000

setenv kernel_filename kernel.img
setenv core_state "/uboot/ubuntu/boot.sel"
setenv kernel_bootpart ${distro_bootpart}

if test -z "${fk_image_locations}"; then
  setenv fk_image_locations ${prefix}
fi

for pathprefix in ${fk_image_locations}; do
  load ${devtype} ${devnum}:${distro_bootpart} ${kernel_addr_r} ${pathprefix}${core_state}

  setenv kernel_vars "snap_kernel snap_try_kernel kernel_status"
  setenv recovery_vars "snapd_recovery_mode snapd_recovery_system snapd_recovery_kernel"
  setenv snapd_recovery_mode "install"
  setenv snapd_standard_params "panic=-1 systemd.gpt_auto=0 snapd.debug=1 systemd.log_level=debug"

  env import -c ${kernel_addr_r} ${filesize} ${recovery_vars}
  setenv bootargs "${bootargs} snapd_recovery_mode=${snapd_recovery_mode} snapd_recovery_system=${snapd_recovery_system} ${snapd_standard_params}"

  if test "${snapd_recovery_mode}" = "run"; then
    setexpr kernel_bootpart ${distro_bootpart} + 1
    load ${devtype} ${devnum}:${kernel_bootpart} ${kernel_addr_r} ${pathprefix}${core_state}
    env import -c ${kernel_addr_r} ${filesize} ${kernel_vars}
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
      env export -c ${kernel_addr_r} ${kernel_vars}
      save ${devtype} ${devnum}:${kernel_bootpart} ${kernel_addr_r} ${pathprefix}${core_state} ${filesize}
    fi
    setenv kernel_prefix "${pathprefix}uboot/ubuntu/${kernel_name}/"
  else
    setenv kernel_prefix "${pathprefix}systems/${snapd_recovery_system}/kernel/"
  fi

  load ${devtype} ${devnum}:${kernel_bootpart} ${fit_addr_r} ${kernel_prefix}${kernel_filename}
  bootm ${fit_addr_r}
done
