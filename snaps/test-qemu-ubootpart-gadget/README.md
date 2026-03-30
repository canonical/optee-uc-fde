# test-qemu-ubootpart-gadget

Reference gadget snap for QEMU & OP-TEE integration testing using the
**ubootpart** bootloader. This stores the U-Boot environment in a dedicated
raw partition (`system-boot-state` role) with redundancy support, rather than
in a file on the `system-boot` FAT filesystem.

## Differences from test-qemu-optee-gadget

The existing `test-qemu-optee-gadget` uses the standard `uboot` bootloader,
which stores the environment as `boot.sel` on the `ubuntu-boot` FAT partition.
This gadget uses the `ubootpart` bootloader instead:

| | test-qemu-optee-gadget | test-qemu-ubootpart-gadget |
|---|---|---|
| Environment storage | File on FAT (`boot.sel`) | Raw partition (`ubuntu-boot-state`) |
| Bootloader marker | `uboot.conf` | N/A |
| Redundancy | None (single file) | Two env copies in raw partition |
| Runtime persistence | snapd writes file on FAT | snapd writes raw partition device |

## Partition layout

The gadget defines a GPT disk with:

- **ubuntu-boot-state** (`system-boot-state`, raw) — redundant U-Boot environment
- **ubuntu-seed** (`system-seed`, FAT) — recovery and install kernels
- **ubuntu-boot** (`system-boot`, FAT) — run-mode kernel assets
- **ubuntu-save** (`system-save`, ext4) — encrypted device state
- **ubuntu-data** (`system-data`, ext4) — user data

The boot-state partition is placed before ubuntu-seed because, during factory
reset, snapd re-creates any ubuntu-* partition after ubuntu-seed. Placing
boot-state after ubuntu-boot would leave it in the middle, potentially blocking
options for resizing ubuntu-boot.

The `ubuntu-boot-state` partition uses GPT type GUID
`3DE21764-95BD-54BD-A5C3-4ABE786F38A8` and holds two 8 KiB environment copies
(matching `DefaultRedundantEnvSize` in snapd).

## Boot script

The boot script (`boot.cmd`) reads and writes the environment using block-level
I/O rather than filesystem commands:

1. Finds `ubuntu-boot-state` by GPT partition name using `part number`
2. Reads the raw partition with `${devtype} read` (e.g. `virtio read`)
3. Imports variables with `env import -c`
4. On kernel status changes, exports and writes back with `${devtype} write`

The kernel command line includes `snapd_system_disk=vda` so that snapd can
locate the boot-state partition at runtime without scanning all disks.

## Building

```
cd snaps/test-qemu-ubootpart-gadget
snapcraft
```

Requires `snapcraft` with the `core24` base. The build cross-compiles for
arm64 on amd64 and fetches U-Boot, OP-TEE OS, and ARM Trusted Firmware from
upstream repositories.

This also requires the ubootpart feature to be in snapd, so see HACKING.md for
a workaround.

## Related snapd changes

This gadget requires the `ubootpart` bootloader support in snapd, which adds:

- `bootloader/ubootpart.go` — partition-based U-Boot environment bootloader
- `bootloader/ubootenv` — redundant environment read/write support
- `gadget` — `system-boot-state` role validation
- `image` — boot state partition content generation at prepare-image time
