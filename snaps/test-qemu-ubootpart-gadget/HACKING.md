# Building the ubootpart gadget snap

The `system-boot-state` role is not yet in released snapd, so the `snap pack`
validation step inside the snapcraft build container must use a custom `snap`
binary from the snapd branch that adds this role.

## Prerequisites

- `snapcraft` installed (classic snap)
- LXD configured for snapcraft

The part definitions below use snapcraft environment variables:

- `CRAFT_PART_INSTALL` — per-part install directory; files placed here are
  copied into the shared stage area
- `CRAFT_STAGE` — shared staging directory visible to all parts (after their
  dependencies have been staged)
- `CRAFT_PROJECT_DIR` — the project directory on the host, allowing a part to
  copy files back out of the build container

## Patching snap pack via a snapcraft part

Add the following part to `snapcraft.yaml` to build a custom `snap` binary
from the snapd branch with `system-boot-state` support. This replaces the
system `snap` binary via `dpkg-divert` so that it persists across snapcraft
rebuilds (which reinstall the `snapd` deb each time):

    snapd-override:
      plugin: nil
      source: https://github.com/<your-fork>/snapd.git
      source-type: git
      source-branch: <ubootpart-branch>
      build-snaps:
        - go/latest/stable
      override-build: |
        go build -o /tmp/snap-local ./cmd/snap
        dpkg-divert --local --rename --add /usr/bin/snap
        cp /tmp/snap-local /usr/bin/snap
        cp -a . "${CRAFT_PART_INSTALL}/snapd-src"
      stage:
        - snapd-src
      prime:
        - -*

Make sure other parts run after this one by adding `after: [snapd-override]`
to the first part in the build chain (e.g. `optee-fde`).

Then build normally:

    cd snaps/test-qemu-ubootpart-gadget
    snapcraft pack

All the heavy build steps (U-Boot, OP-TEE, ARM TF) are cached, so only the
gadget part and the pack step re-run after the first build.

The output is `test-qemu-ubootpart-gadget_v0.0.1_arm64.snap`.

## Rebuilding after snapd changes

If the snapd source changes, clean the `snapd-override` part to force a
rebuild:

    snapcraft clean snapd-override
    snapcraft pack

## Using a local ubuntu-image

To assemble a UC image from this gadget snap, ubuntu-image also needs the
`system-boot-state` support. Add a part that builds ubuntu-image inside the
snapcraft container and copies the binary back to the host project directory:

    ubuntu-image-local:
      after: [snapd-override]
      plugin: nil
      source: https://github.com/canonical/ubuntu-image.git
      source-type: git
      source-branch: main
      build-snaps:
        - go/latest/stable
      override-build: |
        go mod edit -replace github.com/snapcore/snapd="${CRAFT_STAGE}/snapd-src"
        go mod tidy
        go build -o "${CRAFT_PROJECT_DIR}/ubuntu-image" ./cmd/ubuntu-image
      prime:
        - -*

The `go mod edit -replace` points at the snapd source staged by the
`snapd-override` part, so ubuntu-image builds against the version with
`system-boot-state` support.

After building, `ubuntu-image` appears in the project directory on the host.
Use it to assemble the UC image:

    ./ubuntu-image snap <model-assertion>

## Removing the override

Once `system-boot-state` support lands in released snapd, remove the
`snapd-override` and `ubuntu-image-local` parts from `snapcraft.yaml` and the
`after:` references to them.
