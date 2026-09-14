# AQUOS R6 GhostLock temporary root

Device-specific Linux 5.4 port of GhostLock (CVE-2026-43499) for the Sharp
AQUOS R6. The validated target is the SoftBank A101SH (`Judau`) running
Android 11 build `S0029 / 01.00.06`, kernel `5.4.61-qgki`.

The `ghostlock54` target obtains real UID/GID 0, changes SELinux to permissive,
and opens an interactive root shell directly over the existing ADB transport.
It does not listen on TCP and does not grant a full Linux capability set.

## Build

An AArch64 GNU cross compiler is required:

```sh
make build/ghostlock54
```

## Run

```sh
adb push build/ghostlock54 /data/local/tmp/ghostlock54
adb shell chmod 755 /data/local/tmp/ghostlock54
adb shell -t /data/local/tmp/ghostlock54
```

Use `--leak-only` and `--leak-y-only` for the non-destructive preflight stages
described in [VERIFICATION.md](VERIFICATION.md).

## Important safety notes

- This is calibrated for the exact device/build above. Do not run it on other
  kernels without independently validating every offset and stack geometry.
- After successful exploitation, kernel PI references point into a live worker
  thread's stack. Do not kill the parked exploit process as normal cleanup.
- After `exit`, interrupt only the host-side ADB client if it remains waiting.
- Reboot the device to return to the normal kernel state.
- Use only on hardware you own or are explicitly authorized to test.

Detailed measurements and observed results are in
[VERIFICATION.md](VERIFICATION.md). Text captures used for the S0029
calibration are retained under `build/`; compiled build products are excluded
from Git history and supplied separately as release assets.

## License

Apache License 2.0. See [LICENSE](LICENSE).
