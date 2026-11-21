# lpehunt

*(formerly `lpecheck`)*

A detection-only scanner for known Linux local privilege-escalation CVEs. Point
it at a host you have a shell on and it tells you which public LPE bugs that box
is plausibly vulnerable to (sudo, polkit, snapd, PackageKit, udisks, the kernel,
and more) without running a single exploit.

It is built to be the second opinion on linPEAS: every CVE that current linPEAS
flags has a row here, and lpehunt decides it with real NVD ranges, distro
backports and exploit preconditions. A linPEAS hit therefore ends up either
confirmed or explained as a false positive.

## Get it on the box

```sh
curl -sL https://raw.githubusercontent.com/ksmtp/lpehunt/main/lpehunt.sh | bash
# or
wget -q https://raw.githubusercontent.com/ksmtp/lpehunt/main/lpehunt.sh && bash lpehunt.sh -v
```

No internet on the target: download it on your machine, serve it
(`python3 -m http.server`), and `curl http://<you>:8000/lpehunt.sh | bash`.

## What it does

- **Detection only.** Contains no exploit code and writes nothing: no temp
  files, no here-docs. It reads files and runs version queries.
- **Version- and backport-aware.** It goes past upstream version ranges and
  accounts for distro backports: dpkg fix versions, rpm/deb changelog
  entries, and Ubuntu kernel ABI tables per series (including EOL HWE series
  that never got a fix). Ubuntu kernels are judged by their ABI. linPEAS
  turns `7.0.0-34-generic` into "7.0.34", but lpehunt does not.
- **Precondition-aware.** Kernel bugs are only reported if the attack surface is
  there:
  - the module is loadable and not disabled in modprobe.d (code built into
    the kernel can't be disabled that way, and lpehunt knows that);
  - the `CONFIG_*` option is set (read from `/boot/config-*` or
    `/proc/config.gz`);
  - unprivileged user namespaces work;
  - the relevant sysctls allow it (`ptrace_scope`, `io_uring_disabled`,
    `unprivileged_bpf_disabled`, `legacy_tiocsti`, …).

  Userspace bugs are checked the same way: SUID or file-capability binaries,
  D-Bus services, fstab entries, writable log dirs, listening telnetd, and so on.
- **Tiered findings** so you know how much to trust each one:
  - `CONFIRMED`: a safe probe demonstrated the vulnerable behaviour
  - `LIKELY`: in range, preconditions met, fix provably absent
  - `POSSIBLE`: in range but undecidable (collapsed into one line)

The only active probes are safe, non-destructive, and never prompt (for example
the patched-build usage check for Baron Samedit). Use `--no-probes` to skip even
those.

## Coverage (v1.3, 106 checks)

- **Kernel 2025–2026:**
  - Dirty Frag (xfrm and rxrpc), Fragnesia, DirtyClone, pedit COW, Copy Fail,
    DirtyDecrypt.
  - ptrace exit-race, GhostLock, BadGarbage, Bad Epoll, OVSwrap.
  - CIFSwitch, DiagSpill, SCTPhantom, ZcopyReaper, VsockDrop.
  - XFSTango, RefluXFS, IPv6 fraggap, CrackArmor, the OVS page-cache chain.
  - net/sched, nf_tables catchall, AF_ALG, ALSA UMP, AF_UNIX MSG_OOB,
    posix-cpu-timers, Attack of the Vsock.
- **Kernel classics:**
  - DirtyCow, DirtyPipe, nf_tables (2024-1086 and 5 more), GameOver(lay).
  - OverlayFS, Sequoia, StackRot, io_uring, watch_queue, openvswitch, eBPF,
    af_packet, DCCP, RDS, iSCSI, keyring, PTRACE_TRACEME.
- **Userspace:**
  - sudo (Samedit, chroot, host, sudoedit, pwfeedback, -u#-1).
  - PwnKit, polkit D-Bus, Looney Tunables, snap-confine (dirty_sock, 8933,
    3888), Pack2TheRoot.
  - udisks2/libblockdev and SUSE PAM, UDisks fstab, AccountsService,
    systemd-homed, systemd pager, needrestart.
  - inetutils telnetd, below, netdata ndsudo, runc Leaky Vessels, OpenDoas.
  - Exim, screen, chkrootkit, nginx log dir, Xorg, Enlightenment.

## Usage

```sh
bash lpehunt.sh [-v] [--tsv] [--no-probes]
```

- `-v`: also list every CVE that was ruled out, with the reason (this is
  the line to read when linPEAS flags something lpehunt does not)
- `--tsv`: machine-readable output (`STATUS<TAB>CVE<TAB>component<TAB>path<TAB>reason`)
- `--no-probes`: version/package logic only; runs no `sudo`/`unshare` probes

Needs bash 3+, coreutils, grep, and find (gzip optional, for changelogs and
`/proc/config.gz`).

## Authorized use only

For use on systems you own or have **written permission** to test (pentest
engagements, CTFs, lab work, your own machines). You are responsible for how you
use it.
