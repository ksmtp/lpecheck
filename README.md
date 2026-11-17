# lpecheck

A detection-only scanner for known Linux local privilege-escalation CVEs. Point
it at a host you have a shell on and it tells you which public LPE bugs that box
is plausibly vulnerable to — sudo, polkit, the kernel, and more — without
running a single exploit.

## What it does

- **Detection only.** Contains no exploit code and writes nothing: no temp
  files, no here-docs. It reads files and runs version queries.
- **Version- and backport-aware.** It doesn't just compare upstream version
  ranges — it accounts for distro backports (dpkg/rpm fix versions, changelog
  entries, Ubuntu kernel ABI tables) to cut down false positives.
- **Tiered findings** so you know how much to trust each one:
  - `CONFIRMED` — a safe probe demonstrated the vulnerable behaviour
  - `LIKELY`    — in range, preconditions met, fix provably absent
  - `POSSIBLE`  — in range but undecidable (collapsed into one line)

The only active probes are safe, non-destructive, and never prompt (for example
the patched-build usage check for Baron Samedit). Use `--no-probes` to skip even
those.

## Usage

```sh
bash lpecheck.sh [-v] [--tsv] [--no-probes]
```

- `-v` — also list every CVE that was ruled out, with the reason
- `--tsv` — machine-readable output (`STATUS<TAB>CVE<TAB>component<TAB>path<TAB>reason`)
- `--no-probes` — version/package logic only; runs no `sudo`/`unshare` probes

Needs bash 3+, coreutils, grep, and find.

## Authorized use only

For use on systems you own or have **written permission** to test (pentest
engagements, CTFs, lab work, your own machines). You are responsible for how you
use it.
