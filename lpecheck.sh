#!/bin/bash
# lpecheck.sh - detect known Linux local privilege-escalation CVEs. DETECTION ONLY.
#
#   bash lpecheck.sh [-v] [--tsv] [--no-probes]
#   curl -s http://me/lpecheck.sh | bash            (| bash -s -- -v   for options)
#
#   -v           also list every CVE that was ruled out, with the reason
#   --tsv        machine-readable: STATUS<TAB>CVE<TAB>component<TAB>path<TAB>reason
#   --no-probes  version/package logic only: never runs sudo -l, sudoedit -s,
#                sudo -R or unshare (use if even a sudo log line is unwanted)
#
# Tiers
#   CONFIRMED  a safe probe showed the vulnerable behaviour
#   LIKELY     version in range, preconditions met, and the binary is source-built
#              (owned by no package) or the distro package provably lacks the fix
#              (dpkg version below the fixed version / changelog has no entry)
#   POSSIBLE   in range but undecidable (changelog missing or truncated, or a
#              precondition could not be read); collapsed into one line
#
# Safety: contains no exploit code and writes nothing (no temp files, no
# here-docs). It reads files and runs version queries. The only active probes:
#   sudoedit -n -s /             Baron Samedit: patched builds print usage
#   sudo -n -R <missing dir> true   CVE-2025-32463: vulnerable builds resolve the
#                                chroot before authorising (the dir does not exist,
#                                so nothing can be loaded from it)
#   sudo -n -l                   read sudo rules if no password is needed
#   unshare -Ur true             are unprivileged user namespaces usable
# sudo may log those invocations (-n never prompts). Nothing is crashed.
#
# Needs: bash 3+, coreutils, grep, find. gzip is used for Debian changelogs when
# present. No sed/awk/python.
#
# Adding a CVE: add a CVE_TABLE row; optionally a FIXDB row (tools/cvedata.py
# prints both data sets from NVD / the Ubuntu and Debian trackers).
#
# Changelog
#   1.0  first version: 32 rows, three tiers, dpkg/rpm backport detection,
#        Ubuntu kernel ABI table, safe probes for CVE-2021-3156 / CVE-2025-32463.
#   1.1  false negative on a source-built sudo installed over /usr/bin/sudo:
#        a package-owned path whose binary reports another upstream version is
#        now treated as source-built; FIXDB is skipped for packages built from
#        a newer upstream base than the series' fix (foreign .deb).
#   1.2  12 OSCP-typical rows: chkrootkit 0.49, nginx Debian log dir, SUID Xorg
#        -modulepath, Enlightenment enlightenment_sys, needrestart, systemd < 247
#        sudo pager, glibc $ORIGIN / LD_AUDIT, sock_sendpage, af_packet
#        (chocobo_root), DCCP, eBPF ALU32. FIXDB value "unfixed" = that release
#        never got a fix. Debian 5/6 (lenny/squeeze) codenames.

LPE_VERSION="1.2"

# id | name | component | affected | preconditions | probe | reference
#   affected: one or more "LO:FIX[,FIX...]" specs (upstream versions). Affected
#     when version >= LO and below the FIX of its own branch (x.y); a branch
#     with no FIX listed is affected up to the last FIX (EOL branch, never
#     fixed). "-" = no upstream range, FIXDB decides (distro-specific bugs).
#   preconditions: names of pre_* functions, all must hold.  probe: probe_* name.
CVE_TABLE='
CVE-2021-3156  | Baron Samedit (sudoedit -s heap overflow) | sudo | 1.8.2:1.8.32,1.9.5p2 | suid | samedit | https://www.sudo.ws/security/advisories/unescape_overflow/
CVE-2025-32463 | sudo --chroot nsswitch load (chwoot) | sudo | 1.9.14:1.9.17p1 | suid | chroot | https://www.sudo.ws/security/advisories/chroot_bug/
CVE-2025-32462 | sudo --host rule bypass | sudo | 1.8.8:1.9.17p1 | suid sudo_host_rule | - | https://www.sudo.ws/security/advisories/host_any/
CVE-2023-22809 | sudoedit EDITOR "--" arbitrary file edit | sudo | 1.8.0:1.9.12p2 | suid sudoedit_rule | - | https://www.sudo.ws/security/advisories/sudoedit_any/
CVE-2019-18634 | sudo pwfeedback buffer overflow | sudo | 1.7.1:1.8.26 | suid sudo_pwfeedback | - | https://www.sudo.ws/security/advisories/pwfeedback/
CVE-2019-14287 | sudo -u#-1 runas bypass | sudo | 0:1.8.28 | suid sudo_runas_notroot | - | https://www.sudo.ws/security/advisories/minus_1_uid/
CVE-2021-4034  | PwnKit (pkexec argv) | pkexec | 0:121 | suid kernel_lt_5_18 | - | https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
CVE-2021-3560  | polkit D-Bus authentication bypass | pkexec | 0.113:0.119 | polkit_dbus | - | https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/
CVE-2023-4911  | Looney Tunables (ld.so GLIBC_TUNABLES) | glibc | 2.34:2.39 | - | - | https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt
CVE-2017-5618  | GNU screen 4.5.0 SUID logfile | screen | 4.5.0:4.5.1 | suid | - | https://www.exploit-db.com/exploits/41154
CVE-2019-7304  | dirty_sock (snapd API) | snapd | 2.28:2.37.1 | snapd_socket | - | https://github.com/initstring/dirty_sock
CVE-2019-10149 | Exim "Return of the WIZard" | exim | 4.87:4.92 | suid | - | https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt
CVE-2016-1531  | Exim perl_startup environment | exim | 0:4.86.2 | suid exim_perl | - | https://www.exim.org/static/doc/CVE-2016-1531.txt
CVE-2016-5195  | DirtyCow | kernel | 2.6.22:3.2.83,3.4.113,3.10.104,3.12.66,3.16.38,3.18.44,4.1.35,4.4.26,4.7.9,4.8.3 | - | - | https://dirtycow.ninja/
CVE-2022-0847  | DirtyPipe | kernel | 5.8:5.10.102,5.15.25,5.16.11 | - | - | https://dirtypipe.cm4all.com/
CVE-2024-1086  | nf_tables verdict use-after-free | kernel | 3.15:4.19.307,5.4.269,5.10.210,5.15.149,6.1.76,6.6.15,6.7.3 | userns nft | - | https://github.com/Notselwyn/CVE-2024-1086
CVE-2023-2640/CVE-2023-32629 | GameOver(lay) Ubuntu OverlayFS | kernel | - | ubuntu userns overlay | - | https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability
CVE-2021-3493  | Ubuntu OverlayFS file capabilities | kernel | - | ubuntu userns overlay | - | https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/
CVE-2023-0386  | OverlayFS/FUSE setuid copy-up | kernel | 5.11:5.15.91,6.1.9,6.2 | userns overlay fuse | - | https://nvd.nist.gov/vuln/detail/CVE-2023-0386
CVE-2021-22555 | Netfilter x_tables heap out-of-bounds | kernel | 2.6.19:4.4.267,4.9.267,4.14.231,4.19.188,5.4.113,5.10.31,5.11.15,5.12 | userns | - | https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
CVE-2022-0185  | fs_context legacy_parse_param overflow | kernel | 5.1:5.4.173,5.10.93,5.15.16,5.16.2 | userns | - | https://www.willsroot.io/2022/01/cve-2022-0185.html
CVE-2022-2588  | cls_route use-after-free | kernel | 2.6.12:4.9.326,4.14.291,4.19.256,5.4.211,5.10.137,5.15.61,5.18.18,5.19.2 | userns cls_route | - | https://nvd.nist.gov/vuln/detail/CVE-2022-2588
CVE-2022-34918 | nf_tables set element type confusion | kernel | 4.1:4.14.316,4.19.284,5.4.244,5.10.130,5.15.54,5.18.11 | userns nft | - | https://nvd.nist.gov/vuln/detail/CVE-2022-34918
CVE-2023-32233 | nf_tables anonymous set use-after-free | kernel | 3.13:4.14.315,4.19.283,5.4.243,5.10.180,5.15.111,6.1.28,6.2.15,6.3.2 | userns nft | - | https://nvd.nist.gov/vuln/detail/CVE-2023-32233
CVE-2019-13272 | PTRACE_TRACEME via pkexec | kernel | 3.16.52:3.16.71 4.4.40:4.4.185 4.9.1:4.9.185 4.10:4.14.133,4.19.58,5.1.17 | pkexec_suid | - | https://nvd.nist.gov/vuln/detail/CVE-2019-13272
CVE-2017-16995 | eBPF verifier sign extension | kernel | 4.9:4.9.72,4.14.9 | ubpf | - | https://www.exploit-db.com/exploits/45010
CVE-2016-4557  | eBPF double fdput | kernel | 4.4:4.4.11,4.5.5 | ubpf | - | https://www.exploit-db.com/exploits/39772
CVE-2017-1000112 | UFO packet memory corruption | kernel | 2.6.15:3.10.108,3.16.47,3.18.65,4.4.82,4.9.43,4.12.7 | userns | - | https://nvd.nist.gov/vuln/detail/CVE-2017-1000112
CVE-2015-1328  | Ubuntu overlayfs (ofs) | kernel | - | ubuntu overlayfs | - | https://www.exploit-db.com/exploits/37292
CVE-2013-2094  | perf_swevent_init | kernel | 2.6.37:3.0.75,3.2.45,3.4.42,3.8.9 | - | - | https://www.exploit-db.com/exploits/25444
CVE-2012-0056  | Mempodipper (/proc/pid/mem) | kernel | 2.6.39:3.0.18,3.2.2 | - | - | https://www.exploit-db.com/exploits/18411
CVE-2010-3904  | RDS protocol | kernel | 2.6.30:2.6.36 | rds | - | https://www.exploit-db.com/exploits/15285
CVE-2014-0476  | chkrootkit 0.49 runs /tmp/update as root | chkrootkit | 0:0.50 | chkrootkit_root | - | https://www.exploit-db.com/exploits/33899
CVE-2016-1247  | nginx Debian log-dir symlink (www-data to root) | nginx | - | nginx_logdir | - | https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
CVE-2018-14665 | Xorg -modulepath / -logfile (SUID Xorg) | xorg | 1.19:1.20.3 | xorg_suid | - | https://www.exploit-db.com/exploits/45697
CVE-2022-37706 | Enlightenment enlightenment_sys mount injection | enlightenment | 0:0.25.4 | suid | - | https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit
CVE-2024-48990 | needrestart PYTHONPATH (also -48991/-48992/-11003) | needrestart | 0:3.8 | needrestart_root | - | https://www.qualys.com/2024/11/19/needrestart/needrestart.txt
CVE-2023-26604 | systemd < 247: sudo systemctl status pager (less) | systemd | 0:247 | sudo_systemctl | - | https://nvd.nist.gov/vuln/detail/CVE-2023-26604
CVE-2010-3847  | glibc $ORIGIN expansion (hardlinked SUID) | glibc | 0:2.11.3,2.12.2 | hardlinks | - | https://www.exploit-db.com/exploits/15274
CVE-2010-3856  | glibc LD_AUDIT (libpcprofile.so) | glibc | 0:2.11.3,2.12.2 | - | - | https://www.exploit-db.com/exploits/15304
CVE-2009-2692  | sock_sendpage NULL deref (wunderbar_emporium) | kernel | 2.4.4:2.4.37.5,2.6.30.5 | mmap_zero | - | https://www.exploit-db.com/exploits/9545
CVE-2016-8655  | af_packet race (chocobo_root) | kernel | 3.2:3.2.85,3.10.106,3.12.69,3.16.40,3.18.46,4.1.37,4.4.38,4.8.14 | userns | - | https://www.exploit-db.com/exploits/40871
CVE-2017-6074  | DCCP double free | kernel | 2.6.14:3.2.86,3.10.106,3.12.71,3.16.41,3.18.49,4.1.41,4.4.52,4.9.13 | dccp | - | https://www.exploit-db.com/exploits/41458
CVE-2021-3490  | eBPF ALU32 bounds tracking | kernel | 5.7:5.10.37,5.11.21,5.12.4 | ubpf | - | https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
'

# Distro fixed versions (backports). id | entries
#   codename=VER   package version that fixed it in that Debian/Ubuntu release;
#                  compared with dpkg --compare-versions.
#   codename=unfixed  that release never got a fix (vulnerable at any version).
#   k=VER          Ubuntu kernel ABI that fixed it, matched by series (5.4.0);
#                  k=5.8.0-EOL = that series went end-of-life unfixed.
#   A leading "!" on VER means the entry also applies outside the upstream
#   range (distro-specific bug or distro-specific backport of the bug).
FIXDB='
CVE-2021-3156  | trusty=1.8.9p5-1ubuntu1.5+esm6 xenial=1.8.16-0ubuntu1.10 bionic=1.8.21p2-3ubuntu1.4 focal=1.8.31-1ubuntu1.2 stretch=1.8.19p1-2.1+deb9u3 buster=1.8.27-1+deb10u3
CVE-2025-32463 | noble=1.9.15p5-3ubuntu5.24.04.1 trixie=1.9.16p2-3
CVE-2025-32462 | trusty=1.8.9p5-1ubuntu1.5+esm8 xenial=1.8.16-0ubuntu1.10+esm3 bionic=1.8.21p2-3ubuntu1.6+esm1 focal=1.8.31-1ubuntu1.5+esm1 jammy=1.9.9-1ubuntu2.5 noble=1.9.15p5-3ubuntu5.24.04.1 bullseye=1.9.5p2-3+deb11u2 bookworm=1.9.13p3-1+deb12u2 trixie=1.9.16p2-3
CVE-2023-22809 | trusty=1.8.9p5-1ubuntu1.5+esm7 xenial=1.8.16-0ubuntu1.10+esm1 bionic=1.8.21p2-3ubuntu1.5 focal=1.8.31-1ubuntu1.4 jammy=1.9.9-1ubuntu2.2 buster=1.8.27-1+deb10u5 bullseye=1.9.5p2-3+deb11u1
CVE-2019-18634 | trusty=1.8.9p5-1ubuntu1.5+esm3 xenial=1.8.16-0ubuntu1.9 bionic=1.8.21p2-3ubuntu1.2 jessie=1.8.10p3-1+deb8u7 stretch=1.8.19p1-2.1+deb9u2
CVE-2019-14287 | trusty=1.8.9p5-1ubuntu1.5+esm2 xenial=1.8.16-0ubuntu1.8 bionic=1.8.21p2-3ubuntu1.1 jessie=1.8.10p3-1+deb8u6 stretch=1.8.19p1-2.1+deb9u1 buster=1.8.27-1+deb10u1
CVE-2021-4034  | trusty=0.105-4ubuntu3.14.04.6+esm1 xenial=0.105-14.1ubuntu0.5+esm1 bionic=0.105-20ubuntu0.18.04.6 focal=0.105-26ubuntu1.2 jammy=0.105-31ubuntu1 stretch=0.105-18+deb9u2 buster=0.105-25+deb10u1 bullseye=0.105-31+deb11u1
CVE-2021-3560  | focal=!0.105-26ubuntu1.1
CVE-2023-4911  | jammy=2.35-0ubuntu3.4 bookworm=2.36-9+deb12u3
CVE-2017-5618  | stretch=4.5.0-3
CVE-2019-7304  | trusty=2.34.2~14.04.1 xenial=2.34.2ubuntu0.1 bionic=2.34.2+18.04.1
CVE-2019-10149 | bionic=4.90.1-1ubuntu1.2 stretch=4.89-2+deb9u4
CVE-2016-1531  | trusty=4.82-3ubuntu2.1 jessie=4.84.2-1
CVE-2016-5195  | k=3.2.0-113.155 k=3.13.0-100.147 k=4.4.0-45.66 k=4.8.0-26.28
CVE-2022-0847  | k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-35.40
CVE-2024-1086  | k=4.4.0-252.286 k=4.15.0-223.235 k=5.4.0-174.193 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.15.0-101.111 k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-26.26
CVE-2023-2640/CVE-2023-32629 | k=!5.4.0-155.172 k=!5.19.0-50.50 k=!6.2.0-26.26
CVE-2021-3493  | k=!4.4.0-209.241 k=!4.15.0-142.146 k=!5.3.0-73.69 k=!5.4.0-72.80 k=!5.8.0-50.56
CVE-2023-0386  | k=5.11.0-EOL k=5.13.0-EOL k=5.15.0-70.77 k=5.19.0-41.42
CVE-2021-22555 | k=3.13.0-187.238 k=4.4.0-213.245 k=4.15.0-144.148 k=5.4.0-74.83 k=5.8.0-55.62
CVE-2022-0185  | k=5.4.0-96.109 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-27.29
CVE-2022-2588  | k=3.13.0-191.242 k=4.4.0-231.265 k=4.15.0-191.202 k=5.4.0-124.140 k=5.15.0-46.49
CVE-2022-34918 | k=4.4.0-230.264 k=4.15.0-191.202 k=5.4.0-124.140 k=5.15.0-43.46
CVE-2023-32233 | k=4.4.0-241.275 k=4.15.0-212.223 k=5.4.0-150.167 k=5.15.0-73.80 k=5.19.0-43.44
CVE-2019-13272 | k=4.4.0-159.187 k=4.15.0-58.64 k=5.0.0-25.26
CVE-2017-16995 | k=!4.4.0-119.143 k=4.13.0-32.35
CVE-2016-4557  | k=4.4.0-22.39
CVE-2017-1000112 | k=3.13.0-128.177 k=4.4.0-91.114 k=4.10.0-32.36
CVE-2015-1328  | k=!3.2.0-86.123 k=!3.13.0-55.92 k=!3.16.0-41.55 k=!3.19.0-21.21
CVE-2014-0476  | trusty=0.49-4.1ubuntu1.14.04.1
CVE-2016-1247  | trusty=!1.4.6-1ubuntu3.6 xenial=!1.10.0-0ubuntu0.16.04.3 jessie=!1.6.2-5+deb8u3
CVE-2018-14665 | bionic=2:1.19.6-1ubuntu4.2 stretch=2:1.19.2-1+deb9u4
CVE-2024-48990 | xenial=2.6-1ubuntu0.1~esm1 bionic=3.1-1ubuntu0.1+esm1 focal=3.4-6ubuntu0.1+esm1 jammy=3.5-5ubuntu2.2 noble=3.6-7ubuntu4.3 bullseye=3.5-4+deb11u4 bookworm=3.6-4+deb12u2
CVE-2023-26604 | xenial=unfixed bionic=unfixed focal=unfixed buster=241-7~deb10u9
CVE-2016-8655  | k=3.13.0-105.152 k=4.4.0-53.74
CVE-2017-6074  | k=3.13.0-110.157 k=4.4.0-64.85 k=4.8.0-39.42
CVE-2021-3490  | k=5.8.0-53.60 k=5.11.0-17.18
'

NL='
'
TAB='	'
R=${LPE_ROOT:-}          # test hook: alternate root for every file and tool lookup
OPT_V=0; OPT_TSV=0; OPT_PROBE=1

# ---------------------------------------------------------------- helpers

have() { command -v "$1" >/dev/null 2>&1; }

trim() {
  REPLY=$1
  REPLY=${REPLY#"${REPLY%%[![:space:]]*}"}
  REPLY=${REPLY%"${REPLY##*[![:space:]]}"}
}

first_line() { REPLY=${1%%"$NL"*}; }

# tool NAME -> REPLY=path or "". Under LPE_ROOT only the fixture's own tools count.
tool() {
  local p
  REPLY=
  if [ -n "$R" ]; then
    for p in "$R/usr/bin/$1" "$R/usr/sbin/$1" "$R/usr/local/bin/$1"; do
      [ -x "$p" ] && { REPLY=$p; return 0; }
    done
    return 1
  fi
  p=$(command -v "$1" 2>/dev/null)
  case $p in /*) REPLY=$p; return 0 ;; esac
  return 1
}

resolve() {
  REPLY=$(readlink -f "$1" 2>/dev/null)
  [ -n "$REPLY" ] || REPLY=$1
}

# run_to SECS cmd...  run with stdin closed and a watchdog (no timeout(1) needed)
run_to() {
  local t=$1 pid rc
  shift
  "$@" </dev/null &
  pid=$!
  ( i=0
    while [ $i -lt $t ]; do
      sleep 1; i=$((i + 1))
      kill -0 $pid 2>/dev/null || exit 0
    done
    kill -9 $pid 2>/dev/null ) >/dev/null 2>&1 &
  wait $pid 2>/dev/null
  rc=$?
  return $rc
}

now_ms() {  # NOW = milliseconds; date %N, else /proc/uptime (10 ms), else seconds
  local t
  if [ -z "${CLOCK:-}" ]; then
    t=$(date +%s%N 2>/dev/null)
    case $t in
      [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*) CLOCK=ns ;;
      *) CLOCK=uptime; [ -r /proc/uptime ] || CLOCK=sec ;;   # busybox date drops %N
    esac
  fi
  case $CLOCK in
    ns) t=$(date +%s%N); NOW=$((t / 1000000)) ;;
    uptime) read -r t _ < /proc/uptime; t=${t/./}; NOW=$((10#$t * 10)) ;;
    *) t=$(date +%s); NOW=$((t * 1000)); MS_COARSE=1 ;;
  esac
}

is_suid_root() {
  local real
  resolve "$1"; real=$REPLY
  [ -u "$real" ] || return 1
  set -- $(ls -ln "$real" 2>/dev/null)
  [ "$3" = 0 ]
}

# ---------------------------------------------------------------- versions

# ver_norm "1.9.16p2" -> 1.9.16.2 ; "5.15.0-91-generic" -> 5.15.0 ; "4.05.00 (GNU)" -> 4.05.00
ver_norm() {
  local v=$1 head rest
  v=${v#"${v%%[0-9]*}"}
  head=${v%%[!0-9.]*}
  rest=${v#"$head"}
  head=${head%.}
  case $rest in
    p[0-9]*) rest=${rest#p}; rest=${rest%%[!0-9]*}; head="$head.$rest" ;;
  esac
  REPLY=$head
}

# pkg_upstream "1:1.9.15p5-3ubuntu5.24.04.1" -> 1.9.15.5 (epoch and revision dropped)
pkg_upstream() {
  local v=$1
  case $v in [0-9]*:*) v=${v#*:} ;; esac
  ver_norm "$v"
}

# ver_cmp A B -> VC = -1 | 0 | 1   (dotted numeric, missing fields are 0)
ver_cmp() {
  local a=$1 b=$2 x y
  VC=0
  while [ -n "$a" ] || [ -n "$b" ]; do
    x=${a%%.*}; y=${b%%.*}
    case $a in *.*) a=${a#*.} ;; *) a= ;; esac
    case $b in *.*) b=${b#*.} ;; *) b= ;; esac
    x=${x%%[!0-9]*}; y=${y%%[!0-9]*}
    x=$((10#${x:-0})); y=$((10#${y:-0}))
    if [ "$x" -lt "$y" ]; then VC=-1; return; fi
    if [ "$x" -gt "$y" ]; then VC=1; return; fi
  done
}

# ver_branch VER KERNEL? -> REPLY = x.y (x.y.z for 2.6 kernels)
ver_branch() {
  local v=$1 a b c
  a=${v%%.*}; v=${v#*.}; b=${v%%.*}
  REPLY="$a.$b"
  if [ "$2" = 1 ] && [ "$a.$b" = 2.6 ]; then
    case $v in *.*) v=${v#*.}; c=${v%%.*}; REPLY="2.6.$c" ;; esac
  fi
}

# ver_affected VER SPECS KERNEL? -> 0 if affected; AFF_LO / AFF_FIX describe why
ver_affected() {
  local v=$1 specs=$2 k=$3 s lo fixes hi vb f fn matched
  AFF_LO=; AFF_FIX=
  [ "$specs" = - ] && return 1
  for s in $specs; do
    lo=${s%%:*}; fixes=${s#*:}
    ver_norm "$lo"; ver_cmp "$v" "$REPLY"
    [ $VC -lt 0 ] && continue
    hi=${fixes##*,}
    ver_norm "$hi"; ver_cmp "$v" "$REPLY"
    [ $VC -ge 0 ] && continue
    ver_branch "$v" "$k"; vb=$REPLY
    matched=
    for f in ${fixes//,/ }; do
      ver_norm "$f"; fn=$REPLY
      ver_branch "$fn" "$k"
      [ "$REPLY" = "$vb" ] || continue
      matched=1
      ver_cmp "$v" "$fn"
      if [ $VC -lt 0 ]; then AFF_LO=$lo; AFF_FIX=$f; return 0; fi
    done
    [ -n "$matched" ] && continue
    AFF_LO=$lo; AFF_FIX="$hi (the $vb branch never got a fix)"
    return 0
  done
  return 1
}

# ---------------------------------------------------------------- tables

# row_parse LINE -> R_ID R_NAME R_COMP R_AFF R_PRE R_PROBE R_REF
row_parse() {
  local oifs=$IFS
  IFS='|'; set -f; set -- $1; set +f; IFS=$oifs
  trim "$1"; R_ID=$REPLY
  trim "$2"; R_NAME=$REPLY
  trim "$3"; R_COMP=$REPLY
  trim "$4"; R_AFF=$REPLY
  trim "$5"; R_PRE=$REPLY
  trim "$6"; R_PROBE=$REPLY
  trim "$7"; R_REF=$REPLY
}

# fixdb_row ID -> FX_ENTRIES
fixdb_row() {
  local rest=$FIXDB line id
  FX_ENTRIES=
  while [ -n "$rest" ]; do
    line=${rest%%"$NL"*}
    case $rest in *"$NL"*) rest=${rest#*"$NL"} ;; *) rest= ;; esac
    case $line in *'|'*) ;; *) continue ;; esac
    trim "${line%%|*}"; id=$REPLY
    if [ "$id" = "$1" ]; then
      trim "${line#*|}"; FX_ENTRIES=$REPLY
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------- OS / packages

inv_os() {
  local f k v low c
  OS_ID=; OS_LIKE=; OS_VER=; OS_CODE=; OS_PRETTY=; OS_VERSION=
  f=$R/etc/os-release
  [ -r "$f" ] || f=$R/usr/lib/os-release
  if [ -r "$f" ]; then
    while IFS='=' read -r k v; do
      v=${v#[\"\']}; v=${v%[\"\']}
      case $k in
        ID) OS_ID=$v ;;
        ID_LIKE) OS_LIKE=$v ;;
        VERSION_ID) OS_VER=$v ;;
        VERSION) OS_VERSION=$v ;;
        PRETTY_NAME) OS_PRETTY=$v ;;
        UBUNTU_CODENAME) OS_CODE=$v ;;
        VERSION_CODENAME) [ -n "$OS_CODE" ] || OS_CODE=$v ;;
      esac
    done < "$f"
  fi
  if [ -z "$OS_CODE" ] && [ -r "$R/etc/lsb-release" ]; then
    while IFS='=' read -r k v; do
      case $k in DISTRIB_CODENAME) OS_CODE=$v ;; esac
    done < "$R/etc/lsb-release"
  fi
  if [ -z "$OS_CODE" ]; then
    low=$(printf '%s' "$OS_VERSION $OS_PRETTY" | tr 'A-Z' 'a-z')
    for c in lenny squeeze wheezy jessie stretch buster bullseye bookworm trixie forky \
             precise trusty xenial bionic focal jammy noble; do
      case $low in *"$c"*) OS_CODE=$c; break ;; esac
    done
  fi
  if [ -z "$OS_CODE" ] && [ -r "$R/etc/debian_version" ]; then
    read -r v < "$R/etc/debian_version"
    case $v in
      5*) OS_CODE=lenny ;; 6*) OS_CODE=squeeze ;; 7*) OS_CODE=wheezy ;; 8*) OS_CODE=jessie ;; 9*) OS_CODE=stretch ;;
      10*) OS_CODE=buster ;; 11*) OS_CODE=bullseye ;; 12*) OS_CODE=bookworm ;;
      13*) OS_CODE=trixie ;;
    esac
  fi
  if [ -z "$OS_PRETTY" ]; then
    for f in "$R/etc/redhat-release" "$R/etc/issue"; do
      [ -r "$f" ] && { read -r OS_PRETTY < "$f"; break; }
    done
  fi
  [ -n "$OS_PRETTY" ] || OS_PRETTY="unknown OS"
}

# pm_query MGR PATH -> 0 if owned; Q_PKG Q_VER Q_PKGQ
pm_query() {
  local o rest
  Q_PKG=; Q_VER=; Q_PKGQ=
  case $1 in
    dpkg)
      o=$("$PM_dpkg" -S "$2" 2>/dev/null | grep -v '^diversion' | head -n 1)
      case $o in *": /"*) ;; *) return 1 ;; esac
      Q_PKG=${o%%: /*}; Q_PKG=${Q_PKG%%,*}
      Q_PKGQ=$Q_PKG
      Q_VER=$("$PM_dpkgquery" -W -f='${Version}' "$Q_PKG" 2>/dev/null)
      Q_PKG=${Q_PKG%%:*}
      ;;
    rpm)
      o=$("$PM_rpm" -qf --qf '%{NAME} %{VERSION}-%{RELEASE} %{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$2" 2>/dev/null) || return 1
      first_line "$o"; o=$REPLY
      case $o in ''|*' not owned '*|*'No such file'*) return 1 ;; esac
      set -- $o
      Q_PKG=$1; Q_VER=$2; Q_PKGQ=$3
      ;;
    apk)
      o=$("$PM_apk" info --who-owns "$2" 2>/dev/null) || return 1
      case $o in *' is owned by '*) ;; *) return 1 ;; esac
      rest=${o##* is owned by }
      first_line "$rest"; rest=$REPLY
      Q_VER=${rest##*-}; rest=${rest%-*}
      Q_VER="${rest##*-}-$Q_VER"; Q_PKG=${rest%-*}; Q_PKGQ=$Q_PKG
      ;;
    pacman)
      o=$("$PM_pacman" -Qo "$2" 2>/dev/null) || return 1
      case $o in *' is owned by '*) ;; *) return 1 ;; esac
      rest=${o##* is owned by }
      Q_PKG=${rest%% *}; Q_VER=${rest#* }; Q_PKGQ=$Q_PKG
      ;;
  esac
  [ -n "$Q_PKG" ]
}

inv_pm() {
  local m ls_path
  PM_ALL=; PM_AUTH=
  PM_dpkg=; PM_dpkgquery=; PM_rpm=; PM_apk=; PM_pacman=
  tool dpkg && PM_dpkg=$REPLY
  tool dpkg-query && PM_dpkgquery=$REPLY
  [ -n "$PM_dpkg" ] && [ -n "$PM_dpkgquery" ] && PM_ALL="$PM_ALL dpkg"
  tool rpm && { PM_rpm=$REPLY; PM_ALL="$PM_ALL rpm"; }
  tool apk && { PM_apk=$REPLY; PM_ALL="$PM_ALL apk"; }
  tool pacman && { PM_pacman=$REPLY; PM_ALL="$PM_ALL pacman"; }
  # a manager's "not owned" only means something if it owns the base system
  ls_path=$(command -v ls 2>/dev/null)
  resolve "${ls_path:-/bin/ls}"; ls_path=$REPLY
  for m in $PM_ALL; do
    if pm_query $m "$ls_path" || pm_query $m /bin/ls || pm_query $m /usr/bin/ls; then
      PM_AUTH="$PM_AUTH $m"
    fi
  done
}

# owner PATH -> O_STATE (pkg|src|unk) O_MGR O_PKG O_VER O_PKGQ O_WHY
owner() {
  local lp real c alt m cands oifs
  O_STATE=; O_MGR=; O_PKG=; O_VER=; O_PKGQ=; O_WHY=
  resolve "$1"; real=${REPLY#"$R"}
  lp=${1#"$R"}
  cands=$lp
  [ "$real" != "$lp" ] && cands="$cands$NL$real"
  oifs=$IFS; IFS=$NL; set -f; set -- $cands; set +f; IFS=$oifs
  for c in "$@"; do
    case $c in
      /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) alt=${c#/usr} ;;
      /bin/*|/sbin/*|/lib/*|/lib64/*) alt=/usr$c ;;
      *) alt= ;;
    esac
    [ -n "$alt" ] && cands="$cands$NL$alt"
  done
  oifs=$IFS; IFS=$NL; set -f; set -- $cands; set +f; IFS=$oifs
  for m in $PM_ALL; do
    for c in "$@"; do
      if pm_query $m "$c"; then
        O_STATE=pkg; O_MGR=$m; O_PKG=$Q_PKG; O_VER=$Q_VER; O_PKGQ=$Q_PKGQ
        O_WHY="$m package $Q_PKG $Q_VER"
        return
      fi
    done
  done
  if [ -n "$PM_AUTH" ]; then
    O_STATE=src
    O_WHY="not owned by any package (asked:$PM_AUTH) => source-built, upstream range applies directly"
  elif [ -n "$PM_ALL" ]; then
    O_STATE=unk
    O_WHY="package database unusable (${PM_ALL# } does not even own ls)"
  else
    O_STATE=src
    O_WHY="no package manager on this system => unpackaged, upstream range applies directly"
  fi
}

# cve_ids: stdin text -> sorted unique CVE ids on one line. grep -o where it
# works (finds ids glued to other text, e.g. "local-CVE-2023-4911.patch").
cve_ids() {
  if [ -z "${GREP_O:-}" ]; then
    GREP_O=0
    [ "$(printf 'a-CVE-2000-00011.b\n' | grep -oE 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]+' 2>/dev/null)" = CVE-2000-00011 ] && GREP_O=1
  fi
  if [ $GREP_O = 1 ]; then
    grep -oE 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]+'
  else
    tr -c 'CVE0-9-' '\n' | tr -s '-' | grep -E 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]+-?$' |
      while read -r l; do l=${l#"${l%%CVE-*}"}; echo "${l%-}"; done
  fi | sort -u | tr '\n' ' '
}

# changelog_ids IDX -> CL_STATE (ok|trunc|none)  CL_IDS (" CVE-a CVE-b ")  CL_SRC
changelog_ids() {
  local i=$1 mgr pkg q f d tailtxt n
  eval "CL_STATE=\${CLS_$i:-}"
  if [ -n "$CL_STATE" ]; then
    eval "CL_IDS=\$CLI_$i; CL_SRC=\$CLF_$i"
    return
  fi
  CL_STATE=none; CL_IDS=; CL_SRC=
  mgr=${I_MGR[$i]}; pkg=${I_PKG[$i]}; q=${I_PKGQ[$i]}
  case $mgr in
    dpkg)
      d="$R/usr/share/doc/$pkg"
      for f in "$d/changelog.Debian.gz" "$d/changelog.gz" "$d/changelog.Debian" "$d/changelog"; do
        [ -r "$f" ] || continue
        case $f in
          *.gz)
            have gzip || continue
            CL_IDS=" $(gzip -dc "$f" 2>/dev/null | cve_ids)"
            tailtxt=$(gzip -dc "$f" 2>/dev/null | tail -n 4)
            ;;
          *)
            CL_IDS=" $(cve_ids < "$f")"
            tailtxt=$(tail -n 4 "$f" 2>/dev/null)
            ;;
        esac
        CL_STATE=ok; CL_SRC=${f#"$R"}
        case $tailtxt in *"older changelog entries"*) CL_STATE=trunc ;; esac
        break
      done
      ;;
    rpm)
      n=$("$PM_rpm" -q --changelog "$q" 2>/dev/null | head -n 3 | grep -c .)
      if [ "${n:-0}" -gt 0 ]; then
        CL_IDS=" $("$PM_rpm" -q --changelog "$q" 2>/dev/null | cve_ids)"
        CL_STATE=ok; CL_SRC="rpm -q --changelog $q"
      fi
      ;;
  esac
  eval "CLS_$i=\$CL_STATE; CLI_$i=\$CL_IDS; CLF_$i=\$CL_SRC"
}

# ---------------------------------------------------------------- inventory

N_INST=0

# add_inst COMP PATH RAWVERSION
add_inst() {
  local i=$N_INST
  I_COMP[$i]=$1; I_PATH[$i]=$2; I_RAW[$i]=$3
  ver_norm "$3"; I_VER[$i]=$REPLY
  owner "$2"
  # A package owns the path, but the binary reports another upstream version:
  # the file was replaced (make install over the package). Package version,
  # FIXDB and changelog say nothing about it. Not for snapd (snap re-execs into the core snap) or
  # kernels (package versions are not the upstream version).
  if [ "$O_STATE" = pkg ] && [ "$1" != snapd ] && [ "$1" != kernel ] && [ -n "${I_VER[$i]}" ]; then
    case $O_MGR in
      dpkg|rpm)
        pkg_upstream "$O_VER"
        if [ -n "$REPLY" ]; then
          ver_cmp "${I_VER[$i]}" "$REPLY"
          if [ $VC != 0 ]; then
            O_STATE=src
            O_WHY="path belongs to $O_MGR package $O_PKG $O_VER but the binary reports $3 => file replaced by another build, upstream range applies directly"
          fi
        fi ;;
    esac
  fi
  I_STATE[$i]=$O_STATE; I_MGR[$i]=$O_MGR; I_PKG[$i]=$O_PKG
  I_PKGVER[$i]=$O_VER; I_PKGQ[$i]=$O_PKGQ; I_WHY[$i]=$O_WHY
  N_INST=$((i + 1))
}

cand() {
  [ -f "$1" ] && [ -x "$1" ] || return
  resolve "$1"
  case $SEEN in *"$NL$REPLY$NL"*) return ;; esac
  SEEN="$SEEN$REPLY$NL"
  FOUND="$FOUND$1$NL"
}

# find_bins NAME... -> FOUND: distinct executables (PATH first, then usual dirs)
find_bins() {
  local n d p
  FOUND=; SEEN=$NL
  for n in "$@"; do
    if [ -z "$R" ]; then
      p=$(command -v "$n" 2>/dev/null)
      case $p in /*) cand "$p" ;; esac
    fi
    for d in /usr/local/bin /usr/bin /bin /usr/local/sbin /usr/sbin /sbin; do
      cand "$R$d/$n"
    done
    for p in "$R"/opt/*/bin/"$n" "$R"/opt/*/sbin/"$n" "$R"/usr/local/*/bin/"$n"; do
      cand "$p"
    done
  done
}

inv_sudo() {
  local p v oifs
  find_bins sudo
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    v=$(run_to 5 "$p" -V 2>/dev/null | head -n 1)
    case $v in "Sudo version "*) add_inst sudo "$p" "${v#Sudo version }" ;; esac
  done
}

inv_pkexec() {
  local p v oifs
  find_bins pkexec
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    v=$(run_to 5 "$p" --version 2>/dev/null | head -n 1)
    case $v in *version*[0-9]*) add_inst pkexec "$p" "${v##* }" ;; esac
  done
}

inv_glibc() {
  local v p f
  v=
  tool getconf && v=$("$REPLY" GNU_LIBC_VERSION 2>/dev/null)
  if [ -z "$v" ] && tool ldd; then
    v=$("$REPLY" --version 2>/dev/null | head -n 1)
    case $v in *musl*) v= ;; esac
  fi
  v=${v##* }
  case $v in [0-9]*.[0-9]*) ;; *) return ;; esac
  f=
  for p in "$R"/lib/*-linux-gnu*/libc.so.6 "$R"/lib64/libc.so.6 "$R"/usr/lib64/libc.so.6 \
           "$R"/lib/libc.so.6 "$R"/usr/lib/*-linux-gnu*/libc.so.6 "$R"/usr/lib/libc.so.6; do
    [ -e "$p" ] && { f=$p; break; }
  done
  [ -n "$f" ] || return
  add_inst glibc "$f" "$v"
}

inv_screen() {
  local p v oifs
  find_bins screen
  for p in "$R"/usr/bin/screen-* "$R"/usr/local/bin/screen-* "$R"/bin/screen-* "$R"/opt/screen*/bin/screen; do
    cand "$p"
  done
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    v=$(run_to 5 "$p" --version 2>/dev/null | head -n 1)
    case $v in
      "Screen version "*) v=${v#Screen version }; add_inst screen "$p" "${v%% *}" ;;
    esac
  done
}

inv_snapd() {
  local p v line oifs
  tool snap || return
  p=$REPLY
  v=$(run_to 8 "$p" version 2>/dev/null)
  oifs=$IFS; IFS=$NL; set -f; set -- $v; set +f; IFS=$oifs
  v=
  for line in "$@"; do
    case $line in snapd*[0-9]*) v=${line##* } ;; esac
  done
  case $v in [0-9]*) add_inst snapd "$p" "$v" ;; esac
}

inv_exim() {
  local p v oifs
  find_bins exim4 exim
  for p in "$R"/usr/exim/bin/exim; do cand "$p"; done
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    v=$(run_to 5 "$p" -bV 2>/dev/null | head -n 1)
    case $v in
      "Exim version "*) v=${v#Exim version }; add_inst exim "$p" "${v%% *}" ;;
    esac
  done
}

inv_chkrootkit() {
  local p v oifs
  find_bins chkrootkit
  for p in "$R"/usr/local/chkrootkit*/chkrootkit "$R"/opt/chkrootkit*/chkrootkit; do cand "$p"; done
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    # it is a shell script: read CHKROOTKIT_VERSION=, run -V only as a fallback
    v=$(grep -E '^[[:space:]]*CHKROOTKIT_VERSION=' "$p" 2>/dev/null | head -n 1); v=${v#*=}
    case $v in *[0-9]*) ;; *) v=$(run_to 5 "$p" -V 2>&1 | head -n 1); v=${v##*version } ;; esac
    ver_norm "$v"
    [ -n "$REPLY" ] && add_inst chkrootkit "$p" "$REPLY"
  done
}

inv_nginx() {
  local p v oifs
  find_bins nginx
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    v=$(run_to 5 "$p" -v 2>&1 | head -n 1)
    case $v in *"nginx/"[0-9]*) v=${v#*nginx/}; add_inst nginx "$p" "${v%% *}" ;; esac
  done
}

inv_xorg() {
  local p v oifs
  find_bins Xorg
  for p in "$R"/usr/lib/xorg/Xorg "$R"/usr/libexec/Xorg "$R"/usr/lib/Xorg; do cand "$p"; done
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    # Debian/Ubuntu /usr/bin/Xorg is a sh wrapper around Xorg.wrap; the real binary is listed too
    case $(head -c 2 "$p" 2>/dev/null) in '#!') grep -qs Xorg.wrap "$p" && continue ;; esac
    v=$(run_to 5 "$p" -version 2>&1 | grep 'X.Org X Server' | head -n 1)
    case $v in *"X Server "[0-9]*) v=${v##*X Server }; add_inst xorg "$p" "${v%% *}" ;; esac
  done
}

inv_enlightenment() {
  local p v f base oifs
  FOUND=; SEEN=$NL
  for p in "$R"/usr/lib/*/enlightenment/utils/enlightenment_sys "$R"/usr/lib/enlightenment/utils/enlightenment_sys \
           "$R"/usr/lib64/enlightenment/utils/enlightenment_sys "$R"/usr/local/lib/enlightenment/utils/enlightenment_sys \
           "$R"/usr/local/lib/*/enlightenment/utils/enlightenment_sys "$R"/opt/*/lib/enlightenment/utils/enlightenment_sys; do
    cand "$p"
  done
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    # version: owning package, else the installed enlightenment.pc, else enlightenment -version
    v=
    owner "$p"
    if [ "$O_STATE" = pkg ]; then pkg_upstream "$O_VER"; v=$REPLY; fi
    if [ -z "$v" ]; then
      f=${p%/enlightenment/utils/enlightenment_sys}/pkgconfig/enlightenment.pc
      [ -r "$f" ] && { v=$(grep '^Version:' "$f" 2>/dev/null | head -n 1); v=${v#Version:}; }
    fi
    if [ -z "$v" ]; then
      base=${p%%/lib/*}
      if [ -x "$base/bin/enlightenment" ]; then
        v=$(run_to 5 "$base/bin/enlightenment" -version 2>/dev/null | grep '^Version' | head -n 1); v=${v#*:}
      fi
    fi
    ver_norm "$v"
    [ -n "$REPLY" ] && add_inst enlightenment "$p" "$REPLY"
  done
}

inv_needrestart() {
  local p v f oifs
  find_bins needrestart
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    # Perl: the version lives in NeedRestart.pm (our $VERSION = '3.6';). Nothing is run.
    v=
    for f in "$R"/usr/share/perl5/NeedRestart.pm "$R"/usr/share/perl5/vendor_perl/NeedRestart.pm \
             "$R"/usr/local/share/perl/*/NeedRestart.pm "$R"/usr/local/share/perl5/NeedRestart.pm \
             "$R"/usr/share/perl/*/NeedRestart.pm "$R"/usr/lib/perl5/vendor_perl/*/NeedRestart.pm; do
      [ -r "$f" ] || continue
      v=$(grep -E 'VERSION[[:space:]]*=' "$f" 2>/dev/null | head -n 1); v=${v#*=}
      break
    done
    ver_norm "$v"
    [ -n "$REPLY" ] && add_inst needrestart "$p" "$REPLY"
  done
}

inv_systemd() {
  local p v w
  tool systemctl || return
  p=$REPLY
  v=$(run_to 5 "$p" --version 2>/dev/null | head -n 1)
  case $v in "systemd "[0-9]*) ;; *) return ;; esac
  # "systemd 245 (245.4-4ubuntu3.15)": the parenthesised build version matches the package
  w=${v#systemd }; w=${w%% *}
  case $v in *"("[0-9]*")"*) w=${v#*\(}; w=${w%%\)*} ;; esac
  add_inst systemd "$p" "$w"
}

inv_kernel() {
  local u sig a rest c p i
  K_REL=; K_BASE=; K_ABI=; K_FLAVOR=; K_KIND=other; K_NOTE=
  tool uname || return
  u=$REPLY
  K_REL=$("$u" -r 2>/dev/null)
  K_VTXT=$("$u" -v 2>/dev/null)
  [ -n "$K_REL" ] || return
  ver_norm "$K_REL"; K_BASE=$REPLY
  if [ -r "$R/proc/version_signature" ]; then
    read -r sig < "$R/proc/version_signature"
    case $sig in
      "Ubuntu "*)
        set -- $sig
        a=${2#*-}
        K_ABI="${2%%-*}-${a%%-*}"; K_ABI=${K_ABI%%\~*}
        K_FLAVOR=${a#*-}
        K_KIND=ubuntu
        if [ -n "$3" ]; then ver_norm "$3"; K_BASE=$REPLY; fi
        K_NOTE="Ubuntu ABI $K_ABI, upstream base $K_BASE"
        ;;
    esac
  fi
  case $K_VTXT in
    *"Debian "[0-9]*)
      rest=${K_VTXT#*Debian }
      ver_norm "${rest%% *}"; K_BASE=$REPLY
      K_KIND=debian
      K_NOTE="Debian package ${rest%% *}"
      ;;
  esac
  p=
  for c in "$R/boot/vmlinuz-$K_REL" "$R/lib/modules/$K_REL/kernel" "$R/usr/lib/modules/$K_REL/kernel"; do
    [ -e "$c" ] && { p=$c; break; }
  done
  i=$N_INST
  if [ -n "$p" ]; then
    add_inst kernel "$p" "$K_BASE"
  else
    I_COMP[$i]=kernel; I_PATH[$i]="(no kernel files visible)"; I_VER[$i]=$K_BASE
    I_MGR[$i]=; I_PKG[$i]=; I_PKGVER[$i]=; I_PKGQ[$i]=
    case $K_KIND:$K_REL in
      ubuntu:*|debian:*|*.el[0-9]*|*.fc[0-9]*|*.amzn*|*-generic|*-amd64|*-arm64|*-686*|*-arch[0-9]*|*-lts|*-default|*-pve|*-kali*|*-MANJARO|*microsoft*|*-cloud*|*-aws|*-azure|*-gcp|*-kvm|*-raspi*)
        I_STATE[$i]=unk
        I_WHY[$i]="distro kernel whose package files are not visible here (container?)" ;;
      *)
        I_STATE[$i]=src
        I_WHY[$i]="no kernel package files and no distro suffix in the release string => custom build, upstream range applies directly" ;;
    esac
    N_INST=$((i + 1))
  fi
  I_RAW[$i]=$K_REL
}

# ensure COMP: run its inventory once
ensure() {
  eval "[ -n \"\${INV_$1:-}\" ]" && return
  eval "INV_$1=1"
  inv_$1
}

# ---------------------------------------------------------------- preconditions
# pre_* : 0 = met, 1 = not met, 2 = unknown.  PRE_MSG explains.

pre_suid() {
  if is_suid_root "$C_PATH"; then PRE_MSG="SUID root"; return 0; fi
  PRE_MSG="$C_PATH is not SUID root"; return 1
}

# sudo_rules -> SR_SRC (none | description) SR_TXT   (cached per sudo binary)
sudo_rules() {
  local out
  eval "SR_SRC=\${SRS_$C_IDX:-}"
  if [ -n "$SR_SRC" ]; then eval "SR_TXT=\$SRT_$C_IDX"; return; fi
  SR_SRC=none; SR_TXT=
  if [ "$OPT_PROBE" = 1 ]; then
    out=$(run_to 8 "$C_PATH" -n -l 2>/dev/null)
    case $out in
      *"may run the following"*) SR_SRC="sudo -n -l"; SR_TXT=$out ;;
      *"not allowed to run sudo"*|*"may not run sudo"*) SR_SRC="sudo -n -l: no rules" ;;
    esac
  fi
  if [ "$SR_SRC" = none ]; then
    sudoers_raw
    if [ -n "$SUDOERS_TXT" ]; then SR_SRC="readable sudoers"; SR_TXT=$SUDOERS_TXT; fi
  fi
  eval "SRS_$C_IDX=\$SR_SRC; SRT_$C_IDX=\$SR_TXT"
}

# any_sudo_rules -> SA_SRC SA_TXT: this user's sudo rules for checks whose
# component is not sudo itself (cached; sudo -n -l only with probes on)
any_sudo_rules() {
  local out
  [ -n "${SA_SRC:-}" ] && return
  SA_SRC=none; SA_TXT=
  if [ "$OPT_PROBE" = 1 ] && tool sudo; then
    out=$(run_to 8 "$REPLY" -n -l 2>/dev/null)
    case $out in
      *"may run the following"*) SA_SRC="sudo -n -l"; SA_TXT=$out ;;
      *"not allowed to run sudo"*|*"may not run sudo"*) SA_SRC="sudo -n -l: no rules" ;;
    esac
  fi
  if [ "$SA_SRC" = none ]; then
    sudoers_raw
    if [ -n "$SUDOERS_TXT" ]; then SA_SRC="readable sudoers"; SA_TXT=$SUDOERS_TXT; fi
  fi
}

# sudoers_raw -> SUDOERS_TXT: lines of readable sudoers files that concern this user
sudoers_raw() {
  local f pre txt g pat
  SUDOERS_TXT=
  pre=${C_PATH%/*}; pre=${pre%/*}
  txt=
  for f in "$R/etc/sudoers" "$R"/etc/sudoers.d/* "$pre/etc/sudoers" "$pre"/etc/sudoers.d/*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    txt="$txt$(cat "$f" 2>/dev/null)$NL"
  done
  [ -n "$txt" ] || return
  pat="Defaults|ALL|$ME|#$MY_UID"
  for g in $MY_GROUPS; do pat="$pat|%$g"; done
  SUDOERS_TXT=$(printf '%s\n' "$txt" | grep -E "^[[:space:]]*($pat)([[:space:]:@!>]|\$)")
}

pre_sudo_runas_notroot() {
  local m
  sudo_rules
  case $SR_SRC in
    none) PRE_MSG="needs a (ALL, !root) runas rule; sudo rules not listable without a password"; return 2 ;;
  esac
  m=$(printf '%s\n' "$SR_TXT" | grep -E '\([^)]*ALL[^)]*![[:space:]]*(root|#0)[^)]*\)' | head -n 1)
  if [ -n "$m" ]; then trim "$m"; PRE_MSG="runas rule: $REPLY [$SR_SRC]"; return 0; fi
  PRE_MSG="no (ALL, !root) runas rule [$SR_SRC]"; return 1
}

pre_sudo_pwfeedback() {
  local m
  sudo_rules
  case $SR_SRC in
    none|*"no rules") PRE_MSG="needs Defaults pwfeedback; sudo Defaults not readable without a password"; return 2 ;;
  esac
  m=$(printf '%s\n' "$SR_TXT" | grep -E '(^|[[:space:],])pwfeedback([[:space:],]|$)' | head -n 1)
  if [ -n "$m" ]; then PRE_MSG="pwfeedback enabled [$SR_SRC]"; return 0; fi
  PRE_MSG="pwfeedback not enabled [$SR_SRC]"; return 1
}

pre_sudoedit_rule() {
  local m
  sudo_rules
  case $SR_SRC in
    none) PRE_MSG="needs a sudoedit rule; sudo rules not listable without a password"; return 2 ;;
  esac
  m=$(printf '%s\n' "$SR_TXT" | grep -E '(^|[[:space:]/:])sudoedit([[:space:]]|$)' | head -n 1)
  if [ -n "$m" ]; then trim "$m"; PRE_MSG="sudoedit rule: $REPLY [$SR_SRC]"; return 0; fi
  PRE_MSG="no sudoedit rule [$SR_SRC]"; return 1
}

pre_sudo_host_rule() {
  local line rest hosts h oifs hn hs
  sudoers_raw
  if [ -z "$SUDOERS_TXT" ]; then
    PRE_MSG="needs a rule limited to another host; sudoers not readable"; return 2
  fi
  hn=; tool hostname && hn=$("$REPLY" 2>/dev/null)
  hs=${hn%%.*}
  oifs=$IFS; IFS=$NL; set -f; set -- $SUDOERS_TXT; set +f; IFS=$oifs
  for line in "$@"; do
    trim "$line"; line=$REPLY
    case $line in Defaults*|*=*) ;; *) continue ;; esac
    case $line in Defaults*) continue ;; esac
    rest=${line#*[[:space:]]}
    hosts=${rest%%=*}
    for h in ${hosts//,/ }; do
      case $h in ALL|"$hn"|"$hs"|localhost|'') ;; *) PRE_MSG="rule limited to host \"$h\": $line"; return 0 ;; esac
    done
  done
  PRE_MSG="no rule limited to another host in readable sudoers"; return 1
}

pre_kernel_lt_5_18() {
  ensure kernel
  if [ -z "$K_BASE" ]; then PRE_MSG="kernel version unknown (kernels >= 5.18 block the empty-argv trick)"; return 2; fi
  ver_cmp "$K_BASE" 5.18
  if [ $VC -lt 0 ]; then PRE_MSG="kernel $K_BASE < 5.18 (allows an empty argv)"; return 0; fi
  PRE_MSG="kernel $K_BASE >= 5.18 never passes an empty argv to pkexec"; return 1
}

pre_polkit_dbus() {
  local p
  if ! tool dbus-send && ! tool gdbus; then PRE_MSG="no dbus-send/gdbus to talk to polkit"; return 1; fi
  for p in "$R/usr/lib/accountsservice/accounts-daemon" "$R/usr/libexec/accounts-daemon" \
           "$R/usr/libexec/accountsservice/accounts-daemon"; do
    [ -e "$p" ] && { PRE_MSG="dbus-send and accountsservice present"; return 0; }
  done
  PRE_MSG="accountsservice not found (the usual exploit path goes through it)"; return 2
}

pre_userns() {
  local f v out u rc
  if [ -n "${USERNS_RC:-}" ]; then PRE_MSG=$USERNS_MSG; return $USERNS_RC; fi
  USERNS_RC=0
  f=$R/proc/sys/kernel/unprivileged_userns_clone
  if [ -r "$f" ]; then
    read -r v < "$f"
    [ "$v" = 0 ] && { USERNS_RC=1; USERNS_MSG="unprivileged user namespaces off (kernel.unprivileged_userns_clone=0)"; }
  fi
  f=$R/proc/sys/user/max_user_namespaces
  if [ -r "$f" ]; then
    read -r v < "$f"
    [ "$v" = 0 ] && { USERNS_RC=1; USERNS_MSG="user namespaces off (user.max_user_namespaces=0)"; }
  elif [ ! -e "$R/proc/self/ns/user" ]; then
    USERNS_RC=1; USERNS_MSG="kernel has no user namespace support"
  fi
  f=$R/proc/sys/kernel/apparmor_restrict_unprivileged_userns
  if [ -r "$f" ]; then
    read -r v < "$f"
    [ "$v" = 1 ] && { USERNS_RC=1; USERNS_MSG="Ubuntu AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1)"; }
  fi
  if [ $USERNS_RC = 0 ]; then
    USERNS_MSG="unprivileged user namespaces enabled (sysctls)"
    if [ "$OPT_PROBE" = 1 ] && tool unshare; then
      u=$REPLY
      out=$(run_to 5 "$u" -Ur true 2>&1); rc=$?
      if [ $rc = 0 ]; then
        USERNS_MSG="unprivileged user namespaces work (unshare -Ur true)"
      else
        case $out in
          *"nvalid option"*|*"nrecognized option"*|*sage*) ;;
          *) first_line "$out"; USERNS_RC=1; USERNS_MSG="unprivileged user namespaces blocked (unshare -Ur true: $REPLY)" ;;
        esac
      fi
    fi
  fi
  PRE_MSG=$USERNS_MSG; return $USERNS_RC
}

# kmod_avail MODULE CONFIG_SYMBOL -> 0 available, 1 not, 2 unknown
kmod_avail() {
  local d f
  ensure kernel
  grep -q "^$1 " "$R/proc/modules" 2>/dev/null && return 0
  for d in "$R/lib/modules/$K_REL" "$R/usr/lib/modules/$K_REL"; do
    [ -d "$d" ] || continue
    grep -q "/$1\.ko" "$d/modules.builtin" 2>/dev/null && return 0
    grep -q "/$1\.ko" "$d/modules.dep" 2>/dev/null && return 0
    [ -r "$d/modules.dep" ] && return 1
  done
  f="$R/boot/config-$K_REL"
  if [ -r "$f" ]; then
    grep -q "^CONFIG_$2=[ym]" "$f" && return 0
    return 1
  fi
  return 2
}

pre_kmod() {  # pre_kmod MODULE CONFIG LABEL
  kmod_avail "$1" "$2"
  case $? in
    0) PRE_MSG="$3 available"; return 0 ;;
    1) PRE_MSG="$3 not built for this kernel"; return 1 ;;
  esac
  PRE_MSG="cannot tell whether $3 is available (no /proc/modules, modules.dep or /boot/config)"; return 2
}

pre_nft() { pre_kmod nf_tables NF_TABLES nf_tables; }
pre_cls_route() { pre_kmod cls_route NET_CLS_ROUTE4 cls_route; }

pre_rds() {
  if ! grep -q '^rds ' "$R/proc/modules" 2>/dev/null &&
     grep -rqsE '^[[:space:]]*(blacklist[[:space:]]+rds|alias[[:space:]]+net-pf-21[[:space:]]+off|install[[:space:]]+rds[[:space:]]+/bin/(true|false))' "$R/etc/modprobe.d" 2>/dev/null; then
    PRE_MSG="rds module is blacklisted in /etc/modprobe.d"; return 1
  fi
  pre_kmod rds RDS "rds module"
}

pre_overlay() {
  if grep -qw overlay "$R/proc/filesystems" 2>/dev/null; then PRE_MSG="overlay filesystem registered"; return 0; fi
  pre_kmod overlay OVERLAY_FS overlayfs
}

pre_overlayfs() {
  if grep -qw overlayfs "$R/proc/filesystems" 2>/dev/null; then PRE_MSG="overlayfs filesystem registered"; return 0; fi
  pre_kmod overlayfs OVERLAYFS_FS "overlayfs (pre-3.18 Ubuntu module)"
}

pre_fuse() {
  if [ -e "$R/dev/fuse" ] || grep -qw fuse "$R/proc/filesystems" 2>/dev/null; then PRE_MSG="FUSE available"; return 0; fi
  pre_kmod fuse FUSE_FS FUSE
}

pre_ubpf() {
  local f=$R/proc/sys/kernel/unprivileged_bpf_disabled v
  if [ -r "$f" ]; then
    read -r v < "$f"
    if [ "$v" = 0 ]; then PRE_MSG="unprivileged bpf() allowed (kernel.unprivileged_bpf_disabled=0)"; return 0; fi
    PRE_MSG="unprivileged bpf() disabled (kernel.unprivileged_bpf_disabled=$v)"; return 1
  fi
  PRE_MSG="kernel.unprivileged_bpf_disabled not readable"; return 2
}

pre_ubuntu() {
  ensure kernel
  if [ "$K_KIND" = ubuntu ]; then PRE_MSG="Ubuntu kernel"; return 0; fi
  PRE_MSG="not an Ubuntu kernel"; return 1
}

pre_pkexec_suid() {
  local p oifs
  find_bins pkexec
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    is_suid_root "$p" && { PRE_MSG="SUID pkexec at ${p#"$R"} (also needs an active polkit session)"; return 0; }
  done
  PRE_MSG="no SUID pkexec (the exploit needs it as a helper)"; return 1
}

pre_snapd_socket() {
  if [ -e "$R/run/snapd.socket" ]; then PRE_MSG="snapd socket present"; return 0; fi
  PRE_MSG="no /run/snapd.socket"; return 1
}

pre_exim_perl() {
  local out
  out=$(run_to 5 "$C_PATH" -bP perl_startup 2>&1)
  case $out in
    *"perl_startup = "?*) first_line "$out"; PRE_MSG="exim $REPLY"; return 0 ;;
    *"perl_startup ="*|*nknown*) PRE_MSG="exim perl_startup not set / Perl not compiled in"; return 1 ;;
  esac
  PRE_MSG="could not read exim perl_startup"; return 2
}

pre_chkrootkit_root() {
  local f off=
  if grep -qsE '^[^ ]+ /tmp [^ ]+ ([^ ]*,)?noexec(,| )' "$R/proc/mounts"; then
    PRE_MSG="/tmp is mounted noexec (the bug runs /tmp/update)"; return 1
  fi
  for f in "$R/etc/crontab" "$R"/etc/cron.d/* "$R"/etc/cron.hourly/* "$R"/etc/cron.daily/* \
           "$R"/etc/cron.weekly/* "$R"/etc/cron.monthly/* "$R/etc/anacrontab" \
           "$R/var/spool/cron/crontabs/root" "$R/var/spool/cron/root" \
           "$R"/etc/systemd/system/*.service "$R"/lib/systemd/system/chkrootkit*.service; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    grep -qs chkrootkit "$f" || continue
    case ${f#"$R"} in
      /etc/cron.daily/chkrootkit)   # Debian's job is a no-op unless RUN_DAILY="true"
        if ! grep -qsE '^[[:space:]]*RUN_DAILY=.?true' "$R/etc/chkrootkit.conf" "$R/etc/chkrootkit/chkrootkit.conf"; then
          off=1; continue
        fi ;;
    esac
    PRE_MSG="root runs it: ${f#"$R"}"; return 0
  done
  if [ -n "$off" ]; then
    PRE_MSG="/etc/cron.daily/chkrootkit present but RUN_DAILY is not \"true\"; root's own crontab is not readable"; return 2
  fi
  PRE_MSG="needs root to run it (cron); no readable cron entry found, root's crontab is not readable"; return 2
}

pre_nginx_logdir() {
  local d=$R/var/log/nginx uid name
  if [ ! -d "$d" ]; then PRE_MSG="no /var/log/nginx"; return 1; fi
  set -f; set -- $(ls -lnd "$d" 2>/dev/null); set +f
  uid=$3
  case $uid in
    '') PRE_MSG="cannot stat /var/log/nginx"; return 2 ;;
    0) PRE_MSG="/var/log/nginx is owned by root (not the vulnerable Debian layout)"; return 1 ;;
  esac
  if [ "$uid" = "$MY_UID" ]; then
    PRE_MSG="you own /var/log/nginx; root (nginx restart / logrotate) follows a symlinked error.log"; return 0
  fi
  name=$(grep -E "^[^:]*:[^:]*:$uid:" "$R/etc/passwd" 2>/dev/null | head -n 1); name=${name%%:*}
  PRE_MSG="exploitable from ${name:-uid $uid}, the owner of /var/log/nginx (get a shell as that user first)"; return 2
}

pre_xorg_suid() {
  local w
  if is_suid_root "$C_PATH"; then PRE_MSG="Xorg is SUID root"; return 0; fi
  for w in "$R"/usr/lib/xorg/Xorg.wrap "$R"/usr/libexec/Xorg.wrap; do
    is_suid_root "$w" || continue
    if grep -qsE '^[[:space:]]*allowed_users[[:space:]]*=[[:space:]]*anybody' "$R/etc/X11/Xwrapper.config"; then
      PRE_MSG="SUID ${w#"$R"} with allowed_users=anybody"; return 0
    fi
    PRE_MSG="SUID ${w#"$R"} starts Xorg for console users only (allowed_users=console)"; return 1
  done
  PRE_MSG="Xorg is not SUID root and there is no SUID Xorg.wrap"; return 1
}

pre_needrestart_root() {
  local f m
  if grep -qsE '^[[:space:]]*.nrconf.interpscan.[[:space:]]*=[[:space:]]*0' \
       "$R/etc/needrestart/needrestart.conf" "$R"/etc/needrestart/conf.d/*.conf; then
    PRE_MSG="interpreter scanning disabled (\$nrconf{interpscan} = 0)"; return 1
  fi
  any_sudo_rules
  m=$(printf '%s\n' "$SA_TXT" | grep needrestart | head -n 1)
  if [ -n "$m" ]; then trim "$m"; PRE_MSG="sudo rule: $REPLY [$SA_SRC]"; return 0; fi
  for f in "$R"/etc/apt/apt.conf.d/*; do
    [ -f "$f" ] || continue
    grep -qs needrestart "$f" && { PRE_MSG="root runs it after every apt/dpkg run, unattended-upgrades included (${f#"$R"})"; return 0; }
  done
  PRE_MSG="no apt hook or sudo rule seen that makes root run it"; return 2
}

pre_sudo_systemctl() {
  local m
  any_sudo_rules
  case $SA_SRC in
    none) PRE_MSG="needs a sudo rule for systemctl (status opens less); sudo rules not listable without a password"; return 2 ;;
  esac
  m=$(printf '%s\n' "$SA_TXT" | grep -E '(^|[[:space:]/:,])systemctl([[:space:],]|$)' | head -n 1)
  if [ -n "$m" ]; then trim "$m"; PRE_MSG="sudo rule: $REPLY [$SA_SRC]"; return 0; fi
  PRE_MSG="no sudo rule for systemctl [$SA_SRC]"; return 1
}

pre_hardlinks() {
  local f=$R/proc/sys/fs/protected_hardlinks v
  if [ -r "$f" ]; then
    read -r v < "$f"
    if [ "$v" = 1 ]; then PRE_MSG="fs.protected_hardlinks=1 blocks hardlinking SUID binaries"; return 1; fi
    PRE_MSG="fs.protected_hardlinks=$v; needs a writable dir on the same filesystem as a SUID-root binary"; return 0
  fi
  PRE_MSG="no fs.protected_hardlinks (kernel predates it); needs a writable dir on the same filesystem as a SUID-root binary"; return 0
}

pre_mmap_zero() {
  local f=$R/proc/sys/vm/mmap_min_addr v
  if [ -r "$f" ]; then
    read -r v < "$f"
    if [ "$v" = 0 ]; then PRE_MSG="vm.mmap_min_addr=0 (page zero mappable)"; return 0; fi
    PRE_MSG="vm.mmap_min_addr=$v; public exploits get past it only on some setups (SELinux unconfined_t, pulseaudio personality trick)"; return 2
  fi
  PRE_MSG="no vm.mmap_min_addr (kernel predates it: page zero mappable)"; return 0
}

pre_dccp() {
  if ! grep -q '^dccp ' "$R/proc/modules" 2>/dev/null &&
     grep -rqsE '^[[:space:]]*(blacklist[[:space:]]+dccp|install[[:space:]]+dccp[[:space:]]+/bin/(true|false))' "$R/etc/modprobe.d" 2>/dev/null; then
    PRE_MSG="dccp module is blacklisted in /etc/modprobe.d"; return 1
  fi
  pre_kmod dccp IP_DCCP "dccp module"
}

# ---------------------------------------------------------------- safe probes
# probe_* : 0 = vulnerable behaviour seen, 1 = patched behaviour seen, 2 = inconclusive

sudoedit_exec() { exec -a sudoedit "$1" -n -s /; }

probe_samedit() {
  local sib=${C_PATH%/*}/sudoedit out line
  if [ -x "$sib" ]; then
    out=$(run_to 6 "$sib" -n -s / 2>&1)
  else
    out=$(run_to 6 sudoedit_exec "$C_PATH" 2>&1)
  fi
  first_line "$out"; line=$REPLY
  case $out in
    *"usage:"*|*"nvalid option"*)
      PROBE_MSG="sudoedit -n -s / -> \"$line\" (patched: -s is rejected in sudoedit mode)"; return 1 ;;
    *"not a regular file"*|*"password is required"*|*"command not found"*|*"not in the sudoers"*|*"not allowed to"*)
      PROBE_MSG="sudoedit -n -s / -> \"$line\" (-s accepted in sudoedit mode; patched builds print usage)"; return 0 ;;
  esac
  PROBE_MSG="sudoedit -n -s / -> \"$line\" (unrecognised)"; return 2
}

probe_chroot() {
  local d="/nonexistent-lpecheck-$$" out line
  [ -e "$d" ] && { PROBE_MSG="probe skipped"; return 2; }
  out=$(cd / && run_to 6 "$C_PATH" -n -R "$d" true 2>&1)
  first_line "$out"; line=$REPLY
  case $out in
    *"true: No such file or directory"*)
      PROBE_MSG="sudo -n -R <missing dir> true -> \"$line\" (chroot resolved before authorisation; fixed builds answer with a password/permission error)"; return 0 ;;
    *"not permitted to use the -R option"*|*"password is required"*|*"will be removed in a future"*|*"nvalid option"*|*"not in the sudoers"*|*"not allowed to"*)
      PROBE_MSG="sudo -n -R <missing dir> true -> \"$line\" (patched behaviour)"; return 1 ;;
  esac
  PROBE_MSG="sudo -n -R <missing dir> true -> \"$line\" (unrecognised)"; return 2
}

# ---------------------------------------------------------------- evaluation

NF=0; NX=0

finding() {  # TIER WHY
  F_TIER[$NF]=$1; F_ID[$NF]=$R_ID; F_NAME[$NF]=$R_NAME; F_REF[$NF]=$R_REF
  F_COMP[$NF]=$C_COMP; F_PATH[$NF]=${C_PATH#"$R"}; F_WHAT[$NF]=$C_WHAT
  F_WHY[$NF]=$2; F_PRE[$NF]=$PRE_TXT; F_PROBE[$NF]=$PROBE_TXT
  NF=$((NF + 1))
}

ruled() {  # KIND WHY
  X_KIND[$NX]=$1; X_ID[$NX]=$R_ID; X_COMP[$NX]=$R_COMP
  X_PATH[$NX]=${C_PATH#"$R"}; X_WHY[$NX]=$2
  NX=$((NX + 1))
}

# fixdb_verdict -> FD (fixed|vuln|none) FD_MSG FD_FORCE
fixdb_verdict() {
  local e key val force series
  FD=none; FD_MSG=; FD_FORCE=0
  fixdb_row "$R_ID" || return
  for e in $FX_ENTRIES; do
    key=${e%%=*}; val=${e#*=}; force=0
    case $val in '!'*) force=1; val=${val#!} ;; esac
    if [ "$C_COMP" = kernel ]; then
      [ "$key" = k ] && [ -n "$K_ABI" ] || continue
      case $K_FLAVOR in generic|lowlatency|generic-lpae|generic-64k) ;; *) continue ;; esac
      series=${val%%-*}
      [ "$series" = "${K_ABI%%-*}" ] || continue
      if [ "${val#*-}" = EOL ]; then
        FD=vuln; FD_MSG="Ubuntu $series kernel series went end-of-life without this fix"
      else
        ver_cmp "${K_ABI/-/.}" "${val/-/.}"
        if [ $VC -lt 0 ]; then
          FD=vuln; FD_MSG="Ubuntu kernel ABI $K_ABI is below the fixed $val"
        else
          FD=fixed; FD_MSG="Ubuntu kernel ABI $K_ABI >= fixed $val"
        fi
      fi
    else
      [ "$key" = "$OS_CODE" ] && [ "$C_STATE" = pkg ] && [ "$C_MGR" = dpkg ] || continue
      if [ "$val" = unfixed ]; then
        FD=vuln; FD_MSG="$OS_CODE never got a fix ($C_PKG $C_PKGVER)"; FD_FORCE=$force
        return
      fi
      # Package from a newer upstream base than this series' fix (foreign .deb,
      # e.g. plucky's 1.9.16p2 on noble): sorting above the fix proves nothing.
      pkg_upstream "$C_PKGVER"; series=$REPLY
      pkg_upstream "$val"; ver_cmp "$series" "$REPLY"
      [ $VC -gt 0 ] && continue
      if "$PM_dpkg" --compare-versions "$C_PKGVER" lt "$val" 2>/dev/null; then
        FD=vuln; FD_MSG="$C_PKG $C_PKGVER is below the $OS_CODE fix $val (dpkg --compare-versions)"
      else
        FD=fixed; FD_MSG="$C_PKG $C_PKGVER >= $OS_CODE fix $val (dpkg --compare-versions)"
      fi
    fi
    FD_FORCE=$force
    return
  done
}

# eval_inst IDX: evaluate the current row against one component instance
eval_inst() {
  local i=$1 inrange=0 clv=none id p rc why tier shown
  C_IDX=$i; C_COMP=${I_COMP[$i]}; C_PATH=${I_PATH[$i]}; C_RAW=${I_RAW[$i]}; C_VER=${I_VER[$i]}
  C_STATE=${I_STATE[$i]}; C_MGR=${I_MGR[$i]}; C_PKG=${I_PKG[$i]}; C_PKGVER=${I_PKGVER[$i]}
  PRE_TXT=; PROBE_TXT=
  shown=$C_RAW
  if [ "$C_COMP" = kernel ]; then
    shown=$C_VER
    C_WHAT="Linux $C_RAW${K_NOTE:+ ($K_NOTE)}"
    ver_affected "$C_VER" "$R_AFF" 1 && inrange=1
  else
    C_WHAT="$C_COMP $C_RAW at ${C_PATH#"$R"}"
    ver_affected "$C_VER" "$R_AFF" 0 && inrange=1
  fi
  fixdb_verdict
  if [ $inrange = 0 ]; then
    if [ "$FD" = vuln ] && [ "$FD_FORCE" = 1 ]; then
      why="distro-specific: $FD_MSG"
    elif [ "$FD" = fixed ] && [ "$FD_FORCE" = 1 ]; then
      ruled FIXED "$C_WHAT: $FD_MSG"
      return
    else
      ruled OUTRANGE "$C_WHAT: version $shown is outside the affected range"
      return
    fi
  else
    why="version $shown is in the affected range (>= $AFF_LO, fixed in $AFF_FIX)"
  fi
  if [ "$FD" = fixed ]; then ruled FIXED "$C_WHAT: $FD_MSG"; return; fi

  if [ "$FD" = none ] && [ "$C_STATE" = pkg ]; then
    changelog_ids "$i"
    case $CL_STATE in
      ok) clv=clean ;;
      *) clv=unk ;;
    esac
    for id in ${R_ID//\// }; do
      case $CL_IDS in *" $id "*) ruled FIXED "$C_WHAT: $C_MGR package $C_PKG $C_PKGVER changelog lists $id (backported fix)"; return ;; esac
    done
  fi

  local pre_unk=0
  for p in $R_PRE; do
    [ "$p" = - ] && continue
    pre_$p; rc=$?
    case $rc in
      1) ruled NOPRE "$C_WHAT: $PRE_MSG"; return ;;
      2) pre_unk=1; PRE_TXT="$PRE_TXT${PRE_TXT:+; }UNKNOWN: $PRE_MSG" ;;
      *) PRE_TXT="$PRE_TXT${PRE_TXT:+; }$PRE_MSG" ;;
    esac
  done

  if [ "$R_PROBE" != - ] && [ "$OPT_PROBE" = 1 ]; then
    probe_$R_PROBE; rc=$?
    PROBE_TXT=$PROBE_MSG
    case $rc in
      0) finding CONFIRMED "$why; ${I_WHY[$i]}"; return ;;
      1) ruled FIXED "$C_WHAT: probe: $PROBE_MSG"; return ;;
    esac
  fi

  tier=POSSIBLE
  if [ "$FD" = vuln ]; then
    tier=LIKELY; why="$why; $FD_MSG"
  elif [ "$C_STATE" = src ]; then
    tier=LIKELY; why="$why; ${I_WHY[$i]}"
  elif [ "$C_STATE" = pkg ]; then
    if [ $clv = clean ]; then
      tier=LIKELY; why="$why; ${I_WHY[$i]}, and its changelog ($CL_SRC) has no entry for ${R_ID//\// or }"
    elif [ "$CL_STATE" = trunc ]; then
      why="$why; ${I_WHY[$i]}; changelog is truncated (Ubuntu keeps only recent entries), fix status unknown"
    else
      why="$why; ${I_WHY[$i]}; no changelog available, fix status unknown"
    fi
  else
    why="$why; ${I_WHY[$i]}"
  fi
  if [ $tier = LIKELY ] && [ $pre_unk = 1 ]; then
    tier=POSSIBLE; why="$why; a precondition could not be checked"
  fi
  finding $tier "$why"
}

eval_row() {
  local i n=0
  ensure "$R_COMP"
  i=0
  while [ $i -lt $N_INST ]; do
    if [ "${I_COMP[$i]}" = "$R_COMP" ]; then eval_inst $i; n=$((n + 1)); fi
    i=$((i + 1))
  done
  if [ $n = 0 ]; then C_PATH=; ruled ABSENT "$R_COMP not present"; fi
}

# ---------------------------------------------------------------- report

color_init() {
  C_R=; C_Y=; C_B=; C_D=; C_0=
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ $OPT_TSV = 0 ]; then
    C_R=$(printf '\033[1;31m'); C_Y=$(printf '\033[1;33m'); C_B=$(printf '\033[1;36m')
    C_D=$(printf '\033[2m'); C_0=$(printf '\033[0m')
  fi
}

print_finding() {
  local i=$1 col=$C_Y
  [ "${F_TIER[$i]}" = CONFIRMED ] && col=$C_R
  printf '%s[%s]%s %s  %s\n' "$col" "${F_TIER[$i]}" "$C_0" "${F_ID[$i]}" "${F_NAME[$i]}"
  printf '    target:   %s\n' "${F_WHAT[$i]}"
  printf '    evidence: %s\n' "${F_WHY[$i]}"
  [ -n "${F_PROBE[$i]}" ] && printf '    probe:    %s\n' "${F_PROBE[$i]}"
  [ -n "${F_PRE[$i]}" ] && printf '    needs:    %s\n' "${F_PRE[$i]}"
  printf '    ref:      %s\n\n' "${F_REF[$i]}"
}

report() {
  local i t n line nfix=0 nout=0 npre=0 nabs=0 nposs=0 nc=0 nl=0
  if [ $OPT_TSV = 1 ]; then
    i=0
    while [ $i -lt $NF ]; do
      printf '%s\t%s\t%s\t%s\t%s\n' "${F_TIER[$i]}" "${F_ID[$i]}" "${F_COMP[$i]}" "${F_PATH[$i]}" \
        "${F_WHY[$i]}${F_PROBE[$i]:+ | probe: ${F_PROBE[$i]}}${F_PRE[$i]:+ | needs: ${F_PRE[$i]}}"
      i=$((i + 1))
    done
    i=0
    while [ $i -lt $NX ]; do
      printf '%s\t%s\t%s\t%s\t%s\n' "${X_KIND[$i]}" "${X_ID[$i]}" "${X_COMP[$i]}" "${X_PATH[$i]}" "${X_WHY[$i]}"
      i=$((i + 1))
    done
    return
  fi

  for t in CONFIRMED LIKELY; do
    i=0
    while [ $i -lt $NF ]; do
      if [ "${F_TIER[$i]}" = $t ]; then
        print_finding $i
        [ $t = CONFIRMED ] && nc=$((nc + 1)) || nl=$((nl + 1))
      fi
      i=$((i + 1))
    done
  done

  line=
  i=0
  while [ $i -lt $NF ]; do
    if [ "${F_TIER[$i]}" = POSSIBLE ]; then
      nposs=$((nposs + 1))
      if [ "${F_COMP[$i]}" = kernel ]; then t="kernel ${K_REL}"; else t="${F_WHAT[$i]%% at *}"; fi
      line="$line${line:+, }${F_ID[$i]} ($t)"
    fi
    i=$((i + 1))
  done
  if [ $nposs -gt 0 ]; then
    printf '%s[POSSIBLE]%s %d in range but undecidable: %s\n' "$C_D" "$C_0" $nposs "$line"
    if [ $OPT_V = 1 ]; then
      i=0
      while [ $i -lt $NF ]; do
        [ "${F_TIER[$i]}" = POSSIBLE ] && printf '    %s: %s%s\n' "${F_ID[$i]}" "${F_WHY[$i]}" "${F_PRE[$i]:+ | needs: ${F_PRE[$i]}}"
        i=$((i + 1))
      done
    fi
    echo
  fi
  [ $((nc + nl + nposs)) = 0 ] && printf 'No known local privilege-escalation CVE from the table applies.\n\n'

  i=0
  while [ $i -lt $NX ]; do
    case ${X_KIND[$i]} in
      FIXED) nfix=$((nfix + 1)) ;; OUTRANGE) nout=$((nout + 1)) ;;
      NOPRE) npre=$((npre + 1)) ;; ABSENT) nabs=$((nabs + 1)) ;;
    esac
    i=$((i + 1))
  done
  printf '%ssummary: %d confirmed, %d likely, %d possible | ruled out: %d patched (backport/probe), %d precondition not met, %d version out of range, %d component absent%s\n' \
    "$C_B" $nc $nl $nposs $nfix $npre $nout $nabs "$C_0"
  if [ $OPT_V = 1 ]; then
    for t in FIXED NOPRE OUTRANGE ABSENT; do
      i=0
      while [ $i -lt $NX ]; do
        [ "${X_KIND[$i]}" = $t ] && printf '    %-8s %-16s %s\n' $t "${X_ID[$i]}" "${X_WHY[$i]}"
        i=$((i + 1))
      done
    done
  else
    printf '%s(run with -v to list the ruled-out CVEs and why)%s\n' "$C_D" "$C_0"
  fi
}

timing_table() {
  local s ms n total=0 rows=0
  [ $OPT_TSV = 1 ] && return
  printf '\n%-13s %7s %9s\n' section checks time
  for s in setup sudo pkexec glibc screen snapd exim chkrootkit nginx xorg enlightenment needrestart systemd kernel; do
    eval "ms=\${T_$s:-}; n=\${N_$s:-0}"
    [ -n "$ms" ] || continue
    total=$((total + ms)); rows=$((rows + n))
    [ $s = setup ] && n=-
    printf '%-13s %7s %6d ms\n' $s "$n" $ms
  done
  printf '%-13s %7s %6d ms%s\n' total $rows $total "${MS_COARSE:+  (no sub-second clock here: 1 s resolution)}"
}

usage() {
  printf 'lpecheck %s - detect known Linux local privilege-escalation CVEs (detection only)\n' "$LPE_VERSION"
  printf 'usage: lpecheck.sh [-v] [--tsv] [--no-probes]\n'
  printf '  -v           list ruled-out CVEs with reasons, expand POSSIBLE\n'
  printf '  --tsv        STATUS<TAB>CVE<TAB>component<TAB>path<TAB>reason\n'
  printf '  --no-probes  no sudo -l / sudoedit -s / sudo -R / unshare, version logic only\n'
}

main() {
  local rest line t0 a
  for a in "$@"; do
    case $a in
      -v|--verbose) OPT_V=1 ;;
      --tsv) OPT_TSV=1 ;;
      --no-probes) OPT_PROBE=0 ;;
      -h|--help) usage; return 0 ;;
      *) usage; return 2 ;;
    esac
  done
  PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
  export LC_ALL=C
  color_init

  now_ms; t0=$NOW
  ME=$(id -un 2>/dev/null); MY_UID=$(id -u 2>/dev/null); MY_GROUPS=$(id -Gn 2>/dev/null)
  inv_os
  inv_pm
  ensure kernel
  now_ms; T_setup=$((NOW - t0))

  if [ $OPT_TSV = 0 ]; then
    printf '%slpecheck %s%s  %s@%s  %s  kernel %s  pkg:%s\n' "$C_B" "$LPE_VERSION" "$C_0" \
      "${ME:-?}" "$(uname -n 2>/dev/null)" "$OS_PRETTY${OS_CODE:+ [$OS_CODE]}" "${K_REL:-?}" "${PM_AUTH:- none}"
    [ "$MY_UID" = 0 ] && printf 'note: already running as root\n'
    echo
  fi

  rest=$CVE_TABLE
  while [ -n "$rest" ]; do
    line=${rest%%"$NL"*}
    case $rest in *"$NL"*) rest=${rest#*"$NL"} ;; *) rest= ;; esac
    case $line in CVE-*'|'*) ;; *) continue ;; esac
    row_parse "$line"
    now_ms; t0=$NOW
    eval_row
    now_ms
    eval "T_$R_COMP=\$(( \${T_$R_COMP:-0} + NOW - t0 )); N_$R_COMP=\$(( \${N_$R_COMP:-0} + 1 ))"
  done

  report
  timing_table
  return 0
}

if [ -z "${LPE_LIB:-}" ]; then
  main "$@" </dev/null
  exit $?
fi
