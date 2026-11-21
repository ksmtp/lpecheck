#!/bin/bash
# lpehunt.sh - detect known Linux local privilege-escalation CVEs. DETECTION ONLY.
#
#   bash lpehunt.sh [-v] [--tsv] [--no-probes]
#   curl -s http://me/lpehunt.sh | bash            (| bash -s -- -v   for options)
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
#   1.3  renamed lpecheck -> lpehunt (matches credhunt / lfihunt).
#        26 kernel rows to cover what current linPEAS flags: the 2026 page-cache
#        family (Dirty Frag xfrm/rxrpc, Fragnesia, DirtyClone, pedit COW, Copy
#        Fail, DirtyDecrypt), ptrace exit-race, GhostLock, BadGarbage, Bad Epoll,
#        OVSwrap, AF_UNIX MSG_OOB, posix-cpu-timers, vsock x2, io_uring, StackRot,
#        nf_tables x4, openvswitch, watch_queue, Sequoia. Real NVD lower bounds
#        (linPEAS uses >=6.19 for bugs that reach back to 3.x). Module checks
#        honour modprobe.d "install X /bin/false" / blacklist mitigations, except
#        for built-in code; kernel config read from /boot/config or /proc/config.gz.
#        Batch 2, the rest of linPEAS's CVE checks: CIFSwitch, DiagSpill, net/sched
#        53264 + 21702, nft catchall, AF_ALG 39964, ALSA UMP, OVS page-cache chain,
#        XFSTango, RefluXFS, IPv6 fraggap, SCTPhantom, VsockDrop, ZcopyReaper,
#        CrackArmor, iSCSI, XFRM lucky0, subuid shell, rds 5333, af_packet 7308,
#        SO_SNDBUFFORCE, keyring, ovl_setattr; userspace: snap-confine 8933 / 3888,
#        Pack2TheRoot (PackageKit), libblockdev/udisks2 6019 + SUSE PAM 6018,
#        UDisks fstab 7867, AccountsService 61897, systemd-homed 16742, inetutils
#        telnetd 24061, below 27591, netdata ndsudo 32019, runc Leaky Vessels,
#        OpenDoas 28339 / 25016. FIXDB "k=SERIES-unfixed" = supported, no fix yet.

LPE_VERSION="1.3"

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
CVE-2026-43284 | Dirty Frag (xfrm ESP page-cache write) | kernel | 4.11:5.10.255,5.15.205,6.1.171,6.6.138,6.12.87,6.18.28,7.0.5 | userns esp | - | https://ubuntu.com/blog/dirty-frag-linux-vulnerability-fixes-available
CVE-2026-43500 | Dirty Frag (rxrpc page-cache write) | kernel | 5.3:6.18.29,7.0.6 | userns rxrpc | - | https://ubuntu.com/blog/dirty-frag-linux-vulnerability-fixes-available
CVE-2026-46300 | Fragnesia (ESP-in-TCP, Dirty Frag bypass) | kernel | 3.9:5.10.258,5.15.208,6.1.174,6.6.141,6.12.91,6.18.33,7.0.10 | userns esp espintcp | - | https://www.openwall.com/lists/oss-security/2026/05/13/3
CVE-2026-43503 | DirtyClone | kernel | 3.9:5.10.257,5.15.208,6.1.174,6.6.141,6.12.91,6.18.33,7.0.10 | userns esp | - | https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503
CVE-2026-46331 | pedit COW (act_pedit) | kernel | 4.19.244:4.20 5.4.195:5.5 5.10.117:5.11 5.15.41:5.16 5.17.9:6.12.94,6.18.36,7.0.13 | userns act_pedit | - | https://github.com/sgkdev/packet_edit_meme
CVE-2026-46333 | ptrace exit-race (pidfd_getfd) | kernel | 3.16.52:3.17 4.4.40:4.5 4.8.16:4.9 4.9.1:5.10.256,5.15.207,6.1.173,6.6.139,6.12.89,6.18.31,7.0.8 | ptrace_scope | - | https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt
CVE-2026-43499 | GhostLock (rtmutex PI futex UAF) | kernel | 2.6.39:6.1.175,6.6.140,6.12.86,6.18.27,7.0.4 | futex_pi | - | https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499
CVE-2026-53361 | BadGarbage (AF_UNIX GC race) | kernel | 6.1.141:6.2 6.6.93:6.6.144 6.9:6.12.95,6.18.38,7.1 | - | - | https://github.com/sgkdev/bad_garbage
CVE-2026-31431 | Copy Fail (algif_aead page-cache write) | kernel | 4.14:5.10.254,5.15.204,6.1.170,6.6.137,6.12.85,6.18.22,6.19.12 | algif_aead | - | https://github.com/theori-io/copy-fail-CVE-2026-31431
CVE-2026-46242 | Bad Epoll (epoll UAF) | kernel | 5.15.209:5.16 6.1.175:6.2 6.4:6.18.33,7.0.10 | - | - | https://github.com/J-jaeyoung/bad-epoll
CVE-2026-64531 | OVSwrap (openvswitch integer wrap) | kernel | 5.15.180:5.15.212 6.1.132:6.1.178 6.6.84:6.6.145 6.12.20:6.12.97 6.13.8:6.14 6.14.1:6.18.40,7.1.5 | userns openvswitch | - | https://github.com/manizada/OVSwrap
CVE-2026-31635 | DirtyDecrypt (rxgk missing COW) | kernel | 6.16:6.18.23,6.19.13 | rxgk | - | https://github.com/v12-security/pocs/tree/main/dirtydecrypt
CVE-2025-38236 | AF_UNIX MSG_OOB use-after-free | kernel | 5.15:5.15.194,6.1.143,6.6.96,6.12.36,6.15.5 | unix_oob | - | https://googleprojectzero.blogspot.com/2025/08/from-chrome-renderer-code-exec-to-kernel.html
CVE-2025-38352 | posix-cpu-timers exit race | kernel | 2.6.36:5.4.295,5.10.239,5.15.186,6.1.142,6.6.94,6.12.34,6.15.3 | - | - | https://nvd.nist.gov/vuln/detail/CVE-2025-38352
CVE-2025-21756 | Attack of the Vsock (vsock UAF) | kernel | 5.5:5.10.235,5.15.179,6.1.131,6.6.79,6.12.16,6.13.4 | vsock | - | https://blog.theori.io/attack-of-the-vsock-cve-2025-21756-ea0c33f84e7b
CVE-2024-50264 | vsock virtio UAF | kernel | 4.8:4.19.324,5.4.286,5.10.230,5.15.172,6.1.117,6.6.61,6.11.8 | vsock | - | https://nvd.nist.gov/vuln/detail/CVE-2024-50264
CVE-2024-0582  | io_uring PROVIDE_BUFFERS page UAF | kernel | 6.4:6.6.5 | io_uring | - | https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582
CVE-2023-35001 | nf_tables nft_byteorder OOB | kernel | 3.13:4.14.322,4.19.291,5.4.251,5.10.188,5.15.121,6.1.39,6.4.4 | userns nft | - | https://www.exodusintel.com/2023/09/20/cve-2023-35001-linux-kernel-oob/
CVE-2023-0179  | nf_tables nft_payload stack overflow | kernel | 5.5:5.10.164,5.15.89,6.1.7 | userns nft | - | https://github.com/TurtleARM/CVE-2023-0179-PoC
CVE-2023-3269  | StackRot (maple tree VMA UAF) | kernel | 6.1:6.1.37,6.3.11,6.4.1 | - | - | https://github.com/lrh2000/StackRot
CVE-2022-32250 | nf_tables set UAF | kernel | 4.1:4.9.318,4.14.283,4.19.247,5.4.198,5.10.120,5.15.45,5.17.13,5.18.2 | userns nft | - | https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
CVE-2022-2586  | nf_tables cross-table UAF | kernel | 3.16:4.14.316,4.19.256,5.4.211,5.10.137,5.15.61,5.18.18,5.19.2 | userns nft | - | https://www.openwall.com/lists/oss-security/2022/08/29/5
CVE-2022-2639  | openvswitch reserve_sfa_size OOB | kernel | 3.18.139:3.19 4.4.179:4.5 4.9.169:4.9.312 4.14.112:4.14.277 4.19.35:4.19.240 5.0.8:5.4.191,5.10.113,5.15.36,5.17.5 | userns openvswitch | - | https://github.com/avboy1337/CVE-2022-2639-PipeVersion
CVE-2022-0995  | watch_queue OOB write | kernel | 5.8:5.10.106,5.15.29,5.16.5 | watch_queue | - | https://github.com/Bonfee/CVE-2022-0995
CVE-2026-46243 | CIFSwitch (cifs.spnego key description) | kernel | 2.6.24:5.10.258,5.15.209,6.1.175,6.6.142,6.12.92,6.18.34,7.0.11 | cifs_spnego | - | https://nvd.nist.gov/vuln/detail/CVE-2026-46243
CVE-2026-74469 | DiagSpill (sctp_diag) | kernel | 4.7:5.10.265,5.15.216,6.1.183,6.6.151,6.12.103,6.18.44,7.1.8 | sctp_diag | - | https://nvd.nist.gov/vuln/detail/CVE-2026-74469
CVE-2026-53264 | net/sched action use-after-free | kernel | 4.14:5.10.259,5.15.210,6.1.176,6.6.143,6.12.94,6.18.36,7.0.13 | userns net_sched | - | https://nvd.nist.gov/vuln/detail/CVE-2026-53264
CVE-2026-23111 | nf_tables catchall verdict-map UAF | kernel | 4.19.316:4.20 5.4.262:5.5 5.10.188:5.11 5.15.121:5.15.200 6.1.36:6.1.163 6.3.10:6.4 6.4:6.6.124,6.12.70,6.18.10 | userns nft | - | https://nvd.nist.gov/vuln/detail/CVE-2026-23111
CVE-2025-39964 | AF_ALG concurrent writers | kernel | 2.6.38:5.10.245,5.15.194,6.1.154,6.6.108,6.12.49,6.16.9 | af_alg | - | https://nvd.nist.gov/vuln/detail/CVE-2025-39964
CVE-2025-37891 | ALSA UMP SysEx overflow | kernel | 6.5:6.6.90,6.12.28,6.14.6 | snd_ump | - | https://nvd.nist.gov/vuln/detail/CVE-2025-37891
CVE-2026-80977/CVE-2026-89487/CVE-2026-90049 | openvswitch forwarded-skb page-cache chain | kernel | 3.14:5.10.270,5.15.221,6.1.188,6.6.157,6.12.110,6.18.51,7.2.5 | userns openvswitch esp | - | https://nvd.nist.gov/vuln/detail/CVE-2026-80977
CVE-2026-80530 | XFSTango (XFS reflink race) | kernel | 6.10:6.12.105,6.18.46,7.1.10 | xfs_reflink | - | https://nvd.nist.gov/vuln/detail/CVE-2026-80530
CVE-2026-64600 | RefluXFS (XFS stale mapping race) | kernel | 4.11:5.15.212,6.1.178,6.6.145,6.12.96,6.18.39,7.1.4 | xfs_reflink | - | https://nvd.nist.gov/vuln/detail/CVE-2026-64600
CVE-2026-53362 | IPv6 fraggap OOB write | kernel | 6.0:6.1.177,6.6.144,6.12.95,6.18.38,7.1.3 | ipv6 | - | https://nvd.nist.gov/vuln/detail/CVE-2026-53362
CVE-2026-64564 | SCTPhantom (SCTP ASCONF UAF) | kernel | 2.6.25:5.10.265,5.15.216,6.1.183,6.6.148,6.12.101,6.18.42,7.1.6 | sctp | - | https://nvd.nist.gov/vuln/detail/CVE-2026-64564
CVE-2026-53365 | VsockDrop (vsock zerocopy refcount) | kernel | 6.7:6.18.34,7.0.11 | vsock io_uring | - | https://nvd.nist.gov/vuln/detail/CVE-2026-53365
CVE-2026-43502 | ZcopyReaper (RDS zerocopy UAF) | kernel | 4.17:5.10.258,5.15.209,6.1.175,6.6.140,6.12.88,6.18.30,7.0.7 | rds_tcp | - | https://nvd.nist.gov/vuln/detail/CVE-2026-43502
CVE-2025-21702 | net/sched pfifo_tail_enqueue UAF | kernel | 2.6.34:5.4.291,5.10.235,5.15.179,6.1.130,6.6.83,6.12.14,6.13.3 | userns | - | https://nvd.nist.gov/vuln/detail/CVE-2025-21702
CVE-2021-27365 | iSCSI netlink heap overflow | kernel | 2.6.12:4.4.260,4.9.260,4.14.224,4.19.179,5.4.103,5.10.21,5.11.4 | iscsi | - | https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
CVE-2019-15666 | XFRM policy UAF (lucky0) | kernel | 3.0:5.0.19 | userns | - | https://duasynt.com/blog/ubuntu-centos-redhat-privesc
CVE-2018-18955 | subuid shell (nested userns id map) | kernel | 4.15:4.19.2 | userns newuidmap | - | https://www.exploit-db.com/exploits/45886
CVE-2018-5333 | rds_atomic_free_op NULL deref | kernel | 4.4:4.14.14 | rds | - | https://github.com/wbowling/cpu.Bugs/tree/master/rds
CVE-2017-7308  | af_packet packet_set_ring | kernel | 2.6.27:3.2.89,3.10.107,3.12.74,3.16.44,3.18.52,4.1.41,4.4.66,4.9.26,4.10.14 | userns | - | https://www.exploit-db.com/exploits/41994
CVE-2016-9793  | SO_SNDBUFFORCE negative sk_sndbuf | kernel | 3.5:3.12.69,3.16.40,3.18.52,4.1.50,4.4.38,4.8.14 | userns | - | https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
CVE-2016-0728  | keyring refcount overflow | kernel | 3.8:3.10.95,3.12.53,3.14.59,3.16.35,3.18.26,4.1.16,4.3.4,4.4.1 | - | - | https://www.exploit-db.com/exploits/39277
CVE-2015-8660  | overlayfs ovl_setattr | kernel | 3.18:3.18.31,4.1.22,4.4 | userns overlay | - | https://www.exploit-db.com/exploits/39166
CVE-2026-23268 | CrackArmor (AppArmor policy race) | kernel | 4.11:5.10.253,5.15.203,6.1.169,6.6.130,6.12.77,6.18.18,6.19.8 | apparmor | - | https://nvd.nist.gov/vuln/detail/CVE-2026-23268
CVE-2026-8933  | snap-confine file-capabilities race | snapd | 2.75:2.76.1 | snap_confine_caps | - | https://cdn2.qualys.com/advisory/2026/07/21/snap-confine-set-capabilities.txt
CVE-2026-3888  | snap-confine + systemd-tmpfiles /tmp/.snap race | snapd | - | snap_confine_priv snap_tmpfiles | - | https://cdn2.qualys.com/advisory/2026/03/17/snap-confine-systemd-tmpfiles.txt
CVE-2026-41651 | Pack2TheRoot (PackageKit transaction TOCTOU) | packagekit | 1.0.2:1.3.5 | packagekit_dbus | - | https://github.security.telekom.com/2026/04/pack2theroot-linux-local-privilege-escalation.html
CVE-2025-6019  | libblockdev/udisks2 resize mount without nosuid | libblockdev | 0:3.3.1 | allow_active udisksd | - | https://www.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt
CVE-2025-6018  | SUSE PAM pam_env grants allow_active (chains 6019) | pam | 1.3.0:1.3.1 | suse_pam_env | - | https://www.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt
CVE-2026-7867  | UDisks user-mountable fstab entry | udisks2 | 2.10.0:2.11.2 | udisks_fstab | - | https://nvd.nist.gov/vuln/detail/CVE-2026-7867
CVE-2026-61897 | AccountsService set-language-helper (Ubuntu) | accountsservice | - | ubuntu_os set_language_helper | - | https://ubuntu.com/security/CVE-2026-61897
CVE-2026-16742 | systemd-homed identity handling | systemd | 245:258 258:258.10 259:259.8 260:260.4 261:261.2 | homed | - | https://nvd.nist.gov/vuln/detail/CVE-2026-16742
CVE-2026-24061 | GNU inetutils telnetd USER=-f root (telnet localhost) | telnetd | 1.9.3:2.8 | telnetd_listen | - | https://nvd.nist.gov/vuln/detail/CVE-2026-24061
CVE-2025-27591 | below world-writable log dir symlink | below | 0:0.9.0 | below_logdir | - | https://nvd.nist.gov/vuln/detail/CVE-2025-27591
CVE-2024-32019 | netdata ndsudo PATH hijack | ndsudo | 1.44.0:1.45.3 | suid | - | https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93
CVE-2024-21626 | Leaky Vessels (runc WORKDIR fd leak) | runc | 1.0.0:1.1.12 | container_access | - | https://snyk.io/blog/leaky-vessels-docker-runc-container-breakout-vulnerabilities/
CVE-2023-28339 | OpenDoas TIOCSTI terminal injection | doas | 0:6.8.3 | suid tiocsti | - | https://nvd.nist.gov/vuln/detail/CVE-2023-28339
CVE-2019-25016 | OpenDoas keeps the caller PATH | doas | 6.6:6.8.1 | suid | - | https://nvd.nist.gov/vuln/detail/CVE-2019-25016
CVE-2021-33909 | Sequoia (seq_file size_t) | kernel | 3.12.43:3.13 3.16:4.4.276,4.9.276,4.14.240,4.19.198,5.4.134,5.10.52,5.12.19,5.13.4 | userns | - | https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt
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
CVE-2026-43284 | k=4.15.0-251.263 k=5.4.0-231.251 k=5.15.0-181.191 k=6.8.0-124.124 k=6.17.0-35.35 k=7.0.0-22.22 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-43500 | k=5.4.0-231.251 k=5.15.0-181.191 k=6.8.0-124.124 k=6.17.0-35.35 k=7.0.0-22.22 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-46300 | k=3.13.0-214.265 k=4.4.0-283.317 k=4.15.0-253.265 k=5.4.0-233.253 k=5.15.0-181.191 k=6.8.0-124.124 k=6.17.0-35.35 k=7.0.0-22.22 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-43503 | k=3.13.0-214.265 k=4.4.0-283.317 k=4.15.0-253.265 k=5.4.0-233.253 k=5.15.0-181.191 k=6.8.0-124.124 k=6.17.0-35.35 k=7.0.0-22.22 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-46331 | k=!4.15.0-254.266 k=5.4.0-234.254 k=5.15.0-187.197 k=6.8.0-137.137 k=6.17.0-42.42 k=7.0.0-29.29 k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-46333 | k=5.15.0-181.191 k=6.8.0-124.124 k=6.17.0-35.35 k=7.0.0-22.22 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-43499 | k=3.13.0-215.266 k=4.4.0-284.318 k=4.15.0-254.266 k=5.4.0-234.254 k=5.15.0-187.197 k=6.8.0-136.136 k=6.17.0-42.42 k=7.0.0-27.27 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-53361 | k=!6.8.0-147.147 k=7.0.0-31.31 k=6.11.0-EOL k=6.14.0-EOL k=6.17.0-EOL
CVE-2026-31431 | k=4.15.0-250.262 k=5.4.0-230.250 k=5.15.0-179.189 k=6.8.0-117.117 k=6.17.0-29.29 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-46242 | k=!5.15.0-202.212 k=!6.8.0-137.137 k=6.17.0-42.42 k=7.0.0-28.28 k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-64531 | k=!5.15.0-190.200 k=!6.8.0-138.138 k=7.0.0-30.30 k=6.14.0-EOL
CVE-2026-31635 | k=6.17.0-40.40
CVE-2025-38236 | k=5.15.0-170.180 k=6.8.0-100.100 k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL
CVE-2025-38352 | k=3.13.0-210.261 k=4.4.0-274.308 k=4.15.0-243.255 k=5.4.0-223.243 k=5.15.0-156.166 k=6.8.0-87.88 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL
CVE-2025-21756 | k=5.15.0-138.148 k=6.8.0-58.60 k=6.11.0-24.24 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL
CVE-2024-50264 | k=4.15.0-232.244 k=5.4.0-204.224 k=5.15.0-130.140 k=6.8.0-51.52 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL
CVE-2024-0582  | k=6.5.0-21.21
CVE-2023-35001 | k=3.13.0-194.245 k=4.4.0-243.277 k=4.15.0-214.225 k=5.4.0-155.172 k=5.15.0-78.85 k=5.19.0-50.50 k=6.2.0-26.26 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL
CVE-2023-0179  | k=5.15.0-67.74 k=5.19.0-35.36 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL
CVE-2023-3269  | k=6.2.0-26.26
CVE-2022-32250 | k=4.4.0-227.261 k=4.15.0-184.194 k=5.4.0-117.132 k=5.13.0-48.54 k=5.15.0-37.39 k=5.8.0-EOL k=5.11.0-EOL
CVE-2022-2586  | k=4.4.0-231.265 k=4.15.0-191.202 k=5.4.0-124.140 k=5.15.0-46.49 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL
CVE-2022-2639  | k=4.4.0-234.268 k=!4.15.0-189.200 k=5.4.0-122.138 k=5.15.0-41.44 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL
CVE-2022-0995  | k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL
CVE-2026-46243 | k=3.13.0-214.265 k=4.4.0-283.317 k=4.15.0-253.265 k=5.4.0-233.253 k=5.15.0-185.195 k=6.8.0-134.134 k=6.17.0-40.40 k=7.0.0-27.27 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-74469 | k=4.15.0-unfixed k=5.4.0-unfixed k=5.15.0-198.208 k=6.8.0-149.149 k=7.0.0-42.42 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-53264 | k=4.15.0-unfixed k=5.4.0-unfixed k=5.15.0-198.208 k=6.8.0-146.146 k=6.17.0-unfixed k=7.0.0-31.31 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-23111 | k=5.15.0-unfixed k=6.8.0-107.107 k=6.17.0-20.20 k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2025-39964 | k=3.13.0-unfixed k=4.4.0-276.310 k=4.15.0-245.257 k=5.4.0-224.244 k=5.15.0-164.174 k=6.8.0-90.91 k=6.14.0-37.37 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL
CVE-2025-37891 | k=6.8.0-100.100 k=6.14.0-24.24 k=6.11.0-EOL
CVE-2026-80977/CVE-2026-89487/CVE-2026-90049 | k=3.13.0-unfixed k=4.4.0-unfixed k=4.15.0-unfixed k=5.4.0-unfixed k=5.15.0-202.212 k=6.8.0-149.149 k=7.0.0-42.42 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-80530 | k=7.0.0-42.42 k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-64600 | k=4.15.0-unfixed k=5.4.0-unfixed k=5.15.0-198.208 k=6.8.0-147.147 k=7.0.0-31.31 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-53362 | k=6.8.0-147.147 k=6.17.0-unfixed k=7.0.0-31.31 k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-64564 | k=3.13.0-unfixed k=4.4.0-unfixed k=4.15.0-unfixed k=5.4.0-247.267 k=5.15.0-198.208 k=6.8.0-147.147 k=7.0.0-38.38 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-53365 | k=6.8.0-147.147 k=7.0.0-28.28 k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-43502 | k=5.4.0-unfixed k=5.15.0-186.196 k=6.8.0-136.136 k=6.17.0-unfixed k=7.0.0-28.28 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2025-21702 | k=3.13.0-unfixed k=4.4.0-267.301 k=4.15.0-236.248 k=5.4.0-214.234 k=5.15.0-138.148 k=6.8.0-58.60 k=6.11.0-24.24 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL
CVE-2021-27365 | k=3.13.0-185.236 k=4.4.0-206.238 k=4.15.0-139.143 k=5.4.0-70.78
CVE-2019-15666 | k=4.4.0-157.185 k=4.15.0-60.67
CVE-2018-18955 | k=4.15.0-42.45
CVE-2018-5333  | k=3.13.0-142.191 k=4.4.0-119.143
CVE-2017-7308  | k=3.13.0-116.163 k=4.4.0-72.93
CVE-2016-9793  | k=3.13.0-107.154 k=4.4.0-59.80
CVE-2016-0728  | k=3.13.0-76.120
CVE-2026-23268 | k=4.15.0-249.261 k=5.4.0-227.247 k=5.15.0-173.183 k=6.8.0-106.106 k=6.17.0-19.19 k=5.8.0-EOL k=5.11.0-EOL k=5.13.0-EOL k=5.19.0-EOL k=6.2.0-EOL k=6.5.0-EOL k=6.11.0-EOL k=6.14.0-EOL
CVE-2026-8933  | jammy=2.76+ubuntu22.04.1 noble=2.76+ubuntu24.04.1 resolute=2.76+ubuntu26.04.3 trixie=unfixed forky=2.76.3-1
CVE-2026-3888  | xenial=!2.61.4ubuntu0.16.04.1+esm2 bionic=!2.61.4ubuntu0.18.04.1+esm2 focal=!2.67.1+20.04ubuntu1~esm1 jammy=!2.73+ubuntu22.04.1 noble=!2.73+ubuntu24.04.2 questing=!2.73+ubuntu25.10.1 resolute=!2.74.1+ubuntu26.04.3 bookworm=!2.57.6-1+deb12u1 trixie=!2.68.3-3+deb13u1 forky=!2.76-1
CVE-2026-41651 | xenial=!0.8.17-4ubuntu6~gcc5.4ubuntu1.5+esm1 bionic=1.1.9-1ubuntu2.18.04.6+esm1 focal=1.1.13-2ubuntu1.1+esm1 jammy=1.2.5-2ubuntu3.1 noble=1.2.8-2ubuntu1.5 questing=1.3.1-1ubuntu1.1 resolute=1.3.4-3ubuntu1 bullseye=1.2.2-2+deb11u1 bookworm=1.2.6-5+deb12u1 trixie=1.3.1-1+deb13u1
CVE-2025-6019  | bionic=2.16-2ubuntu0.1~esm1 focal=2.23-2ubuntu3+esm1 jammy=2.26-1ubuntu0.1 noble=3.1.1-1ubuntu0.1 bullseye=2.25-2+deb11u1 bookworm=2.28-2+deb12u1 trixie=3.3.0-2.1 forky=3.3.0-2.1
CVE-2026-7867  | noble=2.10.1-6ubuntu1.5 resolute=2.10.91-1ubuntu2.1 trixie=2.10.1-12.1+deb13u2
CVE-2026-61897 | trusty=!0.6.35-0ubuntu7.3+esm4 xenial=!0.6.40-2ubuntu11.6+esm2 bionic=!0.6.45-1ubuntu1.3+esm2 focal=!0.6.55-0ubuntu12~20.04.7+esm1 jammy=!22.07.5-2ubuntu1.6 noble=!23.13.9-2ubuntu6.1 resolute=!23.13.9-8ubuntu5.2
CVE-2026-16742 | jammy=249.11-0ubuntu3.22 noble=255.4-1ubuntu8.17 resolute=259.5-0ubuntu3.4 bookworm=unfixed trixie=unfixed forky=261.2-1
CVE-2026-24061 | xenial=2:1.9.4-1ubuntu0.1~esm5 bionic=2:1.9.4-3ubuntu0.1+esm4 focal=2:1.9.4-11ubuntu0.2+esm3 jammy=2:2.2-2ubuntu0.2 noble=2:2.5-3ubuntu4.1 questing=2:2.6-1ubuntu3.1 bullseye=2:2.0-1+deb11u4 bookworm=2:2.4-2+deb12u2 trixie=2:2.6-3+deb13u1 forky=2:2.7-2
CVE-2024-21626 | bionic=1.1.4-0ubuntu1~18.04.2+esm1 focal=1.1.7-0ubuntu1~20.04.2 jammy=1.1.7-0ubuntu1~22.04.2 buster=1.0.0~rc6+dfsg1-3+deb10u3 bullseye=1.0.0~rc93+ds1-5+deb11u3 bookworm=1.1.5+ds1-1+deb12u1
CVE-2021-33909 | k=3.13.0-186.237 k=4.4.0-212.244 k=4.15.0-151.157 k=5.4.0-80.90 k=5.8.0-63.71 k=5.11.0-25.27
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

# first_ver TEXT -> REPLY: first word that looks like a version (leading v / trailing , stripped)
first_ver() {
  local w
  REPLY=
  set -f
  for w in $1; do
    w=${w#v}; w=${w%,}; w=${w%)}
    case $w in [0-9]*.[0-9]*) REPLY=$w; set +f; return ;; esac
  done
  set +f
}

# inv_generic COMP VERARG PATH...: version from the owning package, else "PATH VERARG"
# (VERARG "-" = never run the file: daemons). Files need not be executable (libraries).
inv_generic() {
  local comp=$1 arg=$2 p v out oifs
  shift 2
  FOUND=; SEEN=$NL
  for p in "$@"; do
    [ -f "$p" ] || continue
    resolve "$p"
    case $SEEN in *"$NL$REPLY$NL"*) continue ;; esac
    SEEN="$SEEN$REPLY$NL"; FOUND="$FOUND$p$NL"
  done
  oifs=$IFS; IFS=$NL; set -f; set -- $FOUND; set +f; IFS=$oifs
  for p in "$@"; do
    v=
    owner "$p"
    if [ "$O_STATE" = pkg ]; then pkg_upstream "$O_VER"; v=$O_VER; v=${v#*:}; v=${v%%-*}; v=${v%%+*}; v=${v%%~*}; fi
    if [ -z "$v" ] && [ "$arg" != - ] && [ -x "$p" ]; then
      out=$(run_to 5 "$p" $arg 2>&1 | head -n 3)
      first_ver "$out"; v=$REPLY
    fi
    [ -n "$v" ] && add_inst "$comp" "$p" "$v"
  done
}

inv_packagekit() {
  inv_generic packagekit --version "$R"/usr/libexec/packagekitd "$R"/usr/lib/packagekit/packagekitd \
    "$R"/usr/lib/*/packagekitd "$R"/usr/libexec/packagekit/packagekitd
}
inv_libblockdev() {
  inv_generic libblockdev - "$R"/usr/lib/*/libbd_fs.so.[0-9]* "$R"/usr/lib64/libbd_fs.so.[0-9]* \
    "$R"/lib/*/libbd_fs.so.[0-9]* "$R"/usr/lib/libbd_fs.so.[0-9]*
}
inv_udisks2() {
  inv_generic udisks2 - "$R"/usr/libexec/udisks2/udisksd "$R"/usr/lib/udisks2/udisksd
}
inv_accountsservice() {
  inv_generic accountsservice - "$R"/usr/libexec/accounts-daemon "$R"/usr/lib/accountsservice/accounts-daemon \
    "$R"/usr/libexec/accountsservice/accounts-daemon
}
inv_telnetd() {
  inv_generic telnetd --version "$R"/usr/sbin/telnetd "$R"/usr/sbin/in.telnetd "$R"/usr/libexec/telnetd \
    "$R"/usr/libexec/inetutils/telnetd "$R"/usr/local/libexec/telnetd
}
inv_below() {
  find_bins below
  set -f; set -- $FOUND; set +f
  inv_generic below --version "$@"
}
inv_runc() {
  find_bins runc docker-runc
  set -f; set -- $FOUND; set +f
  inv_generic runc --version "$@"
}
inv_doas() {
  find_bins doas
  set -f; set -- $FOUND; set +f
  inv_generic doas - "$@"
}
inv_pam() {
  inv_generic pam - "$R"/lib64/libpam.so.0 "$R"/usr/lib64/libpam.so.0
}
# netdata's SUID ndsudo helper; version from the owning package or "netdata -v"
inv_ndsudo() {
  local p v d out
  for p in "$R"/usr/libexec/netdata/plugins.d/ndsudo "$R"/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo \
           "$R"/usr/lib/netdata/plugins.d/ndsudo; do
    [ -f "$p" ] || continue
    v=
    owner "$p"
    if [ "$O_STATE" = pkg ]; then v=$O_VER; v=${v#*:}; v=${v%%-*}; v=${v%%+*}; fi
    if [ -z "$v" ]; then
      d=${p%/libexec/netdata/plugins.d/ndsudo}; d=${d%/lib/netdata/plugins.d/ndsudo}
      for out in "$d/sbin/netdata" "$d/bin/netdata" "${d%/usr}/bin/netdata" "$R/usr/sbin/netdata"; do
        [ -x "$out" ] || continue
        out=$(run_to 5 "$out" -v 2>&1 | head -n 1); first_ver "$out"; v=$REPLY; break
      done
    fi
    [ -n "$v" ] && add_inst ndsudo "$p" "${v%%-*}"
  done
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

pre_dccp() { pre_kmod_open dccp IP_DCCP "dccp module"; }

# kmod_blocked MODULE: not loaded, and modprobe.d blacklists it / installs it as true|false
# (blacklist stops alias autoload, which is how socket families get loaded)
kmod_blocked() {
  local d
  grep -q "^$1 " "$R/proc/modules" 2>/dev/null && return 1
  ensure kernel   # built-in (=y) code cannot be blocked by modprobe.d
  grep -qs "/$1\.ko" "$R/lib/modules/$K_REL/modules.builtin" "$R/usr/lib/modules/$K_REL/modules.builtin" && return 1
  for d in "$R/etc/modprobe.d" "$R/run/modprobe.d" "$R/usr/lib/modprobe.d" "$R/lib/modprobe.d"; do
    [ -d "$d" ] || continue
    grep -rqsE "^[[:space:]]*(blacklist[[:space:]]+$1|install[[:space:]]+$1[[:space:]]+(/usr)?/bin/(true|false))([[:space:]]|\$)" "$d" && return 0
  done
  return 1
}

# pre_kmod_open MODULE CONFIG LABEL: available and not blocked in modprobe.d
pre_kmod_open() {
  if kmod_blocked "$1"; then PRE_MSG="$3 is blocked in modprobe.d (mitigation)"; return 1; fi
  pre_kmod "$@"
}

# kconfig SYMBOL -> 0 =y/=m, 1 not set, 2 unknown (no readable kernel config)
kconfig() {
  local f z
  ensure kernel
  f="$R/boot/config-$K_REL"
  if [ -r "$f" ]; then grep -q "^CONFIG_$1=[ym]" "$f" && return 0; return 1; fi
  f="$R/proc/config.gz"
  if [ -r "$f" ] && tool gzip; then
    z=$("$REPLY" -dc "$f" 2>/dev/null)
    if [ -n "$z" ]; then
      case "$NL$z$NL" in *"${NL}CONFIG_$1=y$NL"*|*"${NL}CONFIG_$1=m$NL"*) return 0 ;; esac
      return 1
    fi
  fi
  return 2
}

# pre_kconfig SYMBOL LABEL [DEFAULT_ON]: kernel config option set. DEFAULT_ON=1 treats
# an unreadable config as met (options every distro enables)
pre_kconfig() {
  kconfig "$1"
  case $? in
    0) PRE_MSG="$2 (CONFIG_$1) enabled"; return 0 ;;
    1) PRE_MSG="$2 (CONFIG_$1) not enabled in this kernel"; return 1 ;;
  esac
  if [ "${3:-0}" = 1 ]; then PRE_MSG="kernel config not readable; CONFIG_$1 is on in every distro kernel"; return 0; fi
  PRE_MSG="kernel config not readable, cannot tell whether CONFIG_$1 is set"; return 2
}

# Dirty Frag / DirtyClone / Fragnesia: esp4 or esp6 must be loadable (mitigation blocks both)
pre_esp() {
  local m4 r4 r6
  pre_kmod_open esp4 INET_ESP esp4; r4=$?; m4=$PRE_MSG
  [ $r4 = 0 ] && return 0
  pre_kmod_open esp6 INET6_ESP esp6; r6=$?
  [ $r6 = 0 ] && return 0
  if [ $r4 = 1 ] && [ $r6 = 1 ]; then PRE_MSG="$m4; $PRE_MSG"; return 1; fi
  PRE_MSG="$m4; $PRE_MSG"; return 2
}
pre_espintcp() {
  kconfig INET_ESPINTCP && { PRE_MSG="ESP-in-TCP (CONFIG_INET_ESPINTCP) enabled"; return 0; }
  pre_kconfig INET6_ESPINTCP "ESP-in-TCP over IPv6"
}
pre_rxrpc() { pre_kmod_open rxrpc AF_RXRPC "rxrpc module"; }
pre_act_pedit() { pre_kmod_open act_pedit NET_ACT_PEDIT "act_pedit (tc pedit action)"; }
pre_algif_aead() { pre_kmod_open algif_aead CRYPTO_USER_API_AEAD "algif_aead (AF_ALG AEAD)"; }
pre_openvswitch() { pre_kmod_open openvswitch OPENVSWITCH "openvswitch datapath"; }
pre_futex_pi() { pre_kconfig FUTEX_PI "PI futexes" 1; }
pre_unix_oob() { pre_kconfig AF_UNIX_OOB "AF_UNIX MSG_OOB" 1; }
pre_watch_queue() { pre_kconfig WATCH_QUEUE "watch_queue"; }

pre_rxgk() {
  pre_kconfig RXGK "rxrpc GSSAPI security (rxgk; off on Ubuntu/Debian stable)" || return
  pre_rxrpc
}

pre_vsock() {
  if [ -e "$R/dev/vsock" ]; then PRE_MSG="/dev/vsock present (AF_VSOCK loaded)"; return 0; fi
  pre_kmod_open vsock VSOCKETS "vsock (AF_VSOCK)"
}

pre_io_uring() {
  local f=$R/proc/sys/kernel/io_uring_disabled v
  if [ -r "$f" ]; then
    read -r v < "$f"
    case $v in
      2) PRE_MSG="io_uring disabled (kernel.io_uring_disabled=2)"; return 1 ;;
      1) PRE_MSG="io_uring limited to kernel.io_uring_group members (io_uring_disabled=1)"; return 2 ;;
    esac
  fi
  pre_kconfig IO_URING io_uring 1
}

pre_sctp() { pre_kmod_open sctp IP_SCTP "sctp module"; }
pre_sctp_diag() { pre_sctp || return; pre_kmod_open sctp_diag INET_SCTP_DIAG "sctp_diag module"; }
pre_rds_tcp() { pre_kmod_open rds RDS "rds module" || return; pre_kmod_open rds_tcp RDS_TCP "rds_tcp module"; }
pre_af_alg() { pre_kmod_open algif_skcipher CRYPTO_USER_API_SKCIPHER "algif_skcipher (AF_ALG)"; }
pre_snd_ump() { pre_kconfig SND_UMP "ALSA UMP (MIDI 2.0)"; }
pre_ipv6() { pre_kconfig IPV6 IPv6 1; }
pre_iscsi() { pre_kmod_open scsi_transport_iscsi SCSI_ISCSI_ATTRS "iSCSI transport (scsi_transport_iscsi)"; }
pre_net_sched() {
  pre_kmod_open act_gact NET_ACT_GACT "act_gact" || return
  pre_kmod_open cls_flower NET_CLS_FLOWER "cls_flower"
}

pre_cifs_spnego() {
  grep -q '^cifs ' "$R/proc/modules" 2>/dev/null || { PRE_MSG="cifs module not loaded"; return 1; }
  if grep -rqsE '^[[:space:]]*create[[:space:]]+cifs\.spnego' "$R/etc/request-key.conf" "$R/etc/request-key.d"; then
    PRE_MSG="cifs loaded and a request-key cifs.spnego upcall rule exists"; return 0
  fi
  PRE_MSG="no request-key cifs.spnego rule (cifs-utils upcall not configured)"; return 1
}

pre_newuidmap() {
  local p
  for p in "$R/usr/bin/newuidmap" "$R/bin/newuidmap"; do
    is_suid_root "$p" && { PRE_MSG="SUID newuidmap present"; return 0; }
  done
  PRE_MSG="no SUID-root newuidmap (uidmap package)"; return 1
}

# XFS mounted with reflink=1 (xfs_info reads the superblock geometry of a mounted fs)
pre_xfs_reflink() {
  local mps mp out x seen0=0 unk=0 oifs
  mps=$(grep ' xfs ' "$R/proc/mounts" 2>/dev/null) || { PRE_MSG="no XFS filesystem mounted"; return 1; }
  [ -n "$mps" ] || { PRE_MSG="no XFS filesystem mounted"; return 1; }
  tool xfs_info || { PRE_MSG="XFS mounted; no xfs_info to read reflink"; return 2; }
  x=$REPLY
  oifs=$IFS; IFS=$NL; set -f; set -- $mps; set +f; IFS=$oifs
  for mp in "$@"; do
    set -- $mp; mp=$2
    out=$(run_to 5 "$x" "$mp" 2>/dev/null)
    case $out in
      *reflink=1*) PRE_MSG="XFS with reflink=1 mounted at $mp"; return 0 ;;
      *reflink=0*) seen0=1 ;;
      *) unk=1 ;;
    esac
  done
  if [ $unk = 0 ] && [ $seen0 = 1 ]; then PRE_MSG="XFS mounted, but reflink=0 everywhere"; return 1; fi
  PRE_MSG="XFS mounted; reflink state unreadable"; return 2
}

pre_apparmor() {
  local v
  if [ -r "$R/sys/module/apparmor/parameters/enabled" ]; then
    read -r v < "$R/sys/module/apparmor/parameters/enabled"
    [ "$v" = Y ] && { PRE_MSG="AppArmor enabled"; return 0; }
    PRE_MSG="AppArmor disabled"; return 1
  fi
  [ -d "$R/sys/kernel/security/apparmor" ] && { PRE_MSG="AppArmor securityfs present"; return 0; }
  PRE_MSG="AppArmor not active"; return 1
}

pre_ubuntu_os() {
  case " $OS_ID $OS_LIKE " in *" ubuntu "*) PRE_MSG="Ubuntu"; return 0 ;; esac
  PRE_MSG="not Ubuntu (set-language-helper is an Ubuntu patch)"; return 1
}

# snap-confine variants: SC_SUID (any SUID-root copy), SC_CAPS (getcap shows cap_sys_admin), SC_CAPS_UNK
snap_confine_scan() {
  local p out g
  SC_SUID=; SC_CAPS=; SC_CAPS_UNK=; SC_ANY=
  g=; tool getcap && g=$REPLY
  for p in "$R"/usr/lib/snapd/snap-confine "$R"/usr/libexec/snapd/snap-confine "$R"/snap/snapd/current/usr/lib/snapd/snap-confine; do
    [ -f "$p" ] || continue
    SC_ANY=1
    if is_suid_root "$p"; then SC_SUID=${p#"$R"}; continue; fi
    if [ -n "$g" ]; then
      out=$(run_to 5 "$g" "$p" 2>/dev/null)
      case $out in *cap_sys_admin*) SC_CAPS=${p#"$R"} ;; esac
    else
      SC_CAPS_UNK=${p#"$R"}
    fi
  done
}
pre_snap_confine_caps() {
  snap_confine_scan
  [ -n "$SC_CAPS" ] && { PRE_MSG="$SC_CAPS carries file capabilities (cap_sys_admin)"; return 0; }
  [ -n "$SC_CAPS_UNK" ] && { PRE_MSG="non-SUID $SC_CAPS_UNK, no getcap to read its capabilities"; return 2; }
  [ -n "$SC_ANY" ] && { PRE_MSG="snap-confine is the SUID build, not the file-capabilities one"; return 1; }
  PRE_MSG="no snap-confine"; return 1
}
pre_snap_confine_priv() {
  snap_confine_scan
  [ -n "$SC_SUID" ] && { PRE_MSG="$SC_SUID is SUID root"; return 0; }
  [ -n "$SC_CAPS" ] && { PRE_MSG="$SC_CAPS has cap_sys_admin"; return 0; }
  [ -n "$SC_CAPS_UNK" ] && { PRE_MSG="non-SUID $SC_CAPS_UNK, capabilities unreadable"; return 2; }
  PRE_MSG="no privileged snap-confine"; return 1
}
# the race needs systemd-tmpfiles to age out /tmp/.snap (Ubuntu: 30d on 24.04, 10d on 25.10+)
pre_snap_tmpfiles() {
  local f age t
  f=; for t in "$R/etc/tmpfiles.d/tmp.conf" "$R/usr/lib/tmpfiles.d/tmp.conf" "$R/lib/tmpfiles.d/tmp.conf"; do
    [ -r "$t" ] && { f=$t; break; }
  done
  [ -n "$f" ] || { PRE_MSG="no tmpfiles.d tmp.conf"; return 1; }
  age=$(grep -E '^[[:space:]]*[dDqQ][[:space:]]+/tmp[[:space:]]' "$f" | grep -E '[[:space:]][0-9]+[smhdw][[:space:]]*$' | head -n 1)
  [ -n "$age" ] || { PRE_MSG="${f#"$R"} does not age /tmp"; return 1; }
  set -f; set -- $age; set +f; eval "age=\${$#}"
  for t in "$R"/etc/systemd/system/systemd-tmpfiles-clean.timer "$R"/usr/lib/systemd/system/systemd-tmpfiles-clean.timer "$R"/lib/systemd/system/systemd-tmpfiles-clean.timer; do
    [ -e "$t" ] && { PRE_MSG="/tmp aged after $age (${f#"$R"}), systemd-tmpfiles-clean.timer present"; return 0; }
  done
  PRE_MSG="/tmp age rule $age but no systemd-tmpfiles-clean.timer"; return 2
}

pre_packagekit_dbus() {
  local f
  for f in "$R"/usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service; do
    [ -e "$f" ] && { PRE_MSG="PackageKit D-Bus service activatable"; return 0; }
  done
  PRE_MSG="no PackageKit D-Bus service file"; return 2
}

pre_udisksd() {
  local p
  for p in "$R"/usr/libexec/udisks2/udisksd "$R"/usr/lib/udisks2/udisksd; do
    [ -x "$p" ] && { PRE_MSG="udisksd present"; return 0; }
  done
  PRE_MSG="no udisksd"; return 1
}

# polkit allow_active: the caller must be in an active local session (or SUSE's CVE-2025-6018)
pre_allow_active() {
  local out sid
  sid=${XDG_SESSION_ID:-}
  if [ -n "$sid" ] && tool loginctl; then
    out=$(run_to 5 "$REPLY" show-session "$sid" -p Active -p Remote 2>/dev/null)
    case $out in
      *Active=yes*Remote=no*|*Remote=no*Active=yes*) PRE_MSG="active local session $sid (polkit allow_active)"; return 0 ;;
      *Remote=yes*|*Active=no*)
        case " $OS_ID $OS_LIKE " in *suse*) PRE_MSG="remote session, but SUSE: CVE-2025-6018 can make it allow_active"; return 2 ;; esac
        PRE_MSG="session $sid is remote or inactive: polkit allow_active not granted"; return 1 ;;
    esac
  fi
  case " $OS_ID $OS_LIKE " in *suse*) PRE_MSG="SUSE: allow_active reachable via CVE-2025-6018"; return 2 ;; esac
  PRE_MSG="no logind session (cron/SSH without pam_systemd?): allow_active unlikely"; return 2
}

pre_suse_pam_env() {
  case " $OS_ID $OS_LIKE " in *suse*) ;; *) PRE_MSG="not SUSE (the PAM stack issue is SUSE 15 specific)"; return 1 ;; esac
  if grep -qs '^[[:space:]]*auth.*pam_env' "$R/etc/pam.d/common-auth"; then PRE_MSG="SUSE, pam_env in common-auth"; return 0; fi
  PRE_MSG="SUSE, but pam_env not in /etc/pam.d/common-auth"; return 1
}

pre_udisks_fstab() {
  local m
  m=$(grep -vE '^[[:space:]]*#' "$R/etc/fstab" 2>/dev/null | grep -E '[[:space:]]([^[:space:]]*,)?(user|users|x-udisks-auth)(,[^[:space:]]*)?[[:space:]]' | head -n 1)
  [ -n "$m" ] && { trim "$m"; PRE_MSG="user-mountable fstab entry: $REPLY"; return 0; }
  PRE_MSG="no fstab entry with user/users/x-udisks-auth"; return 1
}

pre_set_language_helper() {
  local p
  for p in "$R"/usr/libexec/accountsservice/set-language-helper "$R"/usr/lib/accountsservice/set-language-helper; do
    [ -e "$p" ] && { PRE_MSG="set-language-helper present"; return 0; }
  done
  PRE_MSG="no set-language-helper"; return 1
}

pre_homed() {
  [ -S "$R/run/systemd/userdb/io.systemd.Home" ] || [ -e "$R/run/systemd/userdb/io.systemd.Home" ] ||
    { PRE_MSG="systemd-homed not running (no io.systemd.Home socket)"; return 1; }
  PRE_MSG="systemd-homed running (io.systemd.Home socket)"; return 0
}

# telnetd reachable: something listens on tcp/23, or inetd/xinetd/systemd enables telnet
pre_telnetd_listen() {
  local f
  for f in "$R/proc/net/tcp" "$R/proc/net/tcp6"; do
    grep -qsE '^[[:space:]]*[0-9]+: [0-9A-F]+:0017 [0-9A-F]+:0000 0A' "$f" && { PRE_MSG="something listens on tcp/23"; return 0; }
  done
  grep -qsE '^[[:space:]]*telnet[[:space:]]' "$R/etc/inetd.conf" && { PRE_MSG="telnet enabled in /etc/inetd.conf"; return 0; }
  if grep -qsE 'disable[[:space:]]*=[[:space:]]*no' "$R/etc/xinetd.d/telnet"; then PRE_MSG="telnet enabled in xinetd"; return 0; fi
  ls "$R"/etc/systemd/system/sockets.target.wants/*telnet* >/dev/null 2>&1 && { PRE_MSG="telnet socket unit enabled"; return 0; }
  [ -r "$R/proc/net/tcp" ] && { PRE_MSG="nothing listens on tcp/23 and telnet is not enabled"; return 1; }
  PRE_MSG="cannot tell whether telnetd is listening"; return 2
}

pre_below_logdir() {
  local d=$R/var/log/below
  [ -d "$d" ] || { PRE_MSG="no /var/log/below"; return 1; }
  [ -L "$d" ] && { PRE_MSG="/var/log/below is a symlink"; return 1; }
  if [ -k "$d" ]; then PRE_MSG="/var/log/below is sticky"; return 1; fi
  if [ -w "$d" ]; then PRE_MSG="/var/log/below is writable by this user and not sticky"; return 0; fi
  PRE_MSG="/var/log/below not writable by this user"; return 1
}

# runc escapes need a way to start containers: docker group / writable docker.sock
pre_container_access() {
  local g s
  for g in $MY_GROUPS; do
    case $g in docker) PRE_MSG="in the docker group (already root-equivalent; runc bug adds a host escape)"; return 0 ;; esac
  done
  for s in "$R/var/run/docker.sock" "$R/run/docker.sock" "$R/run/containerd/containerd.sock"; do
    [ -w "$s" ] && { PRE_MSG="${s#"$R"} is writable"; return 0; }
  done
  PRE_MSG="no docker group / writable container socket (needs a way to start containers)"; return 1
}

pre_tiocsti() {
  local f=$R/proc/sys/dev/tty/legacy_tiocsti v
  if [ -r "$f" ]; then
    read -r v < "$f"
    [ "$v" = 1 ] && { PRE_MSG="dev.tty.legacy_tiocsti=1"; return 0; }
    PRE_MSG="dev.tty.legacy_tiocsti=$v blocks TIOCSTI injection"; return 1
  fi
  ensure kernel
  if [ -n "$K_BASE" ]; then
    ver_cmp "$K_BASE" 6.2
    [ $VC -lt 0 ] && { PRE_MSG="kernel $K_BASE < 6.2 always allows TIOCSTI"; return 0; }
  fi
  PRE_MSG="no dev.tty.legacy_tiocsti sysctl"; return 2
}

# CVE-2026-46333: public exploits use pidfd_getfd (5.6+); yama ptrace_scope >= 2 blocks them
pre_ptrace_scope() {
  local f=$R/proc/sys/kernel/yama/ptrace_scope v
  ensure kernel
  if [ -n "$K_BASE" ]; then
    ver_cmp "$K_BASE" 5.6
    if [ $VC -lt 0 ]; then PRE_MSG="kernel $K_BASE < 5.6 has no pidfd_getfd (the public exploit path)"; return 1; fi
  fi
  if [ -r "$f" ]; then
    read -r v < "$f"
    if [ "$v" -ge 2 ] 2>/dev/null; then PRE_MSG="kernel.yama.ptrace_scope=$v blocks it"; return 1; fi
    PRE_MSG="kernel.yama.ptrace_scope=$v (< 2)"; return 0
  fi
  PRE_MSG="no Yama ptrace_scope (not restricted)"; return 0
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
  local d="/nonexistent-lpehunt-$$" out line
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
      elif [ "${val#*-}" = unfixed ]; then
        FD=vuln; FD_MSG="Ubuntu $series kernel has no fix for this (Ubuntu CVE tracker)"
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
  printf 'lpehunt %s - detect known Linux local privilege-escalation CVEs (detection only)\n' "$LPE_VERSION"
  printf 'usage: lpehunt.sh [-v] [--tsv] [--no-probes]\n'
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
    printf '%slpehunt %s%s  %s@%s  %s  kernel %s  pkg:%s\n' "$C_B" "$LPE_VERSION" "$C_0" \
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
