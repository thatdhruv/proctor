# Containment test results

## Full sandbox (all layers)

* seccomp: **on**, cgroup limits: **enforced**
* attempts: **50**, blocked: **50**, forbidden operation succeeded: **0** 
* reached the host or network: **0** 
* host canary listener connections: **0**
* seccomp-blocked attempts with a matching supervisor log entry: **29/29**

| attempt | category | what it tried | result | blocking layer | logged |
|---|---|---|---|---|---|
| `net.tcp_internet` | network | TCP connect to 1.1.1.1:80 | blocked (EPERM) | seccomp|netns | yes |
| `net.tcp_dns_8888` | network | TCP connect to 8.8.8.8:53 | blocked (EPERM) | seccomp|netns | yes |
| `net.udp_dns` | network | UDP datagram to 1.1.1.1:53 | blocked (EPERM) | seccomp|netns | yes |
| `net.dns_resolve` | network | resolve example.com | blocked (-2) | no resolver (nsswitch: files) + netns | — |
| `net.canary_loopback` | network | connect to host canary listener on 127.0.0.1 | blocked (EPERM) | seccomp|netns | yes |
| `net.loopback_postgres` | network | connect to 127.0.0.1:5433 (host Postgres) | blocked (EPERM) | seccomp|netns | yes |
| `net.metadata_service` | network | connect to cloud metadata 169.254.169.254:80 | blocked (EPERM) | seccomp|netns | yes |
| `net.ipv6` | network | TCP connect over IPv6 | blocked (EPERM) | seccomp|netns | yes |
| `net.raw_icmp` | network | raw ICMP socket | blocked (EPERM) | seccomp|netns | yes |
| `net.af_packet` | network | AF_PACKET socket | blocked (EPERM) | seccomp|netns | yes |
| `net.netlink` | network | enumerate network interfaces that are UP (other than lo) | blocked (EPERM) | seccomp|netns | yes |
| `net.docker_socket` | network | connect to /var/run/docker.sock | blocked (ENOENT) | mount-ns | — |
| `net.abstract_unix` | network | connect to host abstract unix socket | blocked (ECONNREFUSED) | net-ns | — |
| `fs.canary_file` | host-fs | read host canary file by absolute path | blocked (ENOENT) | mount-ns | — |
| `fs.etc_shadow` | host-fs | read /etc/shadow | blocked (ENOENT) | mount-ns | — |
| `fs.host_home` | host-fs | list /home | blocked (ENOENT) | mount-ns | — |
| `fs.windows_drive` | host-fs | list /mnt/c | blocked (ENOENT) | mount-ns | — |
| `fs.proc_init_root` | host-fs | read /proc/1/root/etc/passwd | blocked (EACCES) | pid-ns | — |
| `fs.proc_init_mem` | host-fs | read /proc/1/mem (sandbox init: snapshot store) | blocked (EACCES) | dumpable | — |
| `fs.proc_other_pids` | host-fs | see processes outside the sandbox | blocked (None) | pid-ns | — |
| `fs.dev_mem` | host-fs | open /dev/mem | blocked (ENOENT) | mount-ns | — |
| `fs.dev_disk` | host-fs | open block device /dev/sda | blocked (ENOENT) | mount-ns | — |
| `fs.sys_cgroup` | host-fs | write /sys/fs/cgroup/escape | blocked (ENOENT) | mount-ns | — |
| `fs.write_usr` | host-fs | create /usr/bin/pwned | blocked (EROFS) | ro-bind | — |
| `fs.write_etc` | host-fs | create /etc/pwned | blocked (EROFS) | ro-rootfs | — |
| `fs.daemon_socket` | host-fs | find the proctord control socket | blocked (None) | mount-ns | — |
| `fs.symlink_to_host_root` | host-fs | symlink /workspace/r -> /proc/1/root and read through it | blocked (EACCES) | mount-ns | — |
| `sys.mount` | syscall | mount a tmpfs | blocked (None) | seccomp | yes |
| `sys.pivot_root` | syscall | pivot_root | blocked (EPERM) | seccomp | yes |
| `sys.chroot` | syscall | chroot into /proc/1/root | blocked (None) | seccomp | yes |
| `sys.unshare_user` | syscall | unshare(CLONE_NEWUSER) | blocked (None) | seccomp | yes |
| `sys.unshare_net` | syscall | unshare(CLONE_NEWNET) | blocked (None) | seccomp | yes |
| `sys.setns` | syscall | setns into /proc/self/ns/net | blocked (None) | seccomp | yes |
| `sys.clone_newuser` | syscall | fork with clone(CLONE_NEWUSER) | blocked (None) | seccomp | yes |
| `sys.ptrace_attach` | syscall | ptrace(ATTACH) the sandbox init | blocked (EPERM) | seccomp | yes |
| `sys.process_vm_readv` | syscall | process_vm_readv: read memory of sandbox init (pid 1) | blocked (EPERM) | seccomp|dumpable | yes |
| `sys.bpf` | syscall | bpf(BPF_PROG_LOAD) | blocked (EPERM) | seccomp | yes |
| `sys.kexec_load` | syscall | kexec_load | blocked (EPERM) | seccomp | yes |
| `sys.init_module` | syscall | init_module | blocked (EPERM) | seccomp | yes |
| `sys.reboot` | syscall | reboot | blocked (EPERM) | seccomp | yes |
| `sys.sethostname` | syscall | sethostname | blocked (EPERM) | seccomp | yes |
| `sys.open_by_handle_at` | syscall | open_by_handle_at (container breakout primitive) | blocked (EPERM) | seccomp | yes |
| `sys.io_uring_setup` | syscall | io_uring_setup | blocked (EPERM) | seccomp | yes |
| `sys.perf_event_open` | syscall | perf_event_open | blocked (EPERM) | seccomp | yes |
| `sys.userfaultfd` | syscall | userfaultfd | blocked (EPERM) | seccomp | yes |
| `sys.keyctl` | syscall | keyctl | blocked (EPERM) | seccomp | yes |
| `sys.capabilities` | syscall | hold any Linux capability | blocked (None) | caps-dropped | — |
| `res.memory_bomb` | resource | touch 1.5 GiB of memory | blocked (None) | cgroup memory.max / RLIMIT_AS | — |
| `res.disk_fill` | resource | write 400 MiB into the workspace | blocked (None) | tmpfs size / RLIMIT_FSIZE | — |
| `res.fork_storm` | resource | fork 700 processes | blocked (None) | cgroup pids.max | — |

## Ablation: seccomp disabled (network namespace alone)

* seccomp: **OFF (ablation)**, cgroup limits: **enforced**
* attempts: **50**, blocked: **46**, forbidden operation succeeded: **4** ['sys.unshare_user', 'sys.unshare_net', 'sys.setns', 'sys.capabilities']
* reached the host or network: **0** 
* host canary listener connections: **0**
* seccomp-blocked attempts with a matching supervisor log entry: **0/26**

| attempt | category | what it tried | result | blocking layer | logged |
|---|---|---|---|---|---|
| `net.tcp_internet` | network | TCP connect to 1.1.1.1:80 | blocked (ENETUNREACH) | seccomp|netns | no |
| `net.tcp_dns_8888` | network | TCP connect to 8.8.8.8:53 | blocked (ENETUNREACH) | seccomp|netns | no |
| `net.udp_dns` | network | UDP datagram to 1.1.1.1:53 | blocked (ENETUNREACH) | seccomp|netns | no |
| `net.dns_resolve` | network | resolve example.com | blocked (-2) | no resolver (nsswitch: files) + netns | — |
| `net.canary_loopback` | network | connect to host canary listener on 127.0.0.1 | blocked (ENETUNREACH) | seccomp|netns | no |
| `net.loopback_postgres` | network | connect to 127.0.0.1:5433 (host Postgres) | blocked (ENETUNREACH) | seccomp|netns | no |
| `net.metadata_service` | network | connect to cloud metadata 169.254.169.254:80 | blocked (ENETUNREACH) | seccomp|netns | no |
| `net.ipv6` | network | TCP connect over IPv6 | blocked (EADDRNOTAVAIL) | seccomp|netns | no |
| `net.raw_icmp` | network | raw ICMP socket | blocked (EPERM) | seccomp|netns | no |
| `net.af_packet` | network | AF_PACKET socket | blocked (EPERM) | seccomp|netns | no |
| `net.netlink` | network | enumerate network interfaces that are UP (other than lo) | blocked (None) | seccomp|netns | no |
| `net.docker_socket` | network | connect to /var/run/docker.sock | blocked (ENOENT) | mount-ns | — |
| `net.abstract_unix` | network | connect to host abstract unix socket | blocked (ECONNREFUSED) | net-ns | — |
| `fs.canary_file` | host-fs | read host canary file by absolute path | blocked (ENOENT) | mount-ns | — |
| `fs.etc_shadow` | host-fs | read /etc/shadow | blocked (ENOENT) | mount-ns | — |
| `fs.host_home` | host-fs | list /home | blocked (ENOENT) | mount-ns | — |
| `fs.windows_drive` | host-fs | list /mnt/c | blocked (ENOENT) | mount-ns | — |
| `fs.proc_init_root` | host-fs | read /proc/1/root/etc/passwd | blocked (EACCES) | pid-ns | — |
| `fs.proc_init_mem` | host-fs | read /proc/1/mem (sandbox init: snapshot store) | blocked (EACCES) | dumpable | — |
| `fs.proc_other_pids` | host-fs | see processes outside the sandbox | blocked (None) | pid-ns | — |
| `fs.dev_mem` | host-fs | open /dev/mem | blocked (ENOENT) | mount-ns | — |
| `fs.dev_disk` | host-fs | open block device /dev/sda | blocked (ENOENT) | mount-ns | — |
| `fs.sys_cgroup` | host-fs | write /sys/fs/cgroup/escape | blocked (ENOENT) | mount-ns | — |
| `fs.write_usr` | host-fs | create /usr/bin/pwned | blocked (EROFS) | ro-bind | — |
| `fs.write_etc` | host-fs | create /etc/pwned | blocked (EROFS) | ro-rootfs | — |
| `fs.daemon_socket` | host-fs | find the proctord control socket | blocked (None) | mount-ns | — |
| `fs.symlink_to_host_root` | host-fs | symlink /workspace/r -> /proc/1/root and read through it | blocked (EACCES) | mount-ns | — |
| `sys.mount` | syscall | mount a tmpfs | blocked (None) | seccomp | no |
| `sys.pivot_root` | syscall | pivot_root | blocked (EPERM) | seccomp | no |
| `sys.chroot` | syscall | chroot into /proc/1/root | blocked (None) | seccomp | no |
| `sys.unshare_user` | syscall | unshare(CLONE_NEWUSER) | **SUCCEEDED** | seccomp | — |
| `sys.unshare_net` | syscall | unshare(CLONE_NEWNET) | **SUCCEEDED** | seccomp | — |
| `sys.setns` | syscall | setns into /proc/self/ns/net | **SUCCEEDED** | seccomp | — |
| `sys.clone_newuser` | syscall | fork with clone(CLONE_NEWUSER) | blocked (None) | seccomp | no |
| `sys.ptrace_attach` | syscall | ptrace(ATTACH) the sandbox init | blocked (EPERM) | seccomp | no |
| `sys.process_vm_readv` | syscall | process_vm_readv: read memory of sandbox init (pid 1) | blocked (EPERM) | seccomp|dumpable | no |
| `sys.bpf` | syscall | bpf(BPF_PROG_LOAD) | blocked (EPERM) | seccomp | no |
| `sys.kexec_load` | syscall | kexec_load | blocked (ENOSYS) | seccomp | no |
| `sys.init_module` | syscall | init_module | blocked (EPERM) | seccomp | no |
| `sys.reboot` | syscall | reboot | blocked (EPERM) | seccomp | no |
| `sys.sethostname` | syscall | sethostname | blocked (EPERM) | seccomp | no |
| `sys.open_by_handle_at` | syscall | open_by_handle_at (container breakout primitive) | blocked (EPERM) | seccomp | no |
| `sys.io_uring_setup` | syscall | io_uring_setup | blocked (EFAULT) | seccomp | no |
| `sys.perf_event_open` | syscall | perf_event_open | blocked (EFAULT) | seccomp | no |
| `sys.userfaultfd` | syscall | userfaultfd | blocked (EPERM) | seccomp | no |
| `sys.keyctl` | syscall | keyctl | blocked (EINVAL) | seccomp | no |
| `sys.capabilities` | syscall | hold any Linux capability | **SUCCEEDED** | caps-dropped | — |
| `res.memory_bomb` | resource | touch 1.5 GiB of memory | blocked (None) | cgroup memory.max / RLIMIT_AS | — |
| `res.disk_fill` | resource | write 400 MiB into the workspace | blocked (None) | tmpfs size / RLIMIT_FSIZE | — |
| `res.fork_storm` | resource | fork 700 processes | blocked (None) | cgroup pids.max | — |
