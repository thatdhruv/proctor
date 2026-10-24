#include "proctor/seccomp_filter.hpp"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <sched.h>

#include <cstdio>
#include <vector>

#if defined(__x86_64__)
#define PROCTOR_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define PROCTOR_ARCH AUDIT_ARCH_AARCH64
#else
#error "unsupported architecture"
#endif

namespace proctor {
namespace {

struct Named {
  int nr;
  const char* name;
};

#define N(x) {__NR_##x, #x}

// Syscalls whose every invocation is denied and logged.
const Named kNotify[] = {
    N(ptrace),          N(mount),          N(umount2),         N(pivot_root),
    N(chroot),          N(unshare),        N(setns),           N(bpf),
    N(kexec_load),      N(init_module),    N(finit_module),    N(delete_module),
    N(open_by_handle_at), N(name_to_handle_at), N(perf_event_open), N(keyctl),
    N(add_key),         N(request_key),    N(userfaultfd),     N(reboot),
    N(swapon),          N(swapoff),        N(sethostname),     N(setdomainname),
    N(process_vm_readv), N(process_vm_writev), N(io_uring_setup), N(io_uring_enter),
    N(io_uring_register), N(move_mount),   N(open_tree),       N(fsopen),
    N(fsconfig),        N(fsmount),        N(fspick),          N(mount_setattr),
#ifdef __NR_kexec_file_load
    N(kexec_file_load),
#endif
#ifdef __NR_iopl
    N(iopl),
#endif
#ifdef __NR_ioperm
    N(ioperm),
#endif
#ifdef __NR_acct
    N(acct),
#endif
    N(syslog),          N(quotactl),       N(lookup_dcookie),  N(personality),
};

constexpr unsigned kCloneNsMask = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC |
                                  CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

} // namespace

const char* syscall_name(int nr) {
  for (const auto& n : kNotify)
    if (n.nr == nr) return n.name;
  if (nr == __NR_socket) return "socket";
  if (nr == __NR_clone) return "clone";
  return "unknown";
}

std::string describe_denied(int nr, const unsigned long long a[6]) {
  char buf[96];
  if (nr == __NR_socket) {
    const char* d = a[0] == AF_INET ? "AF_INET" : a[0] == AF_INET6 ? "AF_INET6"
                  : a[0] == AF_NETLINK ? "AF_NETLINK" : a[0] == AF_PACKET ? "AF_PACKET"
                  : a[0] == AF_VSOCK ? "AF_VSOCK" : nullptr;
    if (d) snprintf(buf, sizeof buf, "network socket domain=%s type=%llu", d, a[1] & 0xF);
    else snprintf(buf, sizeof buf, "non-unix socket domain=%llu", a[0]);
    return buf;
  }
  if (nr == __NR_clone) {
    snprintf(buf, sizeof buf, "clone with namespace flags 0x%llx", a[0] & kCloneNsMask);
    return buf;
  }
  if (nr == __NR_ptrace) { snprintf(buf, sizeof buf, "ptrace request=%llu target=%llu", a[0], a[1]); return buf; }
  return "";
}

int install_seccomp_filter() {
  std::vector<sock_filter> p;
  auto stmt = [&](unsigned short code, unsigned k) { p.push_back(BPF_STMT(code, k)); };
  auto jump = [&](unsigned short code, unsigned k, unsigned char jt, unsigned char jf) {
    p.push_back(BPF_JUMP(code, k, jt, jf));
  };
  const unsigned nr_off = offsetof(struct seccomp_data, nr);
  const unsigned arch_off = offsetof(struct seccomp_data, arch);
  const unsigned arg0_off = offsetof(struct seccomp_data, args[0]); // low word (little endian)

  stmt(BPF_LD | BPF_W | BPF_ABS, arch_off);
  jump(BPF_JMP | BPF_JEQ | BPF_K, PROCTOR_ARCH, 1, 0);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  stmt(BPF_LD | BPF_W | BPF_ABS, nr_off);
#if defined(__x86_64__)
  // Reject the x32 compat ABI, which would bypass number-based rules.
  jump(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif
  for (const auto& n : kNotify) {
    jump(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)n.nr, 0, 1);
    stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
  }
  // clone3 cannot be inspected (flags live behind a pointer): force the glibc
  // fallback to clone(2), whose flags we can check. Silent ENOSYS.
  jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
  // socket(): only AF_UNIX is allowed.
  jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 4);
  stmt(BPF_LD | BPF_W | BPF_ABS, arg0_off);
  jump(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 1, 0);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  // clone(): deny namespace-creating flags.
  jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4);
  stmt(BPF_LD | BPF_W | BPF_ABS, arg0_off);
  jump(BPF_JMP | BPF_JSET | BPF_K, kCloneNsMask, 0, 1);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  sock_fprog prog = {(unsigned short)p.size(), p.data()};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
  return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

} // namespace proctor
