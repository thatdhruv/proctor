// seccomp-BPF policy. Escape-relevant syscalls are routed to a user-space
// supervisor (SECCOMP_RET_USER_NOTIF) which logs the attempt and answers EPERM.
#pragma once

#include <string>

namespace proctor {

// Installs NO_NEW_PRIVS + the filter on the calling thread's process.
// Returns the notification listener fd (>=0) or -1 with errno set.
int install_seccomp_filter();

const char* syscall_name(int nr);

// Human readable annotation for a denied call (e.g. "domain=AF_INET").
std::string describe_denied(int nr, const unsigned long long args[6]);

} // namespace proctor
