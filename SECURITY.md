# Security policy and threat model

Proctor exists to run **untrusted agent code**. Please read what is and is not defended.

## What the sandbox defends against
An agent that can run arbitrary shell/Python in a sandbox and wants to (a) reach the network, (b) read or modify
the host or other sandboxes, (c) exhaust resources, or (d) tamper with the reward verifier.

Layers (see `docs/ARCHITECTURE.md`): user + pid + mount + net + ipc + uts + cgroup namespaces, `pivot_root` into a
read-only rootfs, all capabilities dropped, `PR_SET_DUMPABLE=0` on the sandbox init, seccomp-BPF with a
user-notification supervisor that logs every denied escape-relevant syscall, cgroup v2 limits (rlimit fallback),
wall-clock and output caps, and verifier code that runs **outside** the agent's sandbox.

## What it does NOT defend against
* Linux kernel vulnerabilities reachable from the allowed syscall surface (namespaces and seccomp are not a
  hypervisor). For hostile workloads run workers on dedicated nodes and/or under gVisor/Kata
  (`ProctorRun.spec.runtimeClassName`).
* The worker pod itself is privileged (it must create namespaces). The operator removes its API credentials and
  egress, but a kernel escape would land in a privileged pod. Treat sandbox nodes as a blast-radius boundary.
* SQL environments deliberately expose one Unix socket (the broker) into the sandbox. The broker enforces a
  low-privilege role, a statement timeout and row caps, but it is attack surface.
* Without cgroup delegation (plain WSL2, unprivileged users) memory/pids limits fall back to rlimits and a
  fork storm is only stopped by the wall-clock kill. Check `sandbox.cgroup` in any result.
* NetworkPolicy is only a control if your CNI enforces it. The operator proves this with a self-test pod before
  starting workers and fails closed (`NetworkPolicyNotEnforced`).

## Reporting
Open a private security advisory on the repository, or email the maintainer. Please do not file public issues for
sandbox escapes.
