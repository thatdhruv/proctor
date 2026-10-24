#include "proctor/sandbox.hpp"

#include <fcntl.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "proctor/seccomp_filter.hpp"

namespace proctor {
namespace {

std::atomic<uint64_t> g_counter{0};
std::mutex g_log_mu;

bool write_text(const std::string& path, const std::string& v) {
  int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) return false;
  ssize_t n = ::write(fd, v.data(), v.size());
  ::close(fd);
  return n == (ssize_t)v.size();
}

std::string read_text(const std::string& path) {
  std::ifstream f(path);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

double mono_ms() {
  using namespace std::chrono;
  return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

} // namespace

std::string detect_cgroup_base(std::string* note) {
  std::string own = read_text("/proc/self/cgroup");
  auto p = own.find("0::");
  if (p == std::string::npos) {
    *note = "cgroup v2 not mounted";
    return "";
  }
  std::string rel = own.substr(p + 3);
  while (!rel.empty() && (rel.back() == '\n' || rel.back() == ' ')) rel.pop_back();
  std::string base = "/sys/fs/cgroup" + (rel == "/" ? "" : rel);
  if (access(base.c_str(), W_OK) != 0) {
    *note = "cgroup " + base + " is not writable by this user (no delegation)";
    return "";
  }
  // cgroup v2 "no internal processes": move every process out of the base group
  // (like Docker's dind entrypoint) so controllers can be delegated to children.
  std::string self = base + "/daemon";
  if (mkdir(self.c_str(), 0755) == 0 || errno == EEXIST) {
    std::istringstream pids(read_text(base + "/cgroup.procs"));
    std::string pid;
    while (pids >> pid) write_text(self + "/cgroup.procs", pid);
  }
  write_text(base + "/cgroup.subtree_control", "+memory +pids +cpu");
  return base;
}

std::unique_ptr<Sandbox> Sandbox::create(const SandboxConfig& cfg_in, std::string* err) {
  std::unique_ptr<Sandbox> sb(new Sandbox());
  sb->cfg_ = cfg_in;
  auto& cfg = sb->cfg_;
  if (cfg.id.empty()) cfg.id = "sb-" + std::to_string(getpid()) + "-" + std::to_string(g_counter++);
  const double t0 = mono_ms();

  // ---- cgroup (best effort) ----
  std::string base = cfg.cgroup_base;
  if (base.empty()) base = detect_cgroup_base(&sb->stats_.cgroup_note);
  else if (base == "none") { base.clear(); sb->stats_.cgroup_note = "disabled by config"; }
  if (!base.empty()) {
    std::string dir = base + "/proctor-" + cfg.id;
    if (mkdir(dir.c_str(), 0755) == 0) {
      const auto& l = cfg.limits;
      bool ok = write_text(dir + "/memory.max", std::to_string(l.memory_bytes)) &&
                write_text(dir + "/pids.max", std::to_string(l.pids_max));
      write_text(dir + "/memory.swap.max", "0");
      char cpu[64];
      snprintf(cpu, sizeof cpu, "%u 100000", l.cpu_percent * 1000);
      write_text(dir + "/cpu.max", cpu);
      if (ok) {
        sb->stats_.cgroup = true;
        sb->stats_.cgroup_path = dir;
      } else {
        rmdir(dir.c_str());
        sb->stats_.cgroup_note = "controllers not delegated in " + base;
      }
    } else {
      sb->stats_.cgroup_note = "mkdir " + dir + " failed: " + strerror(errno);
    }
  }

  // ---- clone ----
  int sv[2], sync[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0 || pipe2(sync, O_CLOEXEC) != 0) {
    *err = std::string("socketpair/pipe: ") + strerror(errno);
    return nullptr;
  }
  const uid_t uid = getuid();
  const gid_t gid = getgid();
  const std::string init_path = cfg.init_path;
  const int flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC |
                    CLONE_NEWUTS | CLONE_NEWCGROUP | SIGCHLD;
  long pid = syscall(SYS_clone, flags, 0, 0, 0, 0);
  if (pid < 0) {
    *err = std::string("clone(CLONE_NEW*): ") + strerror(errno);
    return nullptr;
  }
  if (pid == 0) {
    // Child: only async-signal-safe calls until execv.
    char go = 0;
    if (read(sync[0], &go, 1) != 1 || go != 'g') _exit(120);
    if (sv[1] != 3) dup2(sv[1], 3);
    fcntl(3, F_SETFD, 0); // dup2 to self keeps CLOEXEC, so clear it explicitly
    char fdarg[] = "3";
    char* argv[] = {(char*)"proctor-init", fdarg, nullptr};
    execv(init_path.c_str(), argv);
    _exit(121);
  }
  sb->pid_ = (int)pid;
  close(sv[1]);
  close(sync[0]);
  sb->ctl_fd_ = sv[0];

  auto fail = [&](const std::string& m) -> std::unique_ptr<Sandbox> {
    *err = m;
    close(sync[1]);
    return nullptr; // ~Sandbox kills the child
  };

  std::string pp = "/proc/" + std::to_string(pid);
  if (!write_text(pp + "/setgroups", "deny")) return fail("write setgroups failed");
  if (!write_text(pp + "/uid_map", "0 " + std::to_string(uid) + " 1"))
    return fail(std::string("write uid_map failed: ") + strerror(errno));
  if (!write_text(pp + "/gid_map", "0 " + std::to_string(gid) + " 1"))
    return fail("write gid_map failed");
  if (sb->stats_.cgroup && !write_text(sb->stats_.cgroup_path + "/cgroup.procs", std::to_string(pid)))
    return fail("cgroup attach failed: " + std::string(strerror(errno)));
  if (write(sync[1], "g", 1) != 1) return fail("sync write failed");
  close(sync[1]);

  struct timeval tv = {15, 0};
  setsockopt(sb->ctl_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

  json hello = {{"op", "setup"},
                {"hostname", cfg.hostname},
                {"limits", cfg.limits},
                {"binds", cfg.binds},
                {"seccomp", cfg.seccomp},
                {"degraded", !sb->stats_.cgroup}};
  if (!send_frame(sb->ctl_fd_, hello)) return fail("send setup failed");
  json ready;
  int nfd = -1;
  if (!recv_frame(sb->ctl_fd_, &ready, &nfd)) return fail("sandbox did not become ready (init died?)");
  if (!ready.value("ok", false)) return fail("sandbox setup failed: " + ready.value("error", std::string("?")));
  if (cfg.seccomp && nfd < 0) return fail("no seccomp notification fd received");
  sb->notif_fd_ = nfd;
  tv = {0, 0};
  setsockopt(sb->ctl_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

  if (nfd >= 0) sb->sup_ = std::thread(&Sandbox::supervise, sb.get());
  sb->stats_.spawn_ms = mono_ms() - t0;
  return sb;
}

Sandbox::~Sandbox() {
  stop_ = true;
  if (pid_ > 0) {
    if (stats_.cgroup) write_text(stats_.cgroup_path + "/cgroup.kill", "1");
    kill(pid_, SIGKILL);
    int st;
    waitpid(pid_, &st, 0);
  }
  if (sup_.joinable()) sup_.join();
  if (ctl_fd_ >= 0) close(ctl_fd_);
  if (notif_fd_ >= 0) close(notif_fd_);
  if (stats_.cgroup) {
    for (int i = 0; i < 20 && rmdir(stats_.cgroup_path.c_str()) != 0; i++) usleep(2000);
  }
}

bool Sandbox::alive() {
  if (pid_ <= 0) return false;
  int st;
  pid_t r = waitpid(pid_, &st, WNOHANG);
  if (r == pid_) { pid_ = -1; return false; }
  return true;
}

uint64_t Sandbox::cgroup_counter(const char* file, const char* key) {
  if (!stats_.cgroup) return 0;
  std::istringstream in(read_text(stats_.cgroup_path + "/" + file));
  std::string k;
  uint64_t v;
  while (in >> k >> v)
    if (k == key) return v;
  return 0;
}

json Sandbox::rpc(const json& req, bool* ok) {
  std::lock_guard<std::mutex> g(rpc_mu_);
  json resp;
  uint32_t wait_ms = 20000;
  if (req.contains("timeout_ms")) wait_ms = (uint32_t)req["timeout_ms"] + 8000;
  struct timeval tv = {(time_t)(wait_ms / 1000), (suseconds_t)((wait_ms % 1000) * 1000)};
  setsockopt(ctl_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  *ok = send_frame(ctl_fd_, req) && recv_frame(ctl_fd_, &resp);
  if (!*ok) {
    resp = json{{"ok", false}, {"error", "sandbox control channel failed"}};
    if (pid_ > 0) kill(pid_, SIGKILL);
  }
  return resp;
}

ExecResult Sandbox::exec(const ExecRequest& req) {
  ExecResult r;
  const uint64_t seq0 = denied_count();
  const uint64_t oom0 = cgroup_counter("memory.events", "oom_kill");
  json q = {{"op", "exec"},       {"argv", req.argv},          {"env", req.env},
            {"stdin", req.stdin_data}, {"timeout_ms", req.timeout_ms}, {"cwd", req.cwd},
            {"max_output", req.max_output}};
  bool ok;
  json p = rpc(q, &ok);
  if (!ok || !p.value("ok", false)) {
    r.error = p.value("error", std::string("exec failed"));
  } else {
    r.exit_code = p.value("exit_code", -1);
    r.term_signal = p.value("term_signal", 0);
    r.timed_out = p.value("timed_out", false);
    r.truncated = p.value("truncated", false);
    r.wall_ms = p.value("wall_ms", 0.0);
    r.user_ms = p.value("user_ms", 0.0);
    r.sys_ms = p.value("sys_ms", 0.0);
    r.max_rss_kb = p.value("max_rss_kb", 0L);
    r.out = p.value("stdout", std::string());
    r.err = p.value("stderr", std::string());
  }
  r.oom_killed = cgroup_counter("memory.events", "oom_kill") > oom0;
  std::lock_guard<std::mutex> g(ev_mu_);
  for (const auto& e : events_)
    if (e.seq >= seq0) r.denied.push_back(e);
  return r;
}

bool Sandbox::write_file(const std::string& path, const std::string& data, unsigned mode, std::string* err) {
  bool ok;
  json p = rpc({{"op", "write_file"}, {"path", path}, {"data_b64", b64_encode(data)}, {"mode", mode}}, &ok);
  if (!ok || !p.value("ok", false)) { *err = p.value("error", std::string("write failed")); return false; }
  return true;
}

bool Sandbox::read_file(const std::string& path, std::string* data, std::string* err) {
  bool ok;
  json p = rpc({{"op", "read_file"}, {"path", path}}, &ok);
  if (!ok || !p.value("ok", false)) { *err = p.value("error", std::string("read failed")); return false; }
  return b64_decode(p.value("data_b64", std::string()), data);
}

bool Sandbox::snapshot(std::string* err) {
  bool ok;
  json p = rpc({{"op", "snapshot"}}, &ok);
  if (!ok || !p.value("ok", false)) { *err = p.value("error", std::string("snapshot failed")); return false; }
  return true;
}

bool Sandbox::restore(std::string* err) {
  bool ok;
  json p = rpc({{"op", "restore"}}, &ok);
  if (!ok || !p.value("ok", false)) { *err = p.value("error", std::string("restore failed")); return false; }
  return true;
}

std::vector<DeniedEvent> Sandbox::denied_all() {
  std::lock_guard<std::mutex> g(ev_mu_);
  return events_;
}

size_t Sandbox::denied_count() {
  std::lock_guard<std::mutex> g(ev_mu_);
  return events_.size();
}

json Sandbox::describe() const {
  return json{{"id", cfg_.id},
              {"spawn_ms", stats_.spawn_ms},
              {"cgroup", stats_.cgroup},
              {"cgroup_note", stats_.cgroup_note},
              {"limits", cfg_.limits}};
}

void Sandbox::supervise() {
  struct seccomp_notif_sizes sz;
  if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sz) != 0) return;
  std::vector<char> rbuf(sz.seccomp_notif), sbuf(sz.seccomp_notif_resp);
  while (!stop_) {
    struct pollfd pfd = {notif_fd_, POLLIN, 0};
    int pr = poll(&pfd, 1, 100);
    if (pr < 0 && errno == EINTR) continue;
    if (pr <= 0) continue;
    if (pfd.revents & (POLLHUP | POLLERR)) { if (!(pfd.revents & POLLIN)) return; }
    memset(rbuf.data(), 0, rbuf.size());
    auto* req = (struct seccomp_notif*)rbuf.data();
    if (ioctl(notif_fd_, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
      if (errno == EINTR || errno == ENOENT) continue;
      return;
    }
    DeniedEvent ev;
    ev.pid = (int)req->pid;
    ev.nr = req->data.nr;
    ev.t_unix = now_unix();
    ev.syscall = syscall_name(ev.nr);
    unsigned long long a[6];
    for (int i = 0; i < 6; i++) { ev.args[i] = req->data.args[i]; a[i] = req->data.args[i]; }
    ev.note = describe_denied(ev.nr, a);
    {
      std::lock_guard<std::mutex> g(ev_mu_);
      ev.seq = events_.size();
      events_.push_back(ev);
    }
    if (!cfg_.denied_log_path.empty()) {
      json j = ev;
      j["sandbox"] = cfg_.id;
      j["action"] = "denied";
      std::lock_guard<std::mutex> g(g_log_mu);
      std::ofstream f(cfg_.denied_log_path, std::ios::app);
      f << j.dump(-1, ' ', false, json::error_handler_t::replace) << "\n";
    }
    memset(sbuf.data(), 0, sbuf.size());
    auto* resp = (struct seccomp_notif_resp*)sbuf.data();
    resp->id = req->id;
    resp->error = -EPERM;
    resp->val = 0;
    ioctl(notif_fd_, SECCOMP_IOCTL_NOTIF_SEND, resp);
  }
}

} // namespace proctor
