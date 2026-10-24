// proctor-init: PID 1 inside a sandbox.
//
// Lifecycle: receive "setup" -> build a minimal root filesystem -> drop all
// capabilities -> install the seccomp filter -> report ready (passing the
// seccomp notification fd to the host) -> serve exec / file / snapshot RPCs.
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "proctor/seccomp_filter.hpp"
#include "proctor/types.hpp"

using namespace proctor;

namespace {

inline void ignore(int) {}

double mono_ms() {
  using namespace std::chrono;
  return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

bool g_degraded = false;
Limits g_limits;
int g_sigfd = -1;

// ---------------------------------------------------------------- filesystem

bool mkdir_p(const std::string& path, mode_t mode = 0755) {
  std::string cur;
  size_t i = 0;
  while (i <= path.size()) {
    size_t j = path.find('/', i);
    if (j == std::string::npos) j = path.size();
    cur = path.substr(0, j);
    if (!cur.empty() && mkdir(cur.c_str(), mode) != 0 && errno != EEXIST) return false;
    i = j + 1;
  }
  return true;
}

bool touch(const std::string& path) {
  int fd = open(path.c_str(), O_WRONLY | O_CREAT, 0644);
  if (fd < 0) return false;
  close(fd);
  return true;
}

unsigned long preserved_flags(const char* src) {
  struct statvfs sv;
  if (statvfs(src, &sv) != 0) return 0;
  return sv.f_flag & (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_NODIRATIME | MS_RELATIME);
}

bool bind_one_ro(const std::string& src, const std::string& dst, bool is_dir, std::string* err) {
  if (is_dir ? !mkdir_p(dst) : !touch(dst)) { *err = "create " + dst; return false; }
  if (mount(src.c_str(), dst.c_str(), nullptr, MS_BIND, nullptr) != 0) {
    *err = "bind " + src + ": " + strerror(errno);
    return false;
  }
  unsigned long fl = MS_BIND | MS_REMOUNT | MS_RDONLY | preserved_flags(src.c_str());
  if (mount(nullptr, dst.c_str(), nullptr, fl, nullptr) != 0) {
    *err = "remount ro " + dst + ": " + strerror(errno);
    return false;
  }
  return true;
}

// Read-only bind of a directory tree. The kernel refuses a plain bind of a tree
// that contains other mounts (e.g. WSL's /usr/lib/wsl/*) from inside a user
// namespace, so fall back to binding each child and skipping nested mount points.
bool bind_tree_ro(const std::string& src, const std::string& dst, std::string* err) {
  std::string first_err;
  if (bind_one_ro(src, dst, true, &first_err)) return true;
  struct stat self;
  if (lstat(src.c_str(), &self) != 0) { *err = first_err; return false; }
  DIR* d = opendir(src.c_str());
  if (!d) { *err = first_err; return false; }
  bool ok = true;
  while (struct dirent* e = readdir(d)) {
    std::string name = e->d_name;
    if (name == "." || name == "..") continue;
    std::string s = src + "/" + name, t = dst + "/" + name;
    struct stat st;
    if (lstat(s.c_str(), &st) != 0) continue;
    if (S_ISLNK(st.st_mode)) {
      char buf[4096];
      ssize_t n = readlink(s.c_str(), buf, sizeof buf - 1);
      if (n > 0) { buf[n] = 0; ignore(symlink(buf, t.c_str())); }
    } else if (S_ISDIR(st.st_mode)) {
      if (st.st_dev != self.st_dev) continue; // nested mount point: not exposed
      if (!bind_tree_ro(s, t, err)) { ok = false; break; }
    } else if (S_ISREG(st.st_mode)) {
      if (!bind_one_ro(s, t, false, err)) { ok = false; break; }
    }
  }
  closedir(d);
  return ok;
}

bool write_small(const std::string& path, const std::string& s) {
  std::ofstream f(path);
  f << s;
  return (bool)f;
}

bool setup_fs(const std::string& hostname, const std::vector<Bind>& binds, std::string* err) {
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) { *err = "make-private"; return false; }
  // Scratch tmpfs over /tmp (hides host /tmp, leaves nothing behind on the host).
  if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=8m,mode=0700") != 0) {
    *err = std::string("mount /tmp: ") + strerror(errno);
    return false;
  }
  const std::string nr = "/tmp/newroot";
  mkdir(nr.c_str(), 0755);
  if (mount("tmpfs", nr.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "size=16m,mode=0755") != 0) {
    *err = std::string("mount newroot: ") + strerror(errno);
    return false;
  }
  for (const char* d : {"usr", "etc", "proc", "dev", "tmp", "workspace"}) mkdir((nr + "/" + d).c_str(), 0755);

  // System directories: recreate merged-/usr symlinks, bind-mount real directories read-only.
  for (const char* d : {"/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"}) {
    struct stat st;
    if (lstat(d, &st) != 0) continue;
    if (S_ISLNK(st.st_mode)) {
      char target[256];
      ssize_t n = readlink(d, target, sizeof target - 1);
      if (n > 0) { target[n] = 0; symlink(target, (nr + d).c_str()); }
    } else if (S_ISDIR(st.st_mode)) {
      if (!bind_tree_ro(d, nr + d, err)) return false;
    }
  }

  // /etc: only what a typical toolchain needs, never the host's.
  write_small(nr + "/etc/passwd", "root:x:0:0:agent:/workspace:/bin/sh\n");
  write_small(nr + "/etc/group", "agent:x:1000:\n");
  write_small(nr + "/etc/hostname", hostname + "\n");
  write_small(nr + "/etc/hosts", "127.0.0.1 localhost\n");
  write_small(nr + "/etc/nsswitch.conf", "passwd: files\ngroup: files\nhosts: files\n");

  // /dev: tmpfs with bind-mounted safe device nodes.
  if (mount("tmpfs", (nr + "/dev").c_str(), "tmpfs", MS_NOSUID | MS_NOEXEC, "size=1m,mode=0755") != 0) {
    *err = std::string("mount /dev: ") + strerror(errno);
    return false;
  }
  for (const char* dev : {"null", "zero", "full", "random", "urandom"}) {
    std::string dst = nr + "/dev/" + dev;
    if (touch(dst)) mount((std::string("/dev/") + dev).c_str(), dst.c_str(), nullptr, MS_BIND, nullptr);
  }
  ignore(symlink("/proc/self/fd", (nr + "/dev/fd").c_str()));
  ignore(symlink("/proc/self/fd/0", (nr + "/dev/stdin").c_str()));
  ignore(symlink("/proc/self/fd/1", (nr + "/dev/stdout").c_str()));
  ignore(symlink("/proc/self/fd/2", (nr + "/dev/stderr").c_str()));
  mkdir((nr + "/dev/shm").c_str(), 01777);
  mount("tmpfs", (nr + "/dev/shm").c_str(), "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=16m,mode=1777");

  if (mount("proc", (nr + "/proc").c_str(), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
    *err = std::string("mount /proc: ") + strerror(errno);
    return false;
  }
  char opts[96];
  snprintf(opts, sizeof opts, "size=%llu,mode=0755", (unsigned long long)g_limits.workspace_bytes);
  if (mount("tmpfs", (nr + "/workspace").c_str(), "tmpfs", MS_NOSUID | MS_NODEV, opts) != 0) {
    *err = std::string("mount /workspace: ") + strerror(errno);
    return false;
  }
  if (mount("tmpfs", (nr + "/tmp").c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "size=64m,mode=1777") != 0) {
    *err = std::string("mount sandbox /tmp: ") + strerror(errno);
    return false;
  }

  for (const auto& b : binds) {
    if (b.dst.rfind("/mnt/", 0) != 0 && b.dst.rfind("/run/", 0) != 0) { *err = "bind dst must be under /mnt or /run"; return false; }
    if (b.dst.find("..") != std::string::npos) { *err = "bad bind dst"; return false; }
    std::string dst = nr + b.dst;
    if (!mkdir_p(dst)) { *err = "mkdir " + dst; return false; }
    if (mount(b.src.c_str(), dst.c_str(), nullptr, MS_BIND, nullptr) != 0) { *err = "bind " + b.src + ": " + strerror(errno); return false; }
    unsigned long fl = MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC | (b.ro ? MS_RDONLY : 0);
    if (mount(nullptr, dst.c_str(), nullptr, fl | (preserved_flags(b.src.c_str()) & ~MS_NOEXEC), nullptr) != 0) { *err = "remount bind " + b.dst + ": " + strerror(errno); return false; }
  }
  if (chdir(nr.c_str()) != 0) { *err = "chdir newroot"; return false; }
  if (syscall(SYS_pivot_root, ".", ".") != 0) { *err = std::string("pivot_root: ") + strerror(errno); return false; }
  if (umount2(".", MNT_DETACH) != 0) { *err = std::string("umount old root: ") + strerror(errno); return false; }
  if (chdir("/") != 0) { *err = "chdir /"; return false; }
  // The root itself becomes read-only; only /workspace, /tmp and /dev/shm are writable.
  if (mount(nullptr, "/", nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV, nullptr) != 0) {
    *err = std::string("remount / ro: ") + strerror(errno);
    return false;
  }
  ignore(sethostname(hostname.data(), hostname.size()));
  return true;
}

void drop_all_caps() {
  int last = 40;
  std::ifstream f("/proc/sys/kernel/cap_last_cap");
  if (f) f >> last;
  for (int c = 0; c <= last; c++) prctl(PR_CAPBSET_DROP, c, 0, 0, 0);
  struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct d[2];
  memset(d, 0, sizeof d);
  syscall(SYS_capset, &h, d);
  prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
}

// ----------------------------------------------------------------- snapshots

struct Entry {
  char type; // d f l
  std::string path;
  mode_t mode;
  std::string data;
};
std::vector<Entry> g_snapshot;
uint64_t g_snap_bytes = 0;
bool g_snap_overflow = false;
constexpr uint64_t kSnapCap = 256ull << 20;

int snap_cb(const char* path, const struct stat* st, int type, struct FTW* ftw) {
  if (ftw->level == 0) return 0;
  Entry e;
  e.path = path;
  e.mode = st->st_mode & 07777;
  if (type == FTW_D) {
    e.type = 'd';
  } else if (type == FTW_F) {
    e.type = 'f';
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    e.data.resize(st->st_size);
    size_t off = 0;
    while (off < e.data.size()) {
      ssize_t n = read(fd, &e.data[off], e.data.size() - off);
      if (n <= 0) break;
      off += (size_t)n;
    }
    e.data.resize(off);
    close(fd);
    g_snap_bytes += off;
  } else if (type == FTW_SL) {
    e.type = 'l';
    char buf[4096];
    ssize_t n = readlink(path, buf, sizeof buf);
    if (n < 0) return 0;
    e.data.assign(buf, (size_t)n);
  } else {
    return 0; // fifos, sockets, devices are not preserved
  }
  if (g_snap_bytes > kSnapCap) { g_snap_overflow = true; return 1; }
  g_snapshot.push_back(std::move(e));
  return 0;
}

int rm_cb(const char* path, const struct stat*, int type, struct FTW* ftw) {
  if (ftw->level == 0) return 0;
  if (type == FTW_DP || type == FTW_D) rmdir(path);
  else unlink(path);
  return 0;
}

bool do_snapshot(std::string* err) {
  g_snapshot.clear();
  g_snap_bytes = 0;
  g_snap_overflow = false;
  nftw("/workspace", snap_cb, 32, FTW_PHYS | FTW_MOUNT);
  if (g_snap_overflow) { *err = "workspace exceeds snapshot cap"; g_snapshot.clear(); return false; }
  return true;
}

void kill_stragglers() {
  kill(-1, SIGKILL);
  int st;
  while (waitpid(-1, &st, WNOHANG) > 0) {}
}

bool do_restore(std::string* err) {
  kill_stragglers();
  nftw("/workspace", rm_cb, 32, FTW_DEPTH | FTW_PHYS | FTW_MOUNT);
  for (const auto& e : g_snapshot) {
    if (e.type == 'd') {
      mkdir(e.path.c_str(), e.mode);
      chmod(e.path.c_str(), e.mode);
    } else if (e.type == 'f') {
      int fd = open(e.path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, e.mode);
      if (fd < 0) { *err = "restore " + e.path + ": " + strerror(errno); return false; }
      size_t off = 0;
      while (off < e.data.size()) {
        ssize_t n = write(fd, e.data.data() + off, e.data.size() - off);
        if (n <= 0) break;
        off += (size_t)n;
      }
      fchmod(fd, e.mode);
      close(fd);
    } else {
      ignore(symlink(e.data.c_str(), e.path.c_str()));
    }
  }
  return true;
}

// ------------------------------------------------------------------- file io

bool path_ok(const std::string& p) {
  if (p.rfind("/workspace/", 0) != 0 && p.rfind("/tmp/", 0) != 0) return false;
  size_t i = 0;
  while (i < p.size()) {
    size_t j = p.find('/', i);
    if (j == std::string::npos) j = p.size();
    if (p.compare(i, j - i, "..") == 0) return false;
    i = j + 1;
  }
  return true;
}

json do_write_file(const json& q) {
  std::string path = q.value("path", std::string());
  if (!path_ok(path)) return {{"ok", false}, {"error", "path must be under /workspace or /tmp"}};
  std::string data;
  if (!b64_decode(q.value("data_b64", std::string()), &data)) return {{"ok", false}, {"error", "bad base64"}};
  mkdir_p(path.substr(0, path.rfind('/')));
  unsigned mode = q.value("mode", 0644u);
  int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode);
  if (fd < 0) return {{"ok", false}, {"error", std::string("open: ") + strerror(errno)}};
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = write(fd, data.data() + off, data.size() - off);
    if (n <= 0) { close(fd); return {{"ok", false}, {"error", std::string("write: ") + strerror(errno)}}; }
    off += (size_t)n;
  }
  fchmod(fd, mode);
  close(fd);
  return {{"ok", true}};
}

json do_read_file(const json& q) {
  std::string path = q.value("path", std::string());
  if (!path_ok(path)) return {{"ok", false}, {"error", "path must be under /workspace or /tmp"}};
  int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return {{"ok", false}, {"error", std::string("open: ") + strerror(errno)}};
  std::string data;
  char buf[65536];
  ssize_t n;
  while ((n = read(fd, buf, sizeof buf)) > 0) {
    data.append(buf, (size_t)n);
    if (data.size() > (64u << 20)) break;
  }
  close(fd);
  return {{"ok", true}, {"data_b64", b64_encode(data)}};
}

// ----------------------------------------------------------------------- exec

void set_nonblock(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

json do_exec(const json& q) {
  ExecRequest req;
  try { req = q.get<ExecRequest>(); } catch (...) { return {{"ok", false}, {"error", "bad exec request"}}; }
  if (req.argv.empty()) return {{"ok", false}, {"error", "empty argv"}};

  int in[2], out[2], er[2];
  if (pipe2(in, O_CLOEXEC) || pipe2(out, O_CLOEXEC) || pipe2(er, O_CLOEXEC))
    return {{"ok", false}, {"error", "pipe"}};

  std::map<std::string, std::string> env = {{"PATH", "/usr/local/bin:/usr/bin:/bin"}, {"HOME", "/workspace"},
                                            {"LANG", "C.UTF-8"}, {"TMPDIR", "/tmp"}, {"PYTHONDONTWRITEBYTECODE", "1"}};
  for (auto& kv : req.env) env[kv.first] = kv.second;
  std::vector<std::string> envs;
  for (auto& kv : env) envs.push_back(kv.first + "=" + kv.second);
  std::vector<char*> envp, argvp;
  for (auto& s : envs) envp.push_back((char*)s.c_str());
  envp.push_back(nullptr);
  for (auto& s : req.argv) argvp.push_back((char*)s.c_str());
  argvp.push_back(nullptr);

  const double t0 = mono_ms();
  pid_t pid = fork();
  if (pid < 0) return {{"ok", false}, {"error", "fork"}};
  if (pid == 0) {
    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, nullptr);
    setsid();
    dup2(in[0], 0); dup2(out[1], 1); dup2(er[1], 2);
    if (chdir(req.cwd.c_str()) != 0) { dprintf(2, "proctor: chdir %s: %s\n", req.cwd.c_str(), strerror(errno)); _exit(126); }
    struct rlimit rl;
    rl = {g_limits.fsize_bytes, g_limits.fsize_bytes}; setrlimit(RLIMIT_FSIZE, &rl);
    rl = {g_limits.nofile, g_limits.nofile};           setrlimit(RLIMIT_NOFILE, &rl);
    rl = {0, 0};                                        setrlimit(RLIMIT_CORE, &rl);
    if (g_degraded) {
      rl = {g_limits.memory_bytes, g_limits.memory_bytes}; setrlimit(RLIMIT_AS, &rl);
      rlim_t cpu = req.timeout_ms / 1000 + 2;
      rl = {cpu, cpu}; setrlimit(RLIMIT_CPU, &rl);
    }
    execvpe(argvp[0], argvp.data(), envp.data());
    dprintf(2, "proctor: exec %s: %s\n", argvp[0], strerror(errno));
    _exit(127);
  }
  close(in[0]); close(out[1]); close(er[1]);
  set_nonblock(in[1]); set_nonblock(out[0]); set_nonblock(er[0]);
  if (req.stdin_data.empty()) { close(in[1]); in[1] = -1; }

  std::string so, se;
  bool truncated = false, timed_out = false, done = false;
  int status = 0;
  struct rusage ru;
  memset(&ru, 0, sizeof ru);
  size_t in_off = 0;
  int ofd = out[0], efd = er[0];
  const double deadline = t0 + req.timeout_ms;

  auto drain = [&](int& fd, std::string& dst) {
    char buf[65536];
    for (;;) {
      ssize_t n = read(fd, buf, sizeof buf);
      if (n > 0) {
        if (dst.size() < req.max_output) {
          size_t take = std::min<size_t>((size_t)n, req.max_output - dst.size());
          dst.append(buf, take);
          if (take < (size_t)n) truncated = true;
        } else {
          truncated = true;
        }
      } else if (n == 0) { close(fd); fd = -1; return; }
      else { if (errno == EINTR) continue; return; }
    }
  };

  while (true) {
    struct pollfd p[4];
    int np = 0;
    p[np++] = {g_sigfd, POLLIN, 0};
    int io = np; p[np++] = {ofd, POLLIN, 0};
    int ie = np; p[np++] = {efd, POLLIN, 0};
    int ii = -1;
    if (in[1] >= 0) { ii = np; p[np++] = {in[1], POLLOUT, 0}; }
    if (ofd < 0) p[io].fd = -1;
    if (efd < 0) p[ie].fd = -1;
    double remain = deadline - mono_ms();
    if (!done && remain <= 0) {
      timed_out = true;
      kill(-pid, SIGKILL);
      kill(pid, SIGKILL);
      done = true;
      wait4(pid, &status, 0, &ru);
      break;
    }
    if (done && ofd < 0 && efd < 0) break;
    int to = done ? 50 : (int)(remain < 1 ? 1 : remain);
    if (poll(p, (nfds_t)np, to) < 0 && errno != EINTR) break;
    if (p[0].revents & POLLIN) {
      struct signalfd_siginfo si;
      while (read(g_sigfd, &si, sizeof si) > 0) {}
    }
    if (!done) {
      pid_t w = wait4(pid, &status, WNOHANG, &ru);
      if (w == pid) {
        done = true;
        // Nothing may outlive the command: kill every process left in the sandbox.
        kill(-1, SIGKILL);
      }
    }
    if (ofd >= 0 && (p[io].revents & (POLLIN | POLLHUP))) drain(ofd, so);
    if (efd >= 0 && (p[ie].revents & (POLLIN | POLLHUP))) drain(efd, se);
    if (ii >= 0 && in[1] >= 0 && (p[ii].revents & (POLLOUT | POLLERR | POLLHUP))) {
      ssize_t n = write(in[1], req.stdin_data.data() + in_off, req.stdin_data.size() - in_off);
      if (n > 0) in_off += (size_t)n;
      if (n < 0 && errno != EAGAIN && errno != EINTR) in_off = req.stdin_data.size();
      if (in_off >= req.stdin_data.size()) { close(in[1]); in[1] = -1; }
    }
    if (done && ((ofd < 0 && efd < 0) || mono_ms() > deadline + 2000)) break;
  }
  if (timed_out) { kill(-1, SIGKILL); }
  if (ofd >= 0) { drain(ofd, so); if (ofd >= 0) close(ofd); }
  if (efd >= 0) { drain(efd, se); if (efd >= 0) close(efd); }
  if (in[1] >= 0) close(in[1]);
  int st2;
  while (waitpid(-1, &st2, WNOHANG) > 0) {}

  json r = {{"ok", true},
            {"exit_code", WIFEXITED(status) ? WEXITSTATUS(status) : -1},
            {"term_signal", WIFSIGNALED(status) ? WTERMSIG(status) : 0},
            {"timed_out", timed_out},
            {"truncated", truncated},
            {"wall_ms", mono_ms() - t0},
            {"user_ms", ru.ru_utime.tv_sec * 1000.0 + ru.ru_utime.tv_usec / 1000.0},
            {"sys_ms", ru.ru_stime.tv_sec * 1000.0 + ru.ru_stime.tv_usec / 1000.0},
            {"max_rss_kb", ru.ru_maxrss},
            {"stdout", so},
            {"stderr", se}};
  return r;
}

} // namespace

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  const int ctl = atoi(argv[1]);

  json setup;
  if (!recv_frame(ctl, &setup) || setup.value("op", "") != "setup") return 3;
  g_limits = setup.value("limits", json::object()).get<Limits>();
  g_degraded = setup.value("degraded", true);

  std::string err;
  std::vector<Bind> binds;
  if (setup.contains("binds")) binds = setup["binds"].get<std::vector<Bind>>();
  bool ok = setup_fs(setup.value("hostname", std::string("proctor")), binds, &err);
  int nfd = -1;
  if (ok) {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0); // keep snapshots and control state unreadable via /proc/1/mem
    struct rlimit core = {0, 0};
    setrlimit(RLIMIT_CORE, &core);
    drop_all_caps();
    nfd = install_seccomp_filter();
    if (nfd < 0) { ok = false; err = std::string("seccomp: ") + strerror(errno); }
  }
  if (!ok) {
    send_frame(ctl, {{"ok", false}, {"error", err}});
    return 4;
  }

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  g_sigfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

  std::string serr;
  do_snapshot(&serr); // baseline: empty workspace
  if (!send_frame(ctl, {{"ok", true}}, nfd)) return 5;
  close(nfd);

  json q;
  while (recv_frame(ctl, &q)) {
    const std::string op = q.value("op", std::string());
    json resp;
    if (op == "exec") resp = do_exec(q);
    else if (op == "write_file") resp = do_write_file(q);
    else if (op == "read_file") resp = do_read_file(q);
    else if (op == "snapshot") { resp = do_snapshot(&serr) ? json{{"ok", true}} : json{{"ok", false}, {"error", serr}}; }
    else if (op == "restore") { resp = do_restore(&serr) ? json{{"ok", true}} : json{{"ok", false}, {"error", serr}}; }
    else if (op == "ping") resp = {{"ok", true}};
    else resp = {{"ok", false}, {"error", "unknown op"}};
    if (!send_frame(ctl, resp)) break;
  }
  return 0; // host closed the control channel -> exit, which tears down the pid namespace
}
