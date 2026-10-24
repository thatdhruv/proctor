// proctord: warm-pool daemon. JSON-lines protocol over a Unix socket.
//
// Request : {"op": "...", ...}\n      Response: {"ok": bool, ...}\n
// Ops     : ping acquire exec write_file read_file snapshot restore release
//           denied stats shutdown
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

#include "proctor/sandbox.hpp"

using namespace proctor;

namespace {

double mono_ms() {
  using namespace std::chrono;
  return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

// ---- tiny Prometheus histogram -------------------------------------------------
struct Histogram {
  std::vector<double> bounds = {0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 5000};
  std::vector<uint64_t> counts = std::vector<uint64_t>(16, 0);
  double sum = 0;
  uint64_t n = 0;
  std::mutex mu;
  void observe(double ms) {
    std::lock_guard<std::mutex> g(mu);
    size_t i = 0;
    while (i < bounds.size() && ms > bounds[i]) i++;
    counts[i]++;
    sum += ms;
    n++;
  }
  std::string render(const std::string& name, const std::string& labels) {
    std::lock_guard<std::mutex> g(mu);
    std::ostringstream o;
    uint64_t cum = 0;
    std::string sep = labels.empty() ? "" : ",";
    for (size_t i = 0; i < bounds.size(); i++) {
      cum += counts[i];
      o << name << "_bucket{" << labels << sep << "le=\"" << bounds[i] / 1000.0 << "\"} " << cum << "\n";
    }
    cum += counts[bounds.size()];
    o << name << "_bucket{" << labels << sep << "le=\"+Inf\"} " << cum << "\n";
    o << name << "_sum{" << labels << "} " << sum / 1000.0 << "\n";
    o << name << "_count{" << labels << "} " << n << "\n";
    return o.str();
  }
};

struct Metrics {
  Histogram startup_cold, startup_warm, exec, restore;
  std::atomic<uint64_t> execs{0}, denied{0}, acquires_warm{0}, acquires_cold{0}, sandboxes_destroyed{0};
  std::mutex mu;
  std::map<std::string, uint64_t> denied_by_syscall;
};

Metrics g_m;
SandboxConfig g_cfg;
size_t g_pool_target = 4;
std::mutex g_mu;
std::condition_variable g_cv;
std::deque<std::shared_ptr<Sandbox>> g_pool;
std::map<std::string, std::shared_ptr<Sandbox>> g_active;
std::atomic<bool> g_stop{false};

void refill_loop() {
  while (!g_stop) {
    bool need;
    {
      std::unique_lock<std::mutex> lk(g_mu);
      g_cv.wait_for(lk, std::chrono::milliseconds(200),
                    [] { return g_stop.load() || g_pool.size() < g_pool_target; });
      need = !g_stop && g_pool.size() < g_pool_target;
    }
    if (!need) continue;
    std::string err;
    auto sb = Sandbox::create(g_cfg, &err);
    if (!sb) {
      fprintf(stderr, "pool refill failed: %s\n", err.c_str());
      std::this_thread::sleep_for(std::chrono::seconds(1));
      continue;
    }
    g_m.startup_cold.observe(sb->stats().spawn_ms);
    std::lock_guard<std::mutex> lk(g_mu);
    g_pool.push_back(std::move(sb));
  }
}

std::shared_ptr<Sandbox> find(const std::string& id) {
  std::lock_guard<std::mutex> lk(g_mu);
  auto it = g_active.find(id);
  return it == g_active.end() ? nullptr : it->second;
}

void count_denied(Sandbox* sb, size_t before) {
  auto ev = sb->denied_all();
  for (size_t i = before; i < ev.size(); i++) {
    g_m.denied++;
    std::lock_guard<std::mutex> g(g_m.mu);
    g_m.denied_by_syscall[ev[i].syscall]++;
  }
}

json handle(const json& q, std::vector<std::string>* mine) {
  const std::string op = q.value("op", std::string());
  if (op == "ping") return {{"ok", true}};

  if (op == "acquire") {
    const double t0 = mono_ms();
    std::shared_ptr<Sandbox> sb;
    bool warm = false;
    const bool custom = q.contains("limits") || q.contains("binds");
    if (!q.value("cold", false) && !custom) {
      std::lock_guard<std::mutex> lk(g_mu);
      if (!g_pool.empty()) {
        sb = std::move(g_pool.front());
        g_pool.pop_front();
        warm = true;
      }
    }
    g_cv.notify_all();
    if (!sb) {
      SandboxConfig c = g_cfg;
      if (q.contains("limits")) c.limits = q["limits"].get<Limits>();
      if (q.contains("binds")) c.binds = q["binds"].get<std::vector<Bind>>();
      std::string err;
      sb = Sandbox::create(c, &err);
      if (!sb) return {{"ok", false}, {"error", err}};
      g_m.startup_cold.observe(sb->stats().spawn_ms);
    }
    const double ms = mono_ms() - t0;
    if (warm) { g_m.acquires_warm++; g_m.startup_warm.observe(ms); }
    else g_m.acquires_cold++;
    std::string id = sb->id();
    json d = sb->describe();
    {
      std::lock_guard<std::mutex> lk(g_mu);
      g_active[id] = sb;
    }
    mine->push_back(id);
    return {{"ok", true}, {"sandbox_id", id}, {"source", warm ? "warm" : "cold"},
            {"acquire_ms", ms}, {"sandbox", d}};
  }

  if (op == "stats") {
    std::lock_guard<std::mutex> lk(g_mu);
    return {{"ok", true}, {"pool", g_pool.size()}, {"pool_target", g_pool_target},
            {"active", g_active.size()}, {"execs", g_m.execs.load()}, {"denied", g_m.denied.load()}};
  }

  if (op == "shutdown") { g_stop = true; g_cv.notify_all(); return {{"ok", true}}; }

  auto sb = find(q.value("sandbox_id", std::string()));
  if (!sb) return {{"ok", false}, {"error", "unknown sandbox_id"}};

  if (op == "exec") {
    ExecRequest r;
    try { r = q.get<ExecRequest>(); } catch (...) { return {{"ok", false}, {"error", "bad request"}}; }
    size_t before = sb->denied_count();
    ExecResult res = sb->exec(r);
    g_m.execs++;
    g_m.exec.observe(res.wall_ms);
    count_denied(sb.get(), before);
    json j = res;
    j["ok"] = true;
    return j;
  }
  std::string err;
  if (op == "write_file") {
    std::string data;
    if (!b64_decode(q.value("data_b64", std::string()), &data)) return {{"ok", false}, {"error", "bad base64"}};
    if (!sb->write_file(q.value("path", std::string()), data, q.value("mode", 0644u), &err)) return {{"ok", false}, {"error", err}};
    return {{"ok", true}};
  }
  if (op == "read_file") {
    std::string data;
    if (!sb->read_file(q.value("path", std::string()), &data, &err)) return {{"ok", false}, {"error", err}};
    return {{"ok", true}, {"data_b64", b64_encode(data)}};
  }
  if (op == "snapshot") {
    if (!sb->snapshot(&err)) return {{"ok", false}, {"error", err}};
    return {{"ok", true}};
  }
  if (op == "restore") {
    const double t0 = mono_ms();
    if (!sb->restore(&err)) return {{"ok", false}, {"error", err}};
    double ms = mono_ms() - t0;
    g_m.restore.observe(ms);
    return {{"ok", true}, {"restore_ms", ms}};
  }
  if (op == "denied") return {{"ok", true}, {"events", sb->denied_all()}};

  if (op == "release") {
    std::string id = sb->id();
    {
      std::lock_guard<std::mutex> lk(g_mu);
      g_active.erase(id);
    }
    mine->erase(std::remove(mine->begin(), mine->end(), id), mine->end());
    // A sandbox that tripped the filter is never recycled: destroy it, keep the log.
    bool reuse = q.value("reuse", true) && sb->denied_count() == 0 && sb->alive();
    bool recycled = false;
    if (reuse) {
      const double t0 = mono_ms();
      std::string e2;
      if (sb->restore(&e2)) {
        g_m.restore.observe(mono_ms() - t0);
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_pool.size() < g_pool_target) { g_pool.push_back(sb); recycled = true; }
      }
    }
    if (!recycled) g_m.sandboxes_destroyed++;
    return {{"ok", true}, {"recycled", recycled}};
  }
  return {{"ok", false}, {"error", "unknown op"}};
}

void serve_client(int fd) {
  std::vector<std::string> mine;
  std::string buf;
  char tmp[65536];
  for (;;) {
    ssize_t n = read(fd, tmp, sizeof tmp);
    if (n <= 0) break;
    buf.append(tmp, (size_t)n);
    size_t pos;
    while ((pos = buf.find('\n')) != std::string::npos) {
      std::string line = buf.substr(0, pos);
      buf.erase(0, pos + 1);
      json q = json::parse(line, nullptr, false);
      json r = q.is_discarded() ? json{{"ok", false}, {"error", "bad json"}} : handle(q, &mine);
      std::string out = r.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
      size_t off = 0;
      while (off < out.size()) {
        ssize_t w = write(fd, out.data() + off, out.size() - off);
        if (w <= 0) { close(fd); goto done; }
        off += (size_t)w;
      }
    }
  }
  close(fd);
done:
  for (auto& id : mine) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_active.erase(id);
  }
}

std::string render_metrics() {
  std::ostringstream o;
  o << "# TYPE proctor_sandbox_startup_seconds histogram\n";
  o << g_m.startup_cold.render("proctor_sandbox_startup_seconds", "kind=\"cold\"");
  o << g_m.startup_warm.render("proctor_sandbox_startup_seconds", "kind=\"warm\"");
  o << "# TYPE proctor_exec_seconds histogram\n" << g_m.exec.render("proctor_exec_seconds", "");
  o << "# TYPE proctor_restore_seconds histogram\n" << g_m.restore.render("proctor_restore_seconds", "");
  o << "# TYPE proctor_execs_total counter\nproctor_execs_total " << g_m.execs.load() << "\n";
  o << "# TYPE proctor_acquires_total counter\n";
  o << "proctor_acquires_total{source=\"warm\"} " << g_m.acquires_warm.load() << "\n";
  o << "proctor_acquires_total{source=\"cold\"} " << g_m.acquires_cold.load() << "\n";
  o << "# TYPE proctor_denied_syscalls_total counter\n";
  {
    std::lock_guard<std::mutex> g(g_m.mu);
    for (auto& kv : g_m.denied_by_syscall)
      o << "proctor_denied_syscalls_total{syscall=\"" << kv.first << "\"} " << kv.second << "\n";
  }
  {
    std::lock_guard<std::mutex> lk(g_mu);
    o << "# TYPE proctor_pool_size gauge\nproctor_pool_size " << g_pool.size() << "\n";
    o << "proctor_active_sandboxes " << g_active.size() << "\n";
  }
  return o.str();
}

void metrics_server(int port) {
  int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  sockaddr_in a = {};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  a.sin_port = htons((uint16_t)port);
  if (bind(s, (sockaddr*)&a, sizeof a) != 0 || listen(s, 16) != 0) {
    fprintf(stderr, "metrics bind :%d failed: %s\n", port, strerror(errno));
    return;
  }
  while (!g_stop) {
    int c = accept4(s, nullptr, nullptr, SOCK_CLOEXEC);
    if (c < 0) continue;
    char junk[1024];
    (void)!read(c, junk, sizeof junk);
    std::string body = render_metrics();
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: " +
                       std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    (void)!write(c, resp.data(), resp.size());
    close(c);
  }
}

} // namespace

int main(int argc, char** argv) {
  std::string sock = "/tmp/proctord.sock";
  int metrics_port = 0;
  char self[4096];
  ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
  std::string dir = ".";
  if (n > 0) { self[n] = 0; dir = std::string(self).substr(0, std::string(self).rfind('/')); }
  g_cfg.init_path = dir + "/proctor-init";
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--socket") sock = next();
    else if (a == "--pool") g_pool_target = (size_t)atoi(next());
    else if (a == "--init") g_cfg.init_path = next();
    else if (a == "--metrics-port") metrics_port = atoi(next());
    else if (a == "--denied-log") g_cfg.denied_log_path = next();
    else if (a == "--no-cgroup") g_cfg.cgroup_base = "none";
    else if (a == "--cgroup-base") g_cfg.cgroup_base = next();
    else if (a == "--mem-mb") g_cfg.limits.memory_bytes = (uint64_t)atoll(next()) << 20;
    else if (a == "--pids") g_cfg.limits.pids_max = (uint32_t)atoi(next());
    else { fprintf(stderr, "unknown flag %s\n", a.c_str()); return 2; }
  }
  signal(SIGPIPE, SIG_IGN);
  if (g_cfg.cgroup_base.empty()) {
    std::string note;
    std::string base = detect_cgroup_base(&note);
    g_cfg.cgroup_base = base.empty() ? "none" : base;
    fprintf(stderr, "proctord: cgroups %s%s\n", base.empty() ? "unavailable (rlimit fallback): " : "at ", base.empty() ? note.c_str() : base.c_str());
  }

  unlink(sock.c_str());
  int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, sock.c_str(), sizeof addr.sun_path - 1);
  if (bind(ls, (sockaddr*)&addr, sizeof addr) != 0 || listen(ls, 64) != 0) {
    fprintf(stderr, "bind %s: %s\n", sock.c_str(), strerror(errno));
    return 1;
  }
  chmod(sock.c_str(), 0600);

  std::thread refill(refill_loop);
  if (metrics_port) std::thread(metrics_server, metrics_port).detach();
  fprintf(stderr, "proctord: listening on %s, pool=%zu\n", sock.c_str(), g_pool_target);
  while (!g_stop) {
    struct timeval tv = {0, 200000};
    setsockopt(ls, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int c = accept4(ls, nullptr, nullptr, SOCK_CLOEXEC);
    if (c < 0) continue;
    std::thread(serve_client, c).detach();
  }
  g_cv.notify_all();
  refill.join();
  unlink(sock.c_str());
  { std::lock_guard<std::mutex> lk(g_mu); g_pool.clear(); g_active.clear(); }
  return 0;
}
