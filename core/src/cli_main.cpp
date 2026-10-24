// proctor-run: run one command in a fresh sandbox and print the result as JSON.
//
//   proctor-run [--timeout-ms N] [--mem-mb N] [--pids N] [--no-cgroup]
//               [--debug-no-seccomp] [--denied-log FILE] [--stdin-file FILE] -- CMD ARGS...
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include "proctor/sandbox.hpp"

using namespace proctor;

std::string self_dir() {
  char buf[4096];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
  if (n <= 0) return ".";
  buf[n] = 0;
  std::string s = buf;
  return s.substr(0, s.rfind('/'));
}

int main(int argc, char** argv) {
  SandboxConfig cfg;
  ExecRequest req;
  const char* env_init = getenv("PROCTOR_INIT");
  cfg.init_path = env_init ? env_init : self_dir() + "/proctor-init";
  int i = 1;
  for (; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--") { i++; break; }
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--timeout-ms") req.timeout_ms = (uint32_t)atoi(next());
    else if (a == "--mem-mb") cfg.limits.memory_bytes = (uint64_t)atoll(next()) << 20;
    else if (a == "--pids") cfg.limits.pids_max = (uint32_t)atoi(next());
    else if (a == "--no-cgroup") cfg.cgroup_base = "none";
    else if (a == "--debug-no-seccomp") cfg.seccomp = false;
    else if (a == "--denied-log") cfg.denied_log_path = next();
    else if (a == "--stdin-file") { std::ifstream f(next()); std::stringstream ss; ss << f.rdbuf(); req.stdin_data = ss.str(); }
    else { fprintf(stderr, "unknown flag %s\n", a.c_str()); return 2; }
  }
  for (; i < argc; i++) req.argv.push_back(argv[i]);
  if (req.argv.empty()) { fprintf(stderr, "usage: proctor-run [flags] -- CMD...\n"); return 2; }

  std::string err;
  auto sb = Sandbox::create(cfg, &err);
  if (!sb) {
    json j = {{"error", err}};
    std::cout << j.dump() << std::endl;
    return 1;
  }
  ExecResult r = sb->exec(req);
  json j = r;
  j["sandbox"] = sb->describe();
  std::cout << j.dump(-1, ' ', false, json::error_handler_t::replace) << std::endl;
  return r.error.empty() ? 0 : 1;
}
