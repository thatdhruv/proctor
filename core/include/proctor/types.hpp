// Shared value types for the Proctor execution core.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "json.hpp"

namespace proctor {

using json = nlohmann::json;

struct Limits {
  uint64_t memory_bytes = 512ull << 20;    // cgroup memory.max (RLIMIT_AS when degraded)
  uint32_t pids_max = 128;                 // cgroup pids.max
  uint32_t cpu_percent = 100;              // cgroup cpu.max, % of one core
  uint64_t workspace_bytes = 128ull << 20; // size of the /workspace tmpfs
  uint64_t fsize_bytes = 64ull << 20;      // RLIMIT_FSIZE
  uint32_t nofile = 256;                   // RLIMIT_NOFILE
};

struct Bind {
  std::string src; // host path
  std::string dst; // sandbox path, must be under /mnt or /run
  bool ro = true;
};

struct SandboxConfig {
  Limits limits;
  std::vector<Bind> binds;
  bool seccomp = true;         // debug only: disabling it is used to test the other layers in isolation
  std::string hostname = "proctor";
  std::string init_path;       // path to the proctor-init binary
  std::string cgroup_base;     // "" = autodetect; "none" = disable cgroups
  std::string denied_log_path; // "" = keep in memory only; else append JSONL
  std::string id;              // set by the host, used in logs
};

struct DeniedEvent {
  uint64_t seq = 0;
  double t_unix = 0;
  int pid = 0;
  int nr = 0;
  std::string syscall;
  std::string note;
  uint64_t args[6] = {0, 0, 0, 0, 0, 0};
};

struct ExecRequest {
  std::vector<std::string> argv;
  std::map<std::string, std::string> env;
  std::string stdin_data;
  uint32_t timeout_ms = 10000;
  std::string cwd = "/workspace";
  uint64_t max_output = 1 << 20; // per stream
};

struct ExecResult {
  int exit_code = -1;
  int term_signal = 0;
  bool timed_out = false;
  bool oom_killed = false;
  bool truncated = false;
  double wall_ms = 0;
  double user_ms = 0;
  double sys_ms = 0;
  long max_rss_kb = 0;
  std::string out;
  std::string err;
  std::string error; // launcher-level failure (not the command's own)
  std::vector<DeniedEvent> denied;
};

void to_json(json& j, const DeniedEvent& e);
void to_json(json& j, const ExecResult& r);
void from_json(const json& j, ExecRequest& r);
void from_json(const json& j, Limits& l);
void from_json(const json& j, Bind& b);
void to_json(json& j, const Bind& b);
void to_json(json& j, const Limits& l);

// Wire helpers (length-prefixed JSON frames over a stream socket).
bool send_frame(int fd, const json& j, int pass_fd = -1);
bool recv_frame(int fd, json* out, int* recv_fd = nullptr);

std::string b64_encode(const std::string& in);
bool b64_decode(const std::string& in, std::string* out);
double now_unix();

} // namespace proctor
