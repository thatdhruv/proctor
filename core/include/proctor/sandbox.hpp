// Host-side handle to one sandbox (a pid-1 `proctor-init` inside fresh namespaces).
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "proctor/types.hpp"

namespace proctor {

struct SandboxStats {
  double spawn_ms = 0;       // clone -> ready
  bool cgroup = false;       // false => rlimit-only "degraded" mode
  std::string cgroup_path;
  std::string cgroup_note;   // why cgroups are unavailable, if so
};

class Sandbox {
 public:
  // Spawns a new sandbox. On failure returns nullptr and fills *err.
  static std::unique_ptr<Sandbox> create(const SandboxConfig& cfg, std::string* err);
  ~Sandbox();
  Sandbox(const Sandbox&) = delete;
  Sandbox& operator=(const Sandbox&) = delete;

  ExecResult exec(const ExecRequest& req);
  bool write_file(const std::string& path, const std::string& data, unsigned mode, std::string* err);
  bool read_file(const std::string& path, std::string* data, std::string* err);
  bool snapshot(std::string* err);        // capture /workspace
  bool restore(std::string* err);         // reset /workspace to the snapshot + kill stragglers
  bool alive();

  std::vector<DeniedEvent> denied_all();
  size_t denied_count();
  const std::string& id() const { return cfg_.id; }
  const SandboxStats& stats() const { return stats_; }
  json describe() const;

 private:
  Sandbox() = default;
  json rpc(const json& req, bool* ok);
  void supervise();
  uint64_t cgroup_counter(const char* file, const char* key);

  SandboxConfig cfg_;
  SandboxStats stats_;
  int ctl_fd_ = -1;
  int notif_fd_ = -1;
  int pid_ = -1;
  std::mutex rpc_mu_;
  std::mutex ev_mu_;
  std::vector<DeniedEvent> events_;
  std::atomic<bool> stop_{false};
  std::thread sup_;
};

// Process-wide helpers.
std::string detect_cgroup_base(std::string* note);

} // namespace proctor
