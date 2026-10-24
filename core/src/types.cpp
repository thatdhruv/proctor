#include "proctor/types.hpp"

#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>

namespace proctor {

double now_unix() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}

static std::string safe_dump(const json& j) {
  return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

void to_json(json& j, const DeniedEvent& e) {
  j = json{{"seq", e.seq},       {"t", e.t_unix}, {"pid", e.pid},
           {"nr", e.nr},         {"syscall", e.syscall},
           {"note", e.note},
           {"args", {e.args[0], e.args[1], e.args[2], e.args[3], e.args[4], e.args[5]}}};
}

void to_json(json& j, const ExecResult& r) {
  j = json{{"exit_code", r.exit_code}, {"term_signal", r.term_signal},
           {"timed_out", r.timed_out}, {"oom_killed", r.oom_killed},
           {"truncated", r.truncated}, {"wall_ms", r.wall_ms},
           {"user_ms", r.user_ms},     {"sys_ms", r.sys_ms},
           {"max_rss_kb", r.max_rss_kb}, {"stdout", r.out},
           {"stderr", r.err},          {"error", r.error},
           {"denied", r.denied}};
}

void from_json(const json& j, Limits& l) {
  if (j.contains("memory_bytes")) l.memory_bytes = j["memory_bytes"];
  if (j.contains("pids_max")) l.pids_max = j["pids_max"];
  if (j.contains("cpu_percent")) l.cpu_percent = j["cpu_percent"];
  if (j.contains("workspace_bytes")) l.workspace_bytes = j["workspace_bytes"];
  if (j.contains("fsize_bytes")) l.fsize_bytes = j["fsize_bytes"];
  if (j.contains("nofile")) l.nofile = j["nofile"];
}

void to_json(json& j, const Limits& l) {
  j = json{{"memory_bytes", l.memory_bytes}, {"pids_max", l.pids_max},
           {"cpu_percent", l.cpu_percent},   {"workspace_bytes", l.workspace_bytes},
           {"fsize_bytes", l.fsize_bytes},   {"nofile", l.nofile}};
}

void from_json(const json& j, Bind& b) {
  b.src = j.at("src").get<std::string>();
  b.dst = j.at("dst").get<std::string>();
  b.ro = j.value("ro", true);
}

void to_json(json& j, const Bind& b) { j = json{{"src", b.src}, {"dst", b.dst}, {"ro", b.ro}}; }

void from_json(const json& j, ExecRequest& r) {
  r.argv = j.at("argv").get<std::vector<std::string>>();
  if (j.contains("env")) r.env = j["env"].get<std::map<std::string, std::string>>();
  if (j.contains("stdin")) r.stdin_data = j["stdin"].get<std::string>();
  if (j.contains("timeout_ms")) r.timeout_ms = j["timeout_ms"];
  if (j.contains("cwd")) r.cwd = j["cwd"].get<std::string>();
  if (j.contains("max_output")) r.max_output = j["max_output"];
}

static bool write_all(int fd, const char* p, size_t n) {
  while (n) {
    ssize_t w = ::write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += w;
    n -= (size_t)w;
  }
  return true;
}

static bool read_all(int fd, char* p, size_t n) {
  while (n) {
    ssize_t r = ::read(fd, p, n);
    if (r < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (r == 0) return false;
    p += r;
    n -= (size_t)r;
  }
  return true;
}

bool send_frame(int fd, const json& j, int pass_fd) {
  std::string body = safe_dump(j);
  uint32_t len = (uint32_t)body.size();
  if (pass_fd >= 0) {
    // Header byte carries the fd via SCM_RIGHTS so the receiver can pair it.
    char hdr[4];
    memcpy(hdr, &len, 4);
    struct iovec iov = {hdr, 4};
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof cbuf);
    struct msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;
    struct cmsghdr* c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &pass_fd, sizeof(int));
    if (sendmsg(fd, &msg, 0) != 4) return false;
    return write_all(fd, body.data(), body.size());
  }
  return write_all(fd, (const char*)&len, 4) && write_all(fd, body.data(), body.size());
}

bool recv_frame(int fd, json* out, int* recv_fd) {
  char hdr[4];
  struct iovec iov = {hdr, 4};
  char cbuf[CMSG_SPACE(sizeof(int))];
  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof cbuf;
  ssize_t n;
  do {
    n = recvmsg(fd, &msg, MSG_WAITALL);
  } while (n < 0 && errno == EINTR);
  if (n != 4) return false;
  if (recv_fd) {
    *recv_fd = -1;
    for (struct cmsghdr* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
      if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
        memcpy(recv_fd, CMSG_DATA(c), sizeof(int));
  }
  uint32_t len;
  memcpy(&len, hdr, 4);
  if (len > (256u << 20)) return false;
  std::string body(len, '\0');
  if (len && !read_all(fd, &body[0], len)) return false;
  *out = json::parse(body, nullptr, false);
  return !out->is_discarded();
}

static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(const std::string& in) {
  std::string o;
  o.reserve((in.size() + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 2 < in.size(); i += 3) {
    uint32_t v = ((uint8_t)in[i] << 16) | ((uint8_t)in[i + 1] << 8) | (uint8_t)in[i + 2];
    o += B64[v >> 18]; o += B64[(v >> 12) & 63]; o += B64[(v >> 6) & 63]; o += B64[v & 63];
  }
  if (i + 1 == in.size()) {
    uint32_t v = (uint8_t)in[i] << 16;
    o += B64[v >> 18]; o += B64[(v >> 12) & 63]; o += "==";
  } else if (i + 2 == in.size()) {
    uint32_t v = ((uint8_t)in[i] << 16) | ((uint8_t)in[i + 1] << 8);
    o += B64[v >> 18]; o += B64[(v >> 12) & 63]; o += B64[(v >> 6) & 63]; o += '=';
  }
  return o;
}

bool b64_decode(const std::string& in, std::string* out) {
  int T[256];
  for (int& t : T) t = -1;
  for (int i = 0; i < 64; i++) T[(uint8_t)B64[i]] = i;
  out->clear();
  uint32_t v = 0;
  int bits = 0;
  for (unsigned char c : in) {
    if (c == '=') break;
    if (T[c] < 0) return false;
    v = (v << 6) | (uint32_t)T[c];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      *out += (char)((v >> bits) & 0xFF);
    }
  }
  return true;
}

} // namespace proctor
