#pragma once

#include <boost/json.hpp>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <cstdint>

struct Wave37VerusJobSnapshot {
  std::string worker;
  std::string worker_redacted;
  std::string job_id;
  std::string version;
  std::string prevhash;
  std::string coinb1;
  std::string coinb2;
  std::string ntime;
  std::string nbits;
  std::string nonce;
  std::string solution;
  std::string target;
  std::string pool_nonce;
  std::string source;
  uint64_t sequence = 0;
  bool valid = false;
};

inline std::mutex &wave37VerusSnapshotMutex() {
  static std::mutex m;
  return m;
}

inline Wave37VerusJobSnapshot &wave37VerusSnapshot() {
  static Wave37VerusJobSnapshot s;
  return s;
}

inline std::string wave37RedactWorker(const std::string &w) {
  auto dot = w.find('.');
  if (dot == std::string::npos) return "R...redacted";
  return "R...redacted" + w.substr(dot);
}

inline std::string wave37ReadFile(const std::string &path) {
  std::ifstream in(path);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

inline std::string wave37JsonStringValue(const std::string &s, const std::string &key) {
  std::string needle = "\"" + key + "\"";
  size_t p = s.find(needle);
  if (p == std::string::npos) return "";
  p = s.find(':', p);
  if (p == std::string::npos) return "";
  p = s.find('"', p);
  if (p == std::string::npos) return "";
  size_t q = p + 1;
  while (q < s.size()) {
    if (s[q] == '"' && s[q - 1] != '\\') break;
    ++q;
  }
  if (q >= s.size()) return "";
  return s.substr(p + 1, q - p - 1);
}

inline Wave37VerusJobSnapshot wave37SnapshotFromFixtureFile(const std::string &path) {
  std::string s = wave37ReadFile(path);
  Wave37VerusJobSnapshot snap;
  snap.worker = wave37JsonStringValue(s, "worker");
  snap.worker_redacted = wave37RedactWorker(snap.worker);
  snap.job_id = wave37JsonStringValue(s, "job_id");
  snap.version = wave37JsonStringValue(s, "version");
  snap.prevhash = wave37JsonStringValue(s, "prevhash");
  snap.coinb1 = wave37JsonStringValue(s, "coinb1");
  snap.coinb2 = wave37JsonStringValue(s, "coinb2");
  snap.ntime = wave37JsonStringValue(s, "ntime");
  snap.nbits = wave37JsonStringValue(s, "nbits");
  snap.nonce = wave37JsonStringValue(s, "nonce");
  snap.solution = wave37JsonStringValue(s, "solution");
  snap.target = wave37JsonStringValue(s, "target");
  snap.pool_nonce = s.find("725fc83e") == std::string::npos ? "" : "725fc83e";
  snap.source = "fixture";
  snap.valid = !snap.job_id.empty() && !snap.ntime.empty() && !snap.solution.empty();
  return snap;
}

inline bool wave37SnapshotSubmitReady(const Wave37VerusJobSnapshot &s) {
  return !s.worker.empty() && s.job_id.size() == 7 && s.ntime.size() == 8 &&
         s.nonce.size() == 56 && s.solution.size() == 2694 &&
         (s.pool_nonce.empty() || s.solution.find(s.pool_nonce) != std::string::npos);
}

inline bool wave37SnapshotJobReady(const Wave37VerusJobSnapshot &s) {
  return s.valid && !s.job_id.empty() && s.ntime.size() == 8 && !s.solution.empty();
}

inline bool wave41SnapshotLiveScanReady(const Wave37VerusJobSnapshot &s) {
  return wave37SnapshotJobReady(s) &&
         s.version.size() == 8 &&
         s.prevhash.size() == 64 &&
         s.coinb1.size() == 64 &&
         s.coinb2.size() == 64 &&
         s.nbits.size() == 8 &&
         !s.target.empty() &&
         !s.pool_nonce.empty();
}

inline void wave37StoreSnapshot(const Wave37VerusJobSnapshot &snap) {
  std::lock_guard<std::mutex> lock(wave37VerusSnapshotMutex());
  Wave37VerusJobSnapshot next = snap;
  next.sequence = wave37VerusSnapshot().sequence + 1;
  wave37VerusSnapshot() = next;
}

inline Wave37VerusJobSnapshot wave37CopySnapshot() {
  std::lock_guard<std::mutex> lock(wave37VerusSnapshotMutex());
  return wave37VerusSnapshot();
}

inline boost::json::object wave37SubmitDryrunObject(const Wave37VerusJobSnapshot &s) {
  boost::json::object out;
  out["id"] = 7;
  out["method"] = "mining.submit";
  out["params"] = boost::json::array({wave37RedactWorker(s.worker), s.job_id, s.ntime, s.nonce, "<solution_hex_len_" + std::to_string(s.solution.size()) + ">"});
  return out;
}

inline void wave37WriteSnapshotJsonl(const std::string &path, const Wave37VerusJobSnapshot &s, const std::string &event) {
  if (path.empty()) return;
  std::ofstream out(path, std::ios::app);
  out << "{\"event\":\"" << event << "\",\"source\":\"" << s.source << "\",\"job_id\":\"" << s.job_id
      << "\",\"ntime\":\"" << s.ntime << "\",\"solution_len\":" << s.solution.size()
      << ",\"version_len\":" << s.version.size()
      << ",\"prevhash_len\":" << s.prevhash.size()
      << ",\"coinb1_len\":" << s.coinb1.size()
      << ",\"coinb2_len\":" << s.coinb2.size()
      << ",\"nbits_len\":" << s.nbits.size()
      << ",\"pool_nonce_len\":" << s.pool_nonce.size()
      << ",\"sequence\":" << s.sequence
      << ",\"target_len\":" << s.target.size() << ",\"worker\":\"" << s.worker_redacted
      << "\",\"submit_ready\":" << (wave37SnapshotSubmitReady(s) ? "true" : "false")
      << ",\"live_scan_ready\":" << (wave41SnapshotLiveScanReady(s) ? "true" : "false") << "}\n";
}

inline bool wave37SnapshotFromNotify(const boost::json::object &packet,
                                     const std::string &worker,
                                     const std::string &target,
                                     const std::string &pool_nonce,
                                     Wave37VerusJobSnapshot &snap) {
  if (!packet.if_contains("params") || !packet.at("params").is_array()) return false;
  auto params = packet.at("params").as_array();
  if (params.size() < 9) return false;
  snap.worker = worker;
  snap.worker_redacted = wave37RedactWorker(worker);
  snap.job_id = params[0].as_string().c_str();
  snap.version = params[1].as_string().c_str();
  snap.prevhash = params[2].as_string().c_str();
  snap.coinb1 = params[3].as_string().c_str();
  snap.coinb2 = params[4].as_string().c_str();
  snap.ntime = params[5].as_string().c_str();
  snap.nbits = params[6].as_string().c_str();
  snap.solution = params[8].as_string().c_str();
  snap.target = target;
  snap.pool_nonce = pool_nonce;
  snap.source = "mining.notify";
  snap.valid = !snap.job_id.empty() && snap.ntime.size() == 8 && !snap.solution.empty();
  return snap.valid;
}
