#include "miners.hpp"
#include "tnn-hugepages.hpp"
#include <stratum/stratum.h>

#include <atomic>
#include <boost/json.hpp>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "crypto/verus/tnn_verus_work_bridge.h"
#include "verus_job_snapshot.hpp"

extern "C" int scanhash_verus(int thr_id, struct work *work, uint32_t max_nonce, unsigned long *hashes_done);

static std::mutex wave41SubmitGuardMutex;
static std::unordered_set<std::string> wave41SubmitKeys;
static std::unordered_set<std::string> wave41SubmittedJobs;
static std::atomic<uint64_t> wave41Hashes{0};
static std::atomic<int> wave41SubmitsPrepared{0};

static uint32_t wave41Le32dec(const unsigned char *p) {
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t wave41Swab32(uint32_t v) {
  return ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) |
         ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);
}

static bool wave41HexToBytes(const std::string &hex, unsigned char *out, size_t out_len, bool zero_pad = true) {
  if (zero_pad) std::memset(out, 0, out_len);
  if ((hex.size() % 2) != 0) return false;
  size_t n = std::min(out_len, hex.size() / 2);
  for (size_t i = 0; i < n; ++i) {
    char tmp[3] = {hex[i * 2], hex[i * 2 + 1], 0};
    char *end = nullptr;
    unsigned long v = std::strtoul(tmp, &end, 16);
    if (!end || *end != 0) return false;
    out[i] = static_cast<unsigned char>(v & 0xff);
  }
  return true;
}

static std::string wave41BytesToHex(const unsigned char *buf, size_t len) {
  std::ostringstream os;
  os << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) os << std::setw(2) << static_cast<unsigned>(buf[i]);
  return os.str();
}

static double wave41TargetToDiffEqui(const uint32_t *target) {
  const unsigned char *tgt = reinterpret_cast<const unsigned char *>(target);
  uint64_t m = (uint64_t)tgt[30] << 24 |
               (uint64_t)tgt[29] << 16 |
               (uint64_t)tgt[28] << 8  |
               (uint64_t)tgt[27] << 0;
  if (!m) return 0.0;
  return (double)0xffff0000UL / (double)m;
}

static void wave41DiffToTargetEqui(uint32_t *target, double diff) {
  uint64_t m;
  int k;
  for (k = 6; k > 0 && diff > 1.0; k--) diff /= 4294967296.0;
  m = (uint64_t)(4294901760.0 / diff);
  if (m == 0 && k == 6) {
    std::memset(target, 0xff, 32);
  } else {
    std::memset(target, 0, 32);
    target[k + 1] = (uint32_t)(m >> 8);
    target[k + 2] = (uint32_t)(m >> 40);
    for (k = 0; k < 28 && ((unsigned char*)target)[k] == 0; k++) {
      ((unsigned char*)target)[k] = 0xff;
    }
  }
}

static double wave41DiffFromPoolTarget(const std::string &target_hex) {
  unsigned char target_bin[32] = {0};
  unsigned char target_be[32];
  if (!wave41HexToBytes(target_hex, target_bin, 32)) return 1.0;
  std::memset(target_be, 0xff, 32);
  int filled = 0;
  for (int i = 0; i < 32; ++i) {
    if (filled == 3) break;
    target_be[31 - i] = target_bin[i];
    if (target_bin[i]) filled++;
  }
  double d = wave41TargetToDiffEqui(reinterpret_cast<uint32_t *>(target_be));
  return d > 0.0 ? d : 1.0;
}

static double wave41MiningFactor() {
  const char *m = std::getenv("TNN_VERUS_M");
  double v = (m && *m) ? std::atof(m) : 1.2;
  return v > 0.0 ? v : 1.0;
}

static bool wave41BuildWork(const Wave37VerusJobSnapshot &snap, struct work &w) {
  bool trace = std::getenv("TNN_WAVE41_TRACE_BUILDWORK") != nullptr;
  if (trace) std::cerr << "wave41_trace_buildwork_enter job_id=" << snap.job_id << " seq=" << snap.sequence << "\n";
  if (!wave41SnapshotLiveScanReady(snap)) return false;
  if (trace) std::cerr << "wave41_trace_buildwork_ready_ok\n";
  std::memset(&w, 0, sizeof(w));
  if (trace) std::cerr << "wave41_trace_buildwork_memset_ok size=" << sizeof(w) << "\n";
  unsigned char tmp[64] = {0};
  if (!wave41HexToBytes(snap.version, tmp, 4, true)) return false;
  w.data[0] = wave41Le32dec(tmp);
  if (trace) std::cerr << "wave41_trace_buildwork_version_ok\n";
  if (!wave41HexToBytes(snap.prevhash, tmp, 32, true)) return false;
  for (int i = 0; i < 8; ++i) w.data[1 + i] = wave41Le32dec(tmp + i * 4);
  if (trace) std::cerr << "wave41_trace_buildwork_prevhash_ok\n";
  if (!wave41HexToBytes(snap.coinb1, reinterpret_cast<unsigned char *>(&w.data[9]), 32, true)) return false;
  if (!wave41HexToBytes(snap.coinb2, reinterpret_cast<unsigned char *>(&w.data[17]), 32, true)) return false;
  if (trace) std::cerr << "wave41_trace_buildwork_coinbase_ok\n";
  if (!wave41HexToBytes(snap.ntime, tmp, 4, true)) return false;
  w.data[25] = wave41Le32dec(tmp);
  if (!wave41HexToBytes(snap.nbits, tmp, 4, true)) return false;
  w.data[26] = wave41Le32dec(tmp);
  if (trace) std::cerr << "wave41_trace_buildwork_timebits_ok\n";

  unsigned char xnonce1[32] = {0};
  if (!wave41HexToBytes(snap.pool_nonce, xnonce1, sizeof(xnonce1), true)) return false;
  size_t xnonce1_size = snap.pool_nonce.size() / 2;
  if (xnonce1_size == 0 || xnonce1_size > 32) return false;
  std::memcpy(&w.data[27], xnonce1, xnonce1_size);
  w.xnonce2_len = static_cast<uint32_t>(32 - xnonce1_size);
  if (w.xnonce2_len > 0) {
    std::memcpy(w.xnonce2, reinterpret_cast<unsigned char *>(&w.data[27]) + xnonce1_size,
                std::min<size_t>(w.xnonce2_len, sizeof(w.xnonce2)));
  }
  if (trace) std::cerr << "wave41_trace_buildwork_xnonce_ok xnonce1_size=" << xnonce1_size << " xnonce2_len=" << w.xnonce2_len << "\n";

  w.data[35] = 0x80;
  if (!wave41HexToBytes(snap.solution, w.solution, sizeof(w.solution), true)) return false;
  if (trace) std::cerr << "wave41_trace_buildwork_solution_ok\n";
  std::snprintf(w.job_id, sizeof(w.job_id), "%07x %s", wave41Swab32(w.data[25]) & 0x0fffffffU, snap.job_id.c_str());

  double diff = wave41DiffFromPoolTarget(snap.target);
  const double opt_difficulty = 1.0 / wave41MiningFactor();
  wave41DiffToTargetEqui(w.target, diff / opt_difficulty);
  if (const char *forced = std::getenv("TNN_WAVE41_FORCE_TARGET7_HEX")) {
    char *end = nullptr;
    unsigned long v = std::strtoul(forced, &end, 16);
    if (end && *end == 0) w.target[7] = static_cast<uint32_t>(v);
  }
  w.targetdiff = diff;
  if (trace) std::cerr << "wave41_trace_buildwork_done target7=0x" << std::hex << w.target[7] << std::dec << "\n";
  return true;
}

static std::string wave41SubmitJobId(const struct work &w) {
  return std::strlen(w.job_id) > 8 ? std::string(w.job_id + 8) : std::string(w.job_id);
}

static std::string wave41SubmitTimeHex(const struct work &w) {
  char timehex[16] = {0};
  std::snprintf(timehex, sizeof(timehex), "%08x", wave41Swab32(w.data[25]));
  return std::string(timehex);
}

static std::string wave41SubmitNonceStr(const struct work &w) {
  const unsigned char *nonce = reinterpret_cast<const unsigned char *>(&w.data[27]);
  size_t xnonce1_size = 32 - w.xnonce2_len;
  size_t nonce_len = 32 - xnonce1_size;
  return wave41BytesToHex(nonce + xnonce1_size, nonce_len);
}

static std::string wave41SubmitSolHex(const struct work &w) {
  std::string solhex = wave41BytesToHex(w.extra, 1347);
  std::string restore = wave41BytesToHex(&w.solution[8], 64);
  if (solhex.size() >= 6 + 16 + restore.size()) {
    solhex.replace(6 + 16, restore.size(), restore);
  }
  return solhex;
}

static uint64_t wave41Fnv1a64(const std::string &s) {
  uint64_t h = 1469598103934665603ULL;
  for (unsigned char c : s) {
    h ^= c;
    h *= 1099511628211ULL;
  }
  return h;
}

static std::string wave41SubmitHashHex(const struct work &w) {
  return wave41BytesToHex(
      reinterpret_cast<const unsigned char *>(w.submit_hashes[w.submit_nonce_id]),
      sizeof(w.submit_hashes[w.submit_nonce_id]));
}

static std::string wave41SubmitKey(const struct work &w) {
  return wave41SubmitJobId(w) + "|" + wave41SubmitTimeHex(w) + "|" +
         wave41SubmitNonceStr(w) + "|" + wave41SubmitSolHex(w);
}

static bool wave41AllowSameJobSubmits() {
  const char *value = std::getenv("TNN_WAVE41_ALLOW_SAME_JOB_SUBMITS");
  return value != nullptr && std::strcmp(value, "1") == 0;
}

static bool wave41QueueSubmit(const Wave37VerusJobSnapshot &snap, struct work &w, int tid) {
  w.submit_nonce_id = 0;
  w.data[30] = w.nonces[0];
  const std::string job_id = wave41SubmitJobId(w);
  const std::string timehex = wave41SubmitTimeHex(w);
  const std::string noncestr = wave41SubmitNonceStr(w);
  const std::string solhex = wave41SubmitSolHex(w);
  const std::string hashhex = wave41SubmitHashHex(w);
  const std::string key = wave41SubmitKey(w);
  const bool allow_same_job_submits = wave41AllowSameJobSubmits();
  bool inserted_key = false;
  bool inserted_job = false;

  {
    std::lock_guard<std::mutex> lk(wave41SubmitGuardMutex);
    if (!allow_same_job_submits && wave41SubmittedJobs.find(job_id) != wave41SubmittedJobs.end()) {
      std::cout << "wave41_tnn_submit_same_job_skipped jobid=" << job_id << "\n";
      return false;
    }
    if (!wave41SubmitKeys.insert(key).second) {
      std::cout << "wave41_tnn_submit_duplicate_skipped key_fnv64=0x" << std::hex << wave41Fnv1a64(key) << std::dec << "\n";
      return false;
    }
    inserted_key = true;
    if (!allow_same_job_submits) {
      wave41SubmittedJobs.insert(job_id);
      inserted_job = true;
    }
  }

  boost::json::object msg;
  msg["rpc_id"] = submitTracker.nextId(-1);
  msg["method"] = "mining.submit";
  msg["params"] = boost::json::array({snap.worker, job_id, timehex, noncestr, solhex});

  {
    std::lock_guard<std::mutex> lock(mutex);
    if (submitting) {
      std::lock_guard<std::mutex> lk(wave41SubmitGuardMutex);
      if (inserted_key) wave41SubmitKeys.erase(key);
      if (inserted_job) wave41SubmittedJobs.erase(job_id);
      std::cout << "wave41_tnn_submit_queue_busy tid=" << tid << " jobid=" << job_id << "\n";
      return false;
    }
    share = msg;
    submitting = true;
    data_ready = true;
  }
  cv.notify_all();

  int prepared = wave41SubmitsPrepared.fetch_add(1) + 1;
  std::cout << "wave41_tnn_submit_prepared tid=" << tid
            << " count=" << prepared
            << " jobid=" << job_id
            << " allow_same_job=" << (allow_same_job_submits ? 1 : 0)
            << " noncestr_len=" << noncestr.size()
            << " solhex_len=" << solhex.size()
            << " hash_fnv64=0x" << std::hex << wave41Fnv1a64(hashhex) << std::dec
            << " key_fnv64=0x" << std::hex << wave41Fnv1a64(key) << std::dec
            << "\n";
  if (std::getenv("TNN_WAVE41_TRACE_SUBMIT_HASH") != nullptr) {
    std::cout << "wave41_tnn_submit_hash_hex tid=" << tid
              << " jobid=" << job_id
              << " nonce=" << noncestr
              << " hash_hex=" << hashhex
              << "\n";
  }
  return true;
}

static int wave41MaxPreparedSubmits() {
  const char *limit = std::getenv("TNN_WAVE41_MAX_PREPARED_SUBMITS");
  if (!limit || !*limit) return -1;
  return std::atoi(limit);
}

static void wave41LiveScanLoop(int tid) {
  const int scan_tid = tid > 0 ? tid - 1 : 0;
  uint64_t seen_seq = 0;
  uint32_t local_round = 0;
  std::unique_ptr<struct work> work_holder(new struct work);
  struct work &w = *work_holder;

  std::cout << "wave41_tnn_live_scan_start tid=" << tid
            << " scan_tid=" << scan_tid
            << " m=" << wave41MiningFactor()
            << "\n";

  while (!ABORT_MINER) {
    Wave37VerusJobSnapshot snap = wave37CopySnapshot();
    if (!wave41SnapshotLiveScanReady(snap) || snap.sequence == seen_seq) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }
    seen_seq = snap.sequence;
    if (std::getenv("TNN_WAVE41_TRACE_BUILDWORK") != nullptr) {
      std::cerr << "wave41_trace_before_buildwork tid=" << tid << " seq=" << snap.sequence << " job_id=" << snap.job_id << "\n";
    }
    if (!wave41BuildWork(snap, w)) {
      std::cout << "wave41_tnn_build_work=fail tid=" << tid
                << " job_id=" << snap.job_id
                << " seq=" << snap.sequence << "\n";
      continue;
    }
    if (std::getenv("TNN_WAVE41_TRACE_BUILDWORK") != nullptr) {
      std::cerr << "wave41_trace_after_buildwork tid=" << tid << " seq=" << snap.sequence << "\n";
    }

    std::cout << "wave41_tnn_scan_job tid=" << tid
              << " job_id=" << snap.job_id
              << " seq=" << snap.sequence
              << " target7=0x" << std::hex << w.target[7]
              << " data30_start=0x" << w.data[30]
              << std::dec << "\n";

    uint32_t wave41BaseData[48] = {0};
    std::memcpy(wave41BaseData, w.data, sizeof(w.data));

    while (!ABORT_MINER) {
      Wave37VerusJobSnapshot current = wave37CopySnapshot();
      if (!current.valid || current.sequence != seen_seq) break;

      unsigned long done = 0;
      std::memcpy(w.data, wave41BaseData, sizeof(w.data));
      w.data[30] = 0;
      w.data[32] = (local_round++ << 8) | static_cast<uint32_t>(scan_tid & 0xff);
      uint32_t max_nonce = w.data[30] + 8191U;
      w.valid_nonces = 0;
      std::memset(w.submit_hashes, 0, sizeof(w.submit_hashes));
      int hits = scanhash_verus(scan_tid, &w, max_nonce, &done);
      cpu_counter.fetch_add(static_cast<int64_t>(done));
      uint64_t total = wave41Hashes.fetch_add(done) + done;
      if ((total % (1024 * 1024)) < done) {
        std::cout << "wave41_tnn_hashes=" << total
                  << " prepared=" << wave41SubmitsPrepared.load()
                  << "\n";
      }
      if (hits > 0 && w.valid_nonces > 0) {
        std::cout << "wave41_tnn_candidate_found tid=" << tid
                  << " job_id=" << snap.job_id
                  << " nonce=0x" << std::hex << w.nonces[0] << std::dec
                  << "\n";
        wave41QueueSubmit(snap, w, tid);
        int max_prepared = wave41MaxPreparedSubmits();
        if (max_prepared >= 0 && wave41SubmitsPrepared.load() >= max_prepared) {
          std::cout << "wave41_tnn_prepared_submit_limit_reached count=" << wave41SubmitsPrepared.load()
                    << " limit=" << max_prepared << "\n";
          return;
        }
      }
      std::this_thread::yield();
    }
  }
}

void mineVerus(int tid)
{
  const char *fixture = std::getenv("TNN_VERUS_WAVE37_FIXTURE");
  const char *dryrunOut = std::getenv("TNN_VERUS_WAVE37_DRYRUN_OUT");
  if (std::getenv("TNN_VERUS_WAVE37_SNAPSHOT_TEST") != nullptr && fixture != nullptr) {
    Wave37VerusJobSnapshot snap = wave37SnapshotFromFixtureFile(fixture);
    wave37StoreSnapshot(snap);
    wave37WriteSnapshotJsonl(dryrunOut ? dryrunOut : "", snap, "mineverus_fixture_snapshot");
    std::printf("tnn_mineverus_snapshot_offline_loop=%s\n", wave37SnapshotJobReady(snap) ? "pass" : "fail");
    if (wave37SnapshotSubmitReady(snap)) {
      boost::json::object submit = wave37SubmitDryrunObject(snap);
      if (dryrunOut != nullptr) {
        std::ofstream out(dryrunOut, std::ios::app);
        out << boost::json::serialize(submit) << "\n";
      }
      std::printf("tnn_mineverus_snapshot_submit_dryrun=pass\n");
    } else {
      std::printf("tnn_mineverus_snapshot_submit_dryrun=fail\n");
    }
    return;
  }

  if (std::getenv("TNN_VERUS_WAVE37_DRYRUN_LOOP") != nullptr) {
    int loops = 0;
    while (loops++ < 600 && !ABORT_MINER) {
      Wave37VerusJobSnapshot snap = wave37CopySnapshot();
      if (wave37SnapshotJobReady(snap)) {
        wave37WriteSnapshotJsonl(dryrunOut ? dryrunOut : "", snap, "mineverus_runtime_snapshot_seen");
        if (wave37SnapshotSubmitReady(snap)) {
          boost::json::object submit = wave37SubmitDryrunObject(snap);
          if (dryrunOut != nullptr) {
            std::ofstream out(dryrunOut, std::ios::app);
            out << boost::json::serialize(submit) << "\n";
          }
        }
        std::printf("tnn_live_job_mineverus_dryrun=pass\n");
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::printf("tnn_live_job_mineverus_dryrun=no_snapshot\n");
    return;
  }

  if (std::getenv("TNN_VERUS_WAVE41_LIVE_SCAN") != nullptr) {
    wave41LiveScanLoop(tid);
    return;
  }

  for (;;) {
    std::this_thread::yield();
  }
}

