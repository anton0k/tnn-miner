#pragma once

#include <cstdint>
#include <cstddef>

#ifndef MAX_GPUS
#define MAX_GPUS 80
#endif

#ifndef MAX_NONCES
#define MAX_NONCES 2
#endif

#ifndef POK_MAX_TXS
#define POK_MAX_TXS 4
#endif

#ifndef POK_MAX_TX_SZ
#define POK_MAX_TX_SZ 16384U
#endif

struct work_restart {
  volatile uint32_t restart;
  char padding[128 - sizeof(uint32_t)];
};

extern "C" {
extern struct work_restart *work_restart;
}

struct tx {
  uint8_t data[POK_MAX_TX_SZ];
  uint32_t len;
};

struct work {
  uint32_t data[48] = {0};
  uint32_t target[8] = {0};
  uint32_t maxvote = 0;

  char job_id[128] = {0};
  size_t xnonce2_len = 0;
  uint8_t xnonce2[32] = {0};

  union {
    uint32_t u32[2];
    uint64_t u64[1];
  } noncerange = {};

  uint8_t pooln = 0;
  uint8_t valid_nonces = 0;
  uint8_t submit_nonce_id = 0;
  uint8_t job_nonce_id = 0;

  uint32_t nonces[MAX_NONCES] = {0};
  double sharediff[MAX_NONCES] = {0.0};
  double shareratio[MAX_NONCES] = {0.0};
  double targetdiff = 0.0;

  uint32_t height = 0;
  uint32_t scanned_from = 0;
  uint32_t scanned_to = 0;

  uint32_t tx_count = 0;
  struct tx txs[POK_MAX_TXS] = {};

  uint8_t extra[1388] = {0};
  unsigned char solution[1344] = {0};
};

extern "C" void bn_store_hash_target_ratio(uint32_t *hash, uint32_t *target, struct work *w, int nonce);
