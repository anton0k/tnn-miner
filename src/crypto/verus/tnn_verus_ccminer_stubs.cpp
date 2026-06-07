#include "crypto/verus/tnn_verus_work_bridge.h"

static struct work_restart wave41_work_restart_storage[MAX_GPUS] = {};
extern "C" struct work_restart *work_restart = wave41_work_restart_storage;

extern "C" void bn_store_hash_target_ratio(uint32_t *, uint32_t *, struct work *w, int nonce)
{
  if (w != nullptr && nonce >= 0 && nonce < MAX_NONCES) {
    w->shareratio[nonce] = 0.0;
  }
}
