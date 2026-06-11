#include "crypto/verus/tnn_verus_work_bridge.h"

#include <cstring>

static struct work_restart wave41_work_restart_storage[MAX_GPUS] = {};
extern "C" struct work_restart *work_restart = wave41_work_restart_storage;

extern "C" void bn_store_hash_target_ratio(uint32_t *hash, uint32_t *, struct work *w, int nonce)
{
  if (w == nullptr || hash == nullptr || nonce < 0 || nonce >= MAX_NONCES)
    return;

  std::memcpy(w->submit_hashes[nonce], hash, sizeof(w->submit_hashes[nonce]));
  w->shareratio[nonce] = 0.0;
}
