#ifndef ADAM_GATE_H__
#define ADAM_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

bool register_adam_algo(algo_gate_t *gate);

void adam_base_hash(void *state, const void *input, uint8_t* cache);
int scanhash_adam(struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr);
void init_adam_ctx();

#endif
