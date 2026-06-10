#include "adam-gate.h"

bool register_adam_algo( algo_gate_t *gate )
{
  init_adam_ctx();
  gate->scanhash  = (void*)&scanhash_adam;
  gate->hash      = (void*)&adam_base_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT ;
  pk_buffer_size  = 26;
  return true;
};
