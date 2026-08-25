#ifndef SECP256K1_INT128_STRUCT_H
#define SECP256K1_INT128_STRUCT_H

#include <stdint.h>
#include "util.h"

typedef struct {
  uint64_t lo;
  uint64_t hi;
} dominterop_secp_v0_10_0_uint128;

typedef dominterop_secp_v0_10_0_uint128 dominterop_secp_v0_10_0_int128;

#endif
