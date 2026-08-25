/**********************************************************************
 * Copyright (c) 2014, 2015 Gregory Maxwell                          *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_PEDERSEN_H
#define SECP256K1_PEDERSEN_H

#include "../../ecmult_gen.h"
#include "../../group.h"
#include "../../scalar.h"

#include <stdint.h>

/** Multiply a small number with the generator: r = gn*G2 */
static void dominterop_secp_v0_10_0_pedersen_ecmult_small(dominterop_secp_v0_10_0_gej *r, uint64_t gn, const dominterop_secp_v0_10_0_ge* genp);

/* sec * G + value * G2. */
static void dominterop_secp_v0_10_0_pedersen_ecmult(const dominterop_secp_v0_10_0_ecmult_gen_context *ecmult_gen_ctx, dominterop_secp_v0_10_0_gej *rj, const dominterop_secp_v0_10_0_scalar *sec, uint64_t value, const dominterop_secp_v0_10_0_ge* genp);

#endif
