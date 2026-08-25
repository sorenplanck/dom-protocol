/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_KEYAGG_H
#define SECP256K1_MODULE_MUSIG_KEYAGG_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"

#include "../../field.h"
#include "../../group.h"
#include "../../scalar.h"

typedef struct {
    dominterop_secp_v0_10_0_ge pk;
    /* If there is no "second" public key, second_pk is set to the point at
     * infinity */
    dominterop_secp_v0_10_0_ge second_pk;
    unsigned char pk_hash[32];
    /* tweak is identical to value tacc[v] in the specification. */
    dominterop_secp_v0_10_0_scalar tweak;
    /* parity_acc corresponds to gacc[v] in the spec. If gacc[v] is -1,
     * parity_acc is 1. Otherwise, parity_acc is 0. */
    int parity_acc;
} dominterop_secp_v0_10_0_keyagg_cache_internal;

/* point_save_ext and point_load_ext are identical to point_save and point_load
 * except that they allow saving and loading the point at infinity */
static void dominterop_secp_v0_10_0_point_save_ext(unsigned char *data, dominterop_secp_v0_10_0_ge *ge);

static void dominterop_secp_v0_10_0_point_load_ext(dominterop_secp_v0_10_0_ge *ge, const unsigned char *data);

static int dominterop_secp_v0_10_0_keyagg_cache_load(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_keyagg_cache_internal *cache_i, const dominterop_secp_v0_10_0_musig_keyagg_cache *cache);

static void dominterop_secp_v0_10_0_musig_keyaggcoef(dominterop_secp_v0_10_0_scalar *r, const dominterop_secp_v0_10_0_keyagg_cache_internal *cache_i, dominterop_secp_v0_10_0_ge *pk);

#endif
