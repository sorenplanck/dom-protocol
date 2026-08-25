/**********************************************************************
 * Copyright (c) 2020 The libsecp256k1 Developers                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stddef.h>

#include "eckey.h"
#include "hash.h"

/* from secp256k1.c */
static int dominterop_secp_v0_10_0_ec_seckey_tweak_add_helper(dominterop_secp_v0_10_0_scalar *sec, const unsigned char *tweak);
static int dominterop_secp_v0_10_0_ec_pubkey_tweak_add_helper(dominterop_secp_v0_10_0_ge *pubp, const unsigned char *tweak);

static int dominterop_secp_v0_10_0_ec_commit_pubkey_serialize_const(dominterop_secp_v0_10_0_ge *pubp, unsigned char *buf33) {
    if (dominterop_secp_v0_10_0_ge_is_infinity(pubp)) {
        return 0;
    }
    dominterop_secp_v0_10_0_fe_normalize(&pubp->x);
    dominterop_secp_v0_10_0_fe_normalize(&pubp->y);
    dominterop_secp_v0_10_0_fe_get_b32(&buf33[1], &pubp->x);
    buf33[0] = dominterop_secp_v0_10_0_fe_is_odd(&pubp->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    return 1;
}

/* Compute an ec commitment tweak as hash(pubp, data). */
static int dominterop_secp_v0_10_0_ec_commit_tweak(unsigned char *tweak32, dominterop_secp_v0_10_0_ge* pubp, dominterop_secp_v0_10_0_sha256* sha, const unsigned char *data, size_t data_size)
{
    unsigned char rbuf[33];

    if (!dominterop_secp_v0_10_0_ec_commit_pubkey_serialize_const(pubp, rbuf)) {
        return 0;
    }
    dominterop_secp_v0_10_0_sha256_write(sha, rbuf, sizeof(rbuf));
    dominterop_secp_v0_10_0_sha256_write(sha, data, data_size);
    dominterop_secp_v0_10_0_sha256_finalize(sha, tweak32);
    return 1;
}

/* Compute an ec commitment as pubp + hash(pubp, data)*G. */
static int dominterop_secp_v0_10_0_ec_commit(dominterop_secp_v0_10_0_ge* commitp, const dominterop_secp_v0_10_0_ge* pubp, dominterop_secp_v0_10_0_sha256* sha, const unsigned char *data, size_t data_size) {
    unsigned char tweak[32];

    *commitp = *pubp;
    return dominterop_secp_v0_10_0_ec_commit_tweak(tweak, commitp, sha, data, data_size)
           && dominterop_secp_v0_10_0_ec_pubkey_tweak_add_helper(commitp, tweak);
}

/* Compute the seckey of an ec commitment from the original secret key of the pubkey as seckey +
 * hash(pubp, data). */
static int dominterop_secp_v0_10_0_ec_commit_seckey(dominterop_secp_v0_10_0_scalar* seckey, dominterop_secp_v0_10_0_ge* pubp, dominterop_secp_v0_10_0_sha256* sha, const unsigned char *data, size_t data_size) {
    unsigned char tweak[32];
    return dominterop_secp_v0_10_0_ec_commit_tweak(tweak, pubp, sha, data, data_size)
           && dominterop_secp_v0_10_0_ec_seckey_tweak_add_helper(seckey, tweak);
}

/* Verify an ec commitment as pubp + hash(pubp, data)*G ?= commitment. */
static int dominterop_secp_v0_10_0_ec_commit_verify(const dominterop_secp_v0_10_0_ge* commitp, const dominterop_secp_v0_10_0_ge* pubp, dominterop_secp_v0_10_0_sha256* sha, const unsigned char *data, size_t data_size) {
    dominterop_secp_v0_10_0_gej pj;
    dominterop_secp_v0_10_0_ge p;

    if (!dominterop_secp_v0_10_0_ec_commit(&p, pubp, sha, data, data_size)) {
        return 0;
    }

    /* Return p == commitp */
    dominterop_secp_v0_10_0_ge_neg(&p, &p);
    dominterop_secp_v0_10_0_gej_set_ge(&pj, &p);
    dominterop_secp_v0_10_0_gej_add_ge_var(&pj, &pj, commitp, NULL);
    return dominterop_secp_v0_10_0_gej_is_infinity(&pj);
}

