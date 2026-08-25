/**********************************************************************
 * Copyright (c) 2014, 2015 Gregory Maxwell                          *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/


#ifndef SECP256K1_BORROMEAN_IMPL_H
#define SECP256K1_BORROMEAN_IMPL_H

#include "../../scalar.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../eckey.h"
#include "../../ecmult.h"
#include "../../ecmult_gen.h"
#include "borromean.h"

#include <limits.h>
#include <string.h>

SECP256K1_INLINE static void dominterop_secp_v0_10_0_borromean_hash(unsigned char *hash, const unsigned char *m, size_t mlen, const unsigned char *e, size_t elen,
 size_t ridx, size_t eidx) {
    unsigned char ring[4];
    unsigned char epos[4];
    dominterop_secp_v0_10_0_sha256 sha256_en;
    dominterop_secp_v0_10_0_sha256_initialize(&sha256_en);
    dominterop_secp_v0_10_0_write_be32(ring, (uint32_t)ridx);
    dominterop_secp_v0_10_0_write_be32(epos, (uint32_t)eidx);
    dominterop_secp_v0_10_0_sha256_write(&sha256_en, e, elen);
    dominterop_secp_v0_10_0_sha256_write(&sha256_en, m, mlen);
    dominterop_secp_v0_10_0_sha256_write(&sha256_en, ring, 4);
    dominterop_secp_v0_10_0_sha256_write(&sha256_en, epos, 4);
    dominterop_secp_v0_10_0_sha256_finalize(&sha256_en, hash);
}

/**  "Borromean" ring signature.
 *   Verifies nrings concurrent ring signatures all sharing a challenge value.
 *   Signature is one s value per pubkey and a hash.
 *   Verification equation:
 *   | m = H(P_{0..}||message) (Message must contain pubkeys or a pubkey commitment)
 *   | For each ring i:
 *   | | en = to_scalar(H(e0||m||i||0))
 *   | | For each pubkey j:
 *   | | | r = s_i_j G + en * P_i_j
 *   | | | e = H(r||m||i||j)
 *   | | | en = to_scalar(e)
 *   | | r_i = r
 *   | return e_0 ==== H(r_{0..i}||m)
 */
int dominterop_secp_v0_10_0_borromean_verify(dominterop_secp_v0_10_0_scalar *evalues, const unsigned char *e0,
 const dominterop_secp_v0_10_0_scalar *s, const dominterop_secp_v0_10_0_gej *pubs, const size_t *rsizes, size_t nrings, const unsigned char *m, size_t mlen) {
    dominterop_secp_v0_10_0_gej rgej;
    dominterop_secp_v0_10_0_ge rge;
    dominterop_secp_v0_10_0_scalar ens;
    dominterop_secp_v0_10_0_sha256 sha256_e0;
    unsigned char tmp[33];
    size_t i;
    size_t j;
    size_t count;
    size_t size;
    int overflow;
    VERIFY_CHECK(e0 != NULL);
    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(pubs != NULL);
    VERIFY_CHECK(rsizes != NULL);
    VERIFY_CHECK(nrings > 0);
    VERIFY_CHECK(m != NULL);
    count = 0;
    dominterop_secp_v0_10_0_sha256_initialize(&sha256_e0);
    for (i = 0; i < nrings; i++) {
        VERIFY_CHECK(INT_MAX - count > rsizes[i]);
        dominterop_secp_v0_10_0_borromean_hash(tmp, m, mlen, e0, 32, i, 0);
        dominterop_secp_v0_10_0_scalar_set_b32(&ens, tmp, &overflow);
        for (j = 0; j < rsizes[i]; j++) {
            if (overflow || dominterop_secp_v0_10_0_scalar_is_zero(&s[count]) || dominterop_secp_v0_10_0_scalar_is_zero(&ens) || dominterop_secp_v0_10_0_gej_is_infinity(&pubs[count])) {
                return 0;
            }
            if (evalues) {
                /*If requested, save the challenges for proof rewind.*/
                evalues[count] = ens;
            }
            dominterop_secp_v0_10_0_ecmult(&rgej, &pubs[count], &ens, &s[count]);
            if (dominterop_secp_v0_10_0_gej_is_infinity(&rgej)) {
                return 0;
            }
            /* OPT: loop can be hoisted and split to use batch inversion across all the rings; this would make it much faster. */
            dominterop_secp_v0_10_0_ge_set_gej_var(&rge, &rgej);
            dominterop_secp_v0_10_0_eckey_pubkey_serialize(&rge, tmp, &size, 1);
            if (j != rsizes[i] - 1) {
                dominterop_secp_v0_10_0_borromean_hash(tmp, m, mlen, tmp, 33, i, j + 1);
                dominterop_secp_v0_10_0_scalar_set_b32(&ens, tmp, &overflow);
            } else {
                dominterop_secp_v0_10_0_sha256_write(&sha256_e0, tmp, size);
            }
            count++;
        }
    }
    dominterop_secp_v0_10_0_sha256_write(&sha256_e0, m, mlen);
    dominterop_secp_v0_10_0_sha256_finalize(&sha256_e0, tmp);
    return dominterop_secp_v0_10_0_memcmp_var(e0, tmp, 32) == 0;
}

int dominterop_secp_v0_10_0_borromean_sign(const dominterop_secp_v0_10_0_ecmult_gen_context *ecmult_gen_ctx,
 unsigned char *e0, dominterop_secp_v0_10_0_scalar *s, const dominterop_secp_v0_10_0_gej *pubs, const dominterop_secp_v0_10_0_scalar *k, const dominterop_secp_v0_10_0_scalar *sec,
 const size_t *rsizes, const size_t *secidx, size_t nrings, const unsigned char *m, size_t mlen) {
    dominterop_secp_v0_10_0_gej rgej;
    dominterop_secp_v0_10_0_ge rge;
    dominterop_secp_v0_10_0_scalar ens;
    dominterop_secp_v0_10_0_sha256 sha256_e0;
    unsigned char tmp[33];
    size_t i;
    size_t j;
    size_t count;
    size_t size;
    int overflow;
    VERIFY_CHECK(ecmult_gen_ctx != NULL);
    VERIFY_CHECK(e0 != NULL);
    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(pubs != NULL);
    VERIFY_CHECK(k != NULL);
    VERIFY_CHECK(sec != NULL);
    VERIFY_CHECK(rsizes != NULL);
    VERIFY_CHECK(secidx != NULL);
    VERIFY_CHECK(nrings > 0);
    VERIFY_CHECK(m != NULL);
    dominterop_secp_v0_10_0_sha256_initialize(&sha256_e0);
    count = 0;
    for (i = 0; i < nrings; i++) {
        VERIFY_CHECK(INT_MAX - count > rsizes[i]);
        dominterop_secp_v0_10_0_ecmult_gen(ecmult_gen_ctx, &rgej, &k[i]);
        dominterop_secp_v0_10_0_ge_set_gej(&rge, &rgej);
        if (dominterop_secp_v0_10_0_gej_is_infinity(&rgej)) {
            return 0;
        }
        dominterop_secp_v0_10_0_eckey_pubkey_serialize(&rge, tmp, &size, 1);
        for (j = secidx[i] + 1; j < rsizes[i]; j++) {
            dominterop_secp_v0_10_0_borromean_hash(tmp, m, mlen, tmp, 33, i, j);
            dominterop_secp_v0_10_0_scalar_set_b32(&ens, tmp, &overflow);
            if (overflow || dominterop_secp_v0_10_0_scalar_is_zero(&ens)) {
                return 0;
            }
            /** The signing algorithm as a whole is not memory uniform so there is likely a cache sidechannel that
             *  leaks which members are non-forgeries. That the forgeries themselves are variable time may leave
             *  an additional privacy impacting timing side-channel, but not a key loss one.
             */
            dominterop_secp_v0_10_0_ecmult(&rgej, &pubs[count + j], &ens, &s[count + j]);
            if (dominterop_secp_v0_10_0_gej_is_infinity(&rgej)) {
                return 0;
            }
            dominterop_secp_v0_10_0_ge_set_gej_var(&rge, &rgej);
            dominterop_secp_v0_10_0_eckey_pubkey_serialize(&rge, tmp, &size, 1);
        }
        dominterop_secp_v0_10_0_sha256_write(&sha256_e0, tmp, size);
        count += rsizes[i];
    }
    dominterop_secp_v0_10_0_sha256_write(&sha256_e0, m, mlen);
    dominterop_secp_v0_10_0_sha256_finalize(&sha256_e0, e0);
    count = 0;
    for (i = 0; i < nrings; i++) {
        VERIFY_CHECK(INT_MAX - count > rsizes[i]);
        dominterop_secp_v0_10_0_borromean_hash(tmp, m, mlen, e0, 32, i, 0);
        dominterop_secp_v0_10_0_scalar_set_b32(&ens, tmp, &overflow);
        if (overflow || dominterop_secp_v0_10_0_scalar_is_zero(&ens)) {
            return 0;
        }
        for (j = 0; j < secidx[i]; j++) {
            dominterop_secp_v0_10_0_ecmult(&rgej, &pubs[count + j], &ens, &s[count + j]);
            if (dominterop_secp_v0_10_0_gej_is_infinity(&rgej)) {
                return 0;
            }
            dominterop_secp_v0_10_0_ge_set_gej_var(&rge, &rgej);
            dominterop_secp_v0_10_0_eckey_pubkey_serialize(&rge, tmp, &size, 1);
            dominterop_secp_v0_10_0_borromean_hash(tmp, m, mlen, tmp, 33, i, j + 1);
            dominterop_secp_v0_10_0_scalar_set_b32(&ens, tmp, &overflow);
            if (overflow || dominterop_secp_v0_10_0_scalar_is_zero(&ens)) {
                return 0;
            }
        }
        dominterop_secp_v0_10_0_scalar_mul(&s[count + j], &ens, &sec[i]);
        dominterop_secp_v0_10_0_scalar_negate(&s[count + j], &s[count + j]);
        dominterop_secp_v0_10_0_scalar_add(&s[count + j], &s[count + j], &k[i]);
        if (dominterop_secp_v0_10_0_scalar_is_zero(&s[count + j])) {
            return 0;
        }
        count += rsizes[i];
    }
    dominterop_secp_v0_10_0_scalar_clear(&ens);
    dominterop_secp_v0_10_0_ge_clear(&rge);
    dominterop_secp_v0_10_0_gej_clear(&rgej);
    memset(tmp, 0, 33);
    return 1;
}

#endif
