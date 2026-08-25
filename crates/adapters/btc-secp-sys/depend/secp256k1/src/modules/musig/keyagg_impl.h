/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_KEYAGG_IMPL_H
#define SECP256K1_MODULE_MUSIG_KEYAGG_IMPL_H

#include <string.h>

#include "keyagg.h"
#include "../../eckey.h"
#include "../../ecmult.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../util.h"

static void dominterop_secp_v0_10_0_point_save_ext(unsigned char *data, dominterop_secp_v0_10_0_ge *ge) {
    if (dominterop_secp_v0_10_0_ge_is_infinity(ge)) {
        memset(data, 0, 64);
    } else {
        dominterop_secp_v0_10_0_ge_to_bytes(data, ge);
    }
}

static void dominterop_secp_v0_10_0_point_load_ext(dominterop_secp_v0_10_0_ge *ge, const unsigned char *data) {
    unsigned char zeros[64] = { 0 };
    if (dominterop_secp_v0_10_0_memcmp_var(data, zeros, sizeof(zeros)) == 0) {
        dominterop_secp_v0_10_0_ge_set_infinity(ge);
    } else {
        dominterop_secp_v0_10_0_ge_from_bytes(ge, data);
    }
}

static const unsigned char dominterop_secp_v0_10_0_musig_keyagg_cache_magic[4] = { 0xf4, 0xad, 0xbb, 0xdf };

/* A keyagg cache consists of
 * - 4 byte magic set during initialization to allow detecting an uninitialized
 *   object.
 * - 64 byte aggregate (and potentially tweaked) public key
 * - 64 byte "second" public key (set to the point at infinity if not present)
 * - 32 byte hash of all public keys
 * - 1 byte the parity of the internal key (if tweaked, otherwise 0)
 * - 32 byte tweak
 */
/* Requires that cache_i->pk is not infinity and cache_i->second_pk_x to be normalized. */
static void dominterop_secp_v0_10_0_keyagg_cache_save(dominterop_secp_v0_10_0_musig_keyagg_cache *cache, dominterop_secp_v0_10_0_keyagg_cache_internal *cache_i) {
    unsigned char *ptr = cache->data;
    memcpy(ptr, dominterop_secp_v0_10_0_musig_keyagg_cache_magic, 4);
    ptr += 4;
    dominterop_secp_v0_10_0_ge_to_bytes(ptr, &cache_i->pk);
    ptr += 64;
    dominterop_secp_v0_10_0_point_save_ext(ptr, &cache_i->second_pk);
    ptr += 64;
    memcpy(ptr, cache_i->pk_hash, 32);
    ptr += 32;
    *ptr = cache_i->parity_acc;
    ptr += 1;
    dominterop_secp_v0_10_0_scalar_get_b32(ptr, &cache_i->tweak);
}

static int dominterop_secp_v0_10_0_keyagg_cache_load(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_keyagg_cache_internal *cache_i, const dominterop_secp_v0_10_0_musig_keyagg_cache *cache) {
    const unsigned char *ptr = cache->data;
    ARG_CHECK(dominterop_secp_v0_10_0_memcmp_var(ptr, dominterop_secp_v0_10_0_musig_keyagg_cache_magic, 4) == 0);
    ptr += 4;
    dominterop_secp_v0_10_0_ge_from_bytes(&cache_i->pk, ptr);
    ptr += 64;
    dominterop_secp_v0_10_0_point_load_ext(&cache_i->second_pk, ptr);
    ptr += 64;
    memcpy(cache_i->pk_hash, ptr, 32);
    ptr += 32;
    cache_i->parity_acc = *ptr & 1;
    ptr += 1;
    dominterop_secp_v0_10_0_scalar_set_b32(&cache_i->tweak, ptr, NULL);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg list")||SHA256("KeyAgg list"). */
static void dominterop_secp_v0_10_0_musig_keyagglist_sha256(dominterop_secp_v0_10_0_sha256 *sha) {
    dominterop_secp_v0_10_0_sha256_initialize(sha);

    sha->s[0] = 0xb399d5e0ul;
    sha->s[1] = 0xc8fff302ul;
    sha->s[2] = 0x6badac71ul;
    sha->s[3] = 0x07c5b7f1ul;
    sha->s[4] = 0x9701e2eful;
    sha->s[5] = 0x2a72ecf8ul;
    sha->s[6] = 0x201a4c7bul;
    sha->s[7] = 0xab148a38ul;
    sha->bytes = 64;
}

/* Computes pk_hash = tagged_hash(pk[0], ..., pk[np-1]) */
static int dominterop_secp_v0_10_0_musig_compute_pk_hash(const dominterop_secp_v0_10_0_context *ctx, unsigned char *pk_hash, const dominterop_secp_v0_10_0_pubkey * const* pk, size_t np) {
    dominterop_secp_v0_10_0_sha256 sha;
    size_t i;

    dominterop_secp_v0_10_0_musig_keyagglist_sha256(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[33];
        size_t ser_len = sizeof(ser);
        if (!dominterop_secp_v0_10_0_ec_pubkey_serialize(ctx, ser, &ser_len, pk[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        VERIFY_CHECK(ser_len == sizeof(ser));
        dominterop_secp_v0_10_0_sha256_write(&sha, ser, sizeof(ser));
    }
    dominterop_secp_v0_10_0_sha256_finalize(&sha, pk_hash);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg coefficient")||SHA256("KeyAgg coefficient"). */
static void dominterop_secp_v0_10_0_musig_keyaggcoef_sha256(dominterop_secp_v0_10_0_sha256 *sha) {
    dominterop_secp_v0_10_0_sha256_initialize(sha);

    sha->s[0] = 0x6ef02c5aul;
    sha->s[1] = 0x06a480deul;
    sha->s[2] = 0x1f298665ul;
    sha->s[3] = 0x1d1134f2ul;
    sha->s[4] = 0x56a0b063ul;
    sha->s[5] = 0x52da4147ul;
    sha->s[6] = 0xf280d9d4ul;
    sha->s[7] = 0x4484be15ul;
    sha->bytes = 64;
}

/* Compute KeyAgg coefficient which is constant 1 for the second pubkey and
 * otherwise tagged_hash(pk_hash, x) where pk_hash is the hash of public keys.
 * second_pk is the point at infinity in case there is no second_pk. Assumes
 * that pk is not the point at infinity and that the Y-coordinates of pk and
 * second_pk are normalized. */
static void dominterop_secp_v0_10_0_musig_keyaggcoef_internal(dominterop_secp_v0_10_0_scalar *r, const unsigned char *pk_hash, dominterop_secp_v0_10_0_ge *pk, const dominterop_secp_v0_10_0_ge *second_pk) {
    dominterop_secp_v0_10_0_sha256 sha;

    VERIFY_CHECK(!dominterop_secp_v0_10_0_ge_is_infinity(pk));

    if (!dominterop_secp_v0_10_0_ge_is_infinity(second_pk)
          && dominterop_secp_v0_10_0_fe_equal(&pk->x, &second_pk->x)
          && dominterop_secp_v0_10_0_fe_is_odd(&pk->y) == dominterop_secp_v0_10_0_fe_is_odd(&second_pk->y)) {
        dominterop_secp_v0_10_0_scalar_set_int(r, 1);
    } else {
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        int ret;
        dominterop_secp_v0_10_0_musig_keyaggcoef_sha256(&sha);
        dominterop_secp_v0_10_0_sha256_write(&sha, pk_hash, 32);
        ret = dominterop_secp_v0_10_0_eckey_pubkey_serialize(pk, buf, &buflen, 1);
#ifdef VERIFY
        /* Serialization does not fail since the pk is not the point at infinity
         * (according to this function's precondition). */
        VERIFY_CHECK(ret && buflen == sizeof(buf));
#else
        (void) ret;
#endif
        dominterop_secp_v0_10_0_sha256_write(&sha, buf, sizeof(buf));
        dominterop_secp_v0_10_0_sha256_finalize(&sha, buf);
        dominterop_secp_v0_10_0_scalar_set_b32(r, buf, NULL);
    }
}

/* Assumes both field elements x and second_pk_x are normalized. */
static void dominterop_secp_v0_10_0_musig_keyaggcoef(dominterop_secp_v0_10_0_scalar *r, const dominterop_secp_v0_10_0_keyagg_cache_internal *cache_i, dominterop_secp_v0_10_0_ge *pk) {
    dominterop_secp_v0_10_0_musig_keyaggcoef_internal(r, cache_i->pk_hash, pk, &cache_i->second_pk);
}

typedef struct {
    const dominterop_secp_v0_10_0_context *ctx;
    /* pk_hash is the hash of the public keys */
    unsigned char pk_hash[32];
    const dominterop_secp_v0_10_0_pubkey * const* pks;
    dominterop_secp_v0_10_0_ge second_pk;
} dominterop_secp_v0_10_0_musig_pubkey_agg_ecmult_data;

/* Callback for batch EC multiplication to compute keyaggcoef_0*P0 + keyaggcoef_1*P1 + ...  */
static int dominterop_secp_v0_10_0_musig_pubkey_agg_callback(dominterop_secp_v0_10_0_scalar *sc, dominterop_secp_v0_10_0_ge *pt, size_t idx, void *data) {
    dominterop_secp_v0_10_0_musig_pubkey_agg_ecmult_data *ctx = (dominterop_secp_v0_10_0_musig_pubkey_agg_ecmult_data *) data;
    int ret;
    ret = dominterop_secp_v0_10_0_pubkey_load(ctx->ctx, pt, ctx->pks[idx]);
#ifdef VERIFY
    /* pubkey_load can't fail because the same pks have already been loaded in
     * `musig_compute_pk_hash` (and we test this). */
    VERIFY_CHECK(ret);
#else
    (void) ret;
#endif
    dominterop_secp_v0_10_0_musig_keyaggcoef_internal(sc, ctx->pk_hash, pt, &ctx->second_pk);
    return 1;
}

int dominterop_secp_v0_10_0_musig_pubkey_agg(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_scratch_space *scratch, dominterop_secp_v0_10_0_xonly_pubkey *agg_pk, dominterop_secp_v0_10_0_musig_keyagg_cache *keyagg_cache, const dominterop_secp_v0_10_0_pubkey * const* pubkeys, size_t n_pubkeys) {
    dominterop_secp_v0_10_0_musig_pubkey_agg_ecmult_data ecmult_data;
    dominterop_secp_v0_10_0_gej pkj;
    dominterop_secp_v0_10_0_ge pkp;
    size_t i;
    (void) scratch;

    VERIFY_CHECK(ctx != NULL);
    if (agg_pk != NULL) {
        memset(agg_pk, 0, sizeof(*agg_pk));
    }
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(n_pubkeys > 0);

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubkeys;

    dominterop_secp_v0_10_0_ge_set_infinity(&ecmult_data.second_pk);
    for (i = 1; i < n_pubkeys; i++) {
        if (dominterop_secp_v0_10_0_memcmp_var(pubkeys[0], pubkeys[i], sizeof(*pubkeys[0])) != 0) {
            dominterop_secp_v0_10_0_ge pk;
            if (!dominterop_secp_v0_10_0_pubkey_load(ctx, &pk, pubkeys[i])) {
                return 0;
            }
            ecmult_data.second_pk = pk;
            break;
        }
    }

    if (!dominterop_secp_v0_10_0_musig_compute_pk_hash(ctx, ecmult_data.pk_hash, pubkeys, n_pubkeys)) {
        return 0;
    }
    /* TODO: actually use optimized ecmult_multi algorithms by providing a
     * scratch space */
    if (!dominterop_secp_v0_10_0_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, dominterop_secp_v0_10_0_musig_pubkey_agg_callback, (void *) &ecmult_data, n_pubkeys)) {
        /* In order to reach this line with the current implementation of
         * ecmult_multi_var one would need to provide a callback that can
         * fail. */
        return 0;
    }
    dominterop_secp_v0_10_0_ge_set_gej(&pkp, &pkj);
    dominterop_secp_v0_10_0_fe_normalize_var(&pkp.y);
    /* The resulting public key is infinity with negligible probability */
    VERIFY_CHECK(!dominterop_secp_v0_10_0_ge_is_infinity(&pkp));
    if (keyagg_cache != NULL) {
        dominterop_secp_v0_10_0_keyagg_cache_internal cache_i = { 0 };
        cache_i.pk = pkp;
        cache_i.second_pk = ecmult_data.second_pk;
        memcpy(cache_i.pk_hash, ecmult_data.pk_hash, sizeof(cache_i.pk_hash));
        dominterop_secp_v0_10_0_keyagg_cache_save(keyagg_cache, &cache_i);
    }

    dominterop_secp_v0_10_0_extrakeys_ge_even_y(&pkp);
    if (agg_pk != NULL) {
        dominterop_secp_v0_10_0_xonly_pubkey_save(agg_pk, &pkp);
    }
    return 1;
}

int dominterop_secp_v0_10_0_musig_pubkey_get(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_pubkey *agg_pk, const dominterop_secp_v0_10_0_musig_keyagg_cache *keyagg_cache) {
    dominterop_secp_v0_10_0_keyagg_cache_internal cache_i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_pk != NULL);
    memset(agg_pk, 0, sizeof(*agg_pk));
    ARG_CHECK(keyagg_cache != NULL);

    if(!dominterop_secp_v0_10_0_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    dominterop_secp_v0_10_0_pubkey_save(agg_pk, &cache_i.pk);
    return 1;
}

static int dominterop_secp_v0_10_0_musig_pubkey_tweak_add_internal(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_pubkey *output_pubkey, dominterop_secp_v0_10_0_musig_keyagg_cache *keyagg_cache, const unsigned char *tweak32, int xonly) {
    dominterop_secp_v0_10_0_keyagg_cache_internal cache_i;
    int overflow = 0;
    dominterop_secp_v0_10_0_scalar tweak;

    VERIFY_CHECK(ctx != NULL);
    if (output_pubkey != NULL) {
        memset(output_pubkey, 0, sizeof(*output_pubkey));
    }
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!dominterop_secp_v0_10_0_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    dominterop_secp_v0_10_0_scalar_set_b32(&tweak, tweak32, &overflow);
    if (overflow) {
        return 0;
    }
    if (xonly && dominterop_secp_v0_10_0_extrakeys_ge_even_y(&cache_i.pk)) {
        cache_i.parity_acc ^= 1;
        dominterop_secp_v0_10_0_scalar_negate(&cache_i.tweak, &cache_i.tweak);
    }
    dominterop_secp_v0_10_0_scalar_add(&cache_i.tweak, &cache_i.tweak, &tweak);
    if (!dominterop_secp_v0_10_0_eckey_pubkey_tweak_add(&cache_i.pk, &tweak)) {
        return 0;
    }
    /* eckey_pubkey_tweak_add fails if cache_i.pk is infinity */
    VERIFY_CHECK(!dominterop_secp_v0_10_0_ge_is_infinity(&cache_i.pk));
    dominterop_secp_v0_10_0_keyagg_cache_save(keyagg_cache, &cache_i);
    if (output_pubkey != NULL) {
        dominterop_secp_v0_10_0_pubkey_save(output_pubkey, &cache_i.pk);
    }
    return 1;
}

int dominterop_secp_v0_10_0_musig_pubkey_ec_tweak_add(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_pubkey *output_pubkey, dominterop_secp_v0_10_0_musig_keyagg_cache *keyagg_cache, const unsigned char *tweak32) {
    return dominterop_secp_v0_10_0_musig_pubkey_tweak_add_internal(ctx, output_pubkey, keyagg_cache, tweak32, 0);
}

int dominterop_secp_v0_10_0_musig_pubkey_xonly_tweak_add(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_pubkey *output_pubkey, dominterop_secp_v0_10_0_musig_keyagg_cache *keyagg_cache, const unsigned char *tweak32) {
    return dominterop_secp_v0_10_0_musig_pubkey_tweak_add_internal(ctx, output_pubkey, keyagg_cache, tweak32, 1);
}

#endif
