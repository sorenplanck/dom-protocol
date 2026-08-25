/***********************************************************************
 * Copyright (c) 2018-2020 Andrew Poelstra, Jonas Nick                 *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_MAIN_H
#define SECP256K1_MODULE_SCHNORRSIG_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "../../hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/nonce")||SHA256("BIP0340/nonce"). */
static void dominterop_secp_v0_10_0_nonce_function_bip340_sha256_tagged(dominterop_secp_v0_10_0_sha256 *sha) {
    dominterop_secp_v0_10_0_sha256_initialize(sha);
    sha->s[0] = 0x46615b35ul;
    sha->s[1] = 0xf4bfbff7ul;
    sha->s[2] = 0x9f8dc671ul;
    sha->s[3] = 0x83627ab3ul;
    sha->s[4] = 0x60217180ul;
    sha->s[5] = 0x57358661ul;
    sha->s[6] = 0x21a29e54ul;
    sha->s[7] = 0x68b07b4cul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/aux")||SHA256("BIP0340/aux"). */
static void dominterop_secp_v0_10_0_nonce_function_bip340_sha256_tagged_aux(dominterop_secp_v0_10_0_sha256 *sha) {
    dominterop_secp_v0_10_0_sha256_initialize(sha);
    sha->s[0] = 0x24dd3219ul;
    sha->s[1] = 0x4eba7e70ul;
    sha->s[2] = 0xca0fabb9ul;
    sha->s[3] = 0x0fa3166dul;
    sha->s[4] = 0x3afbe4b1ul;
    sha->s[5] = 0x4c44df97ul;
    sha->s[6] = 0x4aac2739ul;
    sha->s[7] = 0x249e850aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_bip340 to derive the nonce exactly as stated in BIP-340
 * by using the correct tagged hash function. */
static const unsigned char bip340_algo[13] = "BIP0340/nonce";

static const unsigned char schnorrsig_extraparams_magic[4] = SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC;

static int nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    dominterop_secp_v0_10_0_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        dominterop_secp_v0_10_0_nonce_function_bip340_sha256_tagged_aux(&sha);
        dominterop_secp_v0_10_0_sha256_write(&sha, data, 32);
        dominterop_secp_v0_10_0_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    } else {
        /* Precomputed TaggedHash("BIP0340/aux", 0x0000...00); */
        static const unsigned char ZERO_MASK[32] = {
              84, 241, 105, 207, 201, 226, 229, 114,
             116, 128,  68,  31, 144, 186,  37, 196,
             136, 244,  97, 199,  11,  94, 165, 220,
             170, 247, 175, 105, 39,  10, 165,  20
        };
        for (i = 0; i < 32; i++) {
            masked_key[i] = key32[i] ^ ZERO_MASK[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithms. If this nonce function is used in BIP-340 signing as defined
     * in the spec, an optimized tagging implementation is used. */
    if (algolen == sizeof(bip340_algo)
            && dominterop_secp_v0_10_0_memcmp_var(algo, bip340_algo, algolen) == 0) {
        dominterop_secp_v0_10_0_nonce_function_bip340_sha256_tagged(&sha);
    } else {
        dominterop_secp_v0_10_0_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash masked-key||pk||msg using the tagged hash as per the spec */
    dominterop_secp_v0_10_0_sha256_write(&sha, masked_key, 32);
    dominterop_secp_v0_10_0_sha256_write(&sha, xonly_pk32, 32);
    dominterop_secp_v0_10_0_sha256_write(&sha, msg, msglen);
    dominterop_secp_v0_10_0_sha256_finalize(&sha, nonce32);
    return 1;
}

const dominterop_secp_v0_10_0_nonce_function_hardened dominterop_secp_v0_10_0_nonce_function_bip340 = nonce_function_bip340;

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"). */
static void dominterop_secp_v0_10_0_schnorrsig_sha256_tagged(dominterop_secp_v0_10_0_sha256 *sha) {
    dominterop_secp_v0_10_0_sha256_initialize(sha);
    sha->s[0] = 0x9cecba11ul;
    sha->s[1] = 0x23925381ul;
    sha->s[2] = 0x11679112ul;
    sha->s[3] = 0xd1627e0ful;
    sha->s[4] = 0x97c87550ul;
    sha->s[5] = 0x003cc765ul;
    sha->s[6] = 0x90f61164ul;
    sha->s[7] = 0x33e9b66aul;
    sha->bytes = 64;
}

static void dominterop_secp_v0_10_0_schnorrsig_challenge(dominterop_secp_v0_10_0_scalar* e, const unsigned char *r32, const unsigned char *msg, size_t msglen, const unsigned char *pubkey32)
{
    unsigned char buf[32];
    dominterop_secp_v0_10_0_sha256 sha;

    /* tagged hash(r.x, pk.x, msg) */
    dominterop_secp_v0_10_0_schnorrsig_sha256_tagged(&sha);
    dominterop_secp_v0_10_0_sha256_write(&sha, r32, 32);
    dominterop_secp_v0_10_0_sha256_write(&sha, pubkey32, 32);
    dominterop_secp_v0_10_0_sha256_write(&sha, msg, msglen);
    dominterop_secp_v0_10_0_sha256_finalize(&sha, buf);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    dominterop_secp_v0_10_0_scalar_set_b32(e, buf, NULL);
}

static int dominterop_secp_v0_10_0_schnorrsig_sign_internal(const dominterop_secp_v0_10_0_context* ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const dominterop_secp_v0_10_0_keypair *keypair, dominterop_secp_v0_10_0_nonce_function_hardened noncefp, void *ndata) {
    dominterop_secp_v0_10_0_scalar sk;
    dominterop_secp_v0_10_0_scalar e;
    dominterop_secp_v0_10_0_scalar k;
    dominterop_secp_v0_10_0_gej rj;
    dominterop_secp_v0_10_0_ge pk;
    dominterop_secp_v0_10_0_ge r;
    unsigned char buf[32] = { 0 };
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(dominterop_secp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(keypair != NULL);

    if (noncefp == NULL) {
        noncefp = dominterop_secp_v0_10_0_nonce_function_bip340;
    }

    ret &= dominterop_secp_v0_10_0_keypair_load(ctx, &sk, &pk, keypair);
    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have an even Y. */
    if (dominterop_secp_v0_10_0_fe_is_odd(&pk.y)) {
        dominterop_secp_v0_10_0_scalar_negate(&sk, &sk);
    }

    dominterop_secp_v0_10_0_scalar_get_b32(seckey, &sk);
    dominterop_secp_v0_10_0_fe_get_b32(pk_buf, &pk.x);
    ret &= !!noncefp(buf, msg, msglen, seckey, pk_buf, bip340_algo, sizeof(bip340_algo), ndata);
    dominterop_secp_v0_10_0_scalar_set_b32(&k, buf, NULL);
    ret &= !dominterop_secp_v0_10_0_scalar_is_zero(&k);
    dominterop_secp_v0_10_0_scalar_cmov(&k, &dominterop_secp_v0_10_0_scalar_one, !ret);

    dominterop_secp_v0_10_0_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    dominterop_secp_v0_10_0_ge_set_gej(&r, &rj);

    /* We declassify r to allow using it as a branch point. This is fine
     * because r is not a secret. */
    dominterop_secp_v0_10_0_declassify(ctx, &r, sizeof(r));
    dominterop_secp_v0_10_0_fe_normalize_var(&r.y);
    if (dominterop_secp_v0_10_0_fe_is_odd(&r.y)) {
        dominterop_secp_v0_10_0_scalar_negate(&k, &k);
    }
    dominterop_secp_v0_10_0_fe_normalize_var(&r.x);
    dominterop_secp_v0_10_0_fe_get_b32(&sig64[0], &r.x);

    dominterop_secp_v0_10_0_schnorrsig_challenge(&e, &sig64[0], msg, msglen, pk_buf);
    dominterop_secp_v0_10_0_scalar_mul(&e, &e, &sk);
    dominterop_secp_v0_10_0_scalar_add(&e, &e, &k);
    dominterop_secp_v0_10_0_scalar_get_b32(&sig64[32], &e);

    dominterop_secp_v0_10_0_memczero(sig64, 64, !ret);
    dominterop_secp_v0_10_0_scalar_clear(&k);
    dominterop_secp_v0_10_0_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int dominterop_secp_v0_10_0_schnorrsig_sign32(const dominterop_secp_v0_10_0_context* ctx, unsigned char *sig64, const unsigned char *msg32, const dominterop_secp_v0_10_0_keypair *keypair, const unsigned char *aux_rand32) {
    /* We cast away const from the passed aux_rand32 argument since we know the default nonce function does not modify it. */
    return dominterop_secp_v0_10_0_schnorrsig_sign_internal(ctx, sig64, msg32, 32, keypair, dominterop_secp_v0_10_0_nonce_function_bip340, (unsigned char*)aux_rand32);
}

int dominterop_secp_v0_10_0_schnorrsig_sign(const dominterop_secp_v0_10_0_context* ctx, unsigned char *sig64, const unsigned char *msg32, const dominterop_secp_v0_10_0_keypair *keypair, const unsigned char *aux_rand32) {
    return dominterop_secp_v0_10_0_schnorrsig_sign32(ctx, sig64, msg32, keypair, aux_rand32);
}

int dominterop_secp_v0_10_0_schnorrsig_sign_custom(const dominterop_secp_v0_10_0_context* ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const dominterop_secp_v0_10_0_keypair *keypair, dominterop_secp_v0_10_0_schnorrsig_extraparams *extraparams) {
    dominterop_secp_v0_10_0_nonce_function_hardened noncefp = NULL;
    void *ndata = NULL;
    VERIFY_CHECK(ctx != NULL);

    if (extraparams != NULL) {
        ARG_CHECK(dominterop_secp_v0_10_0_memcmp_var(extraparams->magic,
                                       schnorrsig_extraparams_magic,
                                       sizeof(extraparams->magic)) == 0);
        noncefp = extraparams->noncefp;
        ndata = extraparams->ndata;
    }
    return dominterop_secp_v0_10_0_schnorrsig_sign_internal(ctx, sig64, msg, msglen, keypair, noncefp, ndata);
}

int dominterop_secp_v0_10_0_schnorrsig_verify(const dominterop_secp_v0_10_0_context* ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const dominterop_secp_v0_10_0_xonly_pubkey *pubkey) {
    dominterop_secp_v0_10_0_scalar s;
    dominterop_secp_v0_10_0_scalar e;
    dominterop_secp_v0_10_0_gej rj;
    dominterop_secp_v0_10_0_ge pk;
    dominterop_secp_v0_10_0_gej pkj;
    dominterop_secp_v0_10_0_fe rx;
    dominterop_secp_v0_10_0_ge r;
    unsigned char buf[32];
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(pubkey != NULL);

    if (!dominterop_secp_v0_10_0_fe_set_b32_limit(&rx, &sig64[0])) {
        return 0;
    }

    dominterop_secp_v0_10_0_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!dominterop_secp_v0_10_0_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    /* Compute e. */
    dominterop_secp_v0_10_0_fe_get_b32(buf, &pk.x);
    dominterop_secp_v0_10_0_schnorrsig_challenge(&e, &sig64[0], msg, msglen, buf);

    /* Compute rj =  s*G + (-e)*pkj */
    dominterop_secp_v0_10_0_scalar_negate(&e, &e);
    dominterop_secp_v0_10_0_gej_set_ge(&pkj, &pk);
    dominterop_secp_v0_10_0_ecmult(&rj, &pkj, &e, &s);

    dominterop_secp_v0_10_0_ge_set_gej_var(&r, &rj);
    if (dominterop_secp_v0_10_0_ge_is_infinity(&r)) {
        return 0;
    }

    dominterop_secp_v0_10_0_fe_normalize_var(&r.y);
    return !dominterop_secp_v0_10_0_fe_is_odd(&r.y) &&
           dominterop_secp_v0_10_0_fe_equal(&rx, &r.x);
}

#endif
