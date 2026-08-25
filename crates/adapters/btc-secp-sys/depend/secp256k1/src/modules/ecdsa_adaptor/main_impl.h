/**********************************************************************
 * Copyright (c) 2020-2021 Jonas Nick, Jesse Posner                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H

#include "../../../include/secp256k1_ecdsa_adaptor.h"
#include "dleq_impl.h"

/* (R, R', s', dleq_proof) */
static int dominterop_secp_v0_10_0_ecdsa_adaptor_sig_serialize(unsigned char *adaptor_sig162, dominterop_secp_v0_10_0_ge *r, dominterop_secp_v0_10_0_ge *rp, const dominterop_secp_v0_10_0_scalar *sp, const dominterop_secp_v0_10_0_scalar *dleq_proof_e, const dominterop_secp_v0_10_0_scalar *dleq_proof_s) {
    size_t size = 33;

    if (!dominterop_secp_v0_10_0_eckey_pubkey_serialize(r, adaptor_sig162, &size, 1)) {
        return 0;
    }
    if (!dominterop_secp_v0_10_0_eckey_pubkey_serialize(rp, &adaptor_sig162[33], &size, 1)) {
        return 0;
    }
    dominterop_secp_v0_10_0_scalar_get_b32(&adaptor_sig162[66], sp);
    dominterop_secp_v0_10_0_scalar_get_b32(&adaptor_sig162[98], dleq_proof_e);
    dominterop_secp_v0_10_0_scalar_get_b32(&adaptor_sig162[130], dleq_proof_s);

    return 1;
}

static int dominterop_secp_v0_10_0_ecdsa_adaptor_sig_deserialize(dominterop_secp_v0_10_0_ge *r, dominterop_secp_v0_10_0_scalar *sigr, dominterop_secp_v0_10_0_ge *rp, dominterop_secp_v0_10_0_scalar *sp, dominterop_secp_v0_10_0_scalar *dleq_proof_e, dominterop_secp_v0_10_0_scalar *dleq_proof_s, const unsigned char *adaptor_sig162) {
    /* If r is deserialized, require that a sigr is provided to receive
     * the X-coordinate */
    VERIFY_CHECK((r == NULL) || (r != NULL && sigr != NULL));
    if (r != NULL) {
        if (!dominterop_secp_v0_10_0_eckey_pubkey_parse(r, &adaptor_sig162[0], 33)) {
            return 0;
        }
    }
    if (sigr != NULL) {
        dominterop_secp_v0_10_0_scalar_set_b32(sigr, &adaptor_sig162[1], NULL);
        if (dominterop_secp_v0_10_0_scalar_is_zero(sigr)) {
            return 0;
        }
    }
    if (rp != NULL) {
        if (!dominterop_secp_v0_10_0_eckey_pubkey_parse(rp, &adaptor_sig162[33], 33)) {
            return 0;
        }
    }
    if (sp != NULL) {
        if (!dominterop_secp_v0_10_0_scalar_set_b32_seckey(sp, &adaptor_sig162[66])) {
            return 0;
        }
    }
    if (dleq_proof_e != NULL) {
        dominterop_secp_v0_10_0_scalar_set_b32(dleq_proof_e, &adaptor_sig162[98], NULL);
    }
    if (dleq_proof_s != NULL) {
        int overflow;
        dominterop_secp_v0_10_0_scalar_set_b32(dleq_proof_s, &adaptor_sig162[130], &overflow);
        if (overflow) {
            return 0;
        }
    }
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("ECDSAadaptor/non")||SHA256("ECDSAadaptor/non"). */
static void dominterop_secp_v0_10_0_nonce_function_ecdsa_adaptor_sha256_tagged(dominterop_secp_v0_10_0_sha256 *sha) {
    dominterop_secp_v0_10_0_sha256_initialize(sha);
    sha->s[0] = 0x791dae43ul;
    sha->s[1] = 0xe52d3b44ul;
    sha->s[2] = 0x37f9edeaul;
    sha->s[3] = 0x9bfd2ab1ul;
    sha->s[4] = 0xcfb0f44dul;
    sha->s[5] = 0xccf1d880ul;
    sha->s[6] = 0xd18f2c13ul;
    sha->s[7] = 0xa37b9024ul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("ECDSAadaptor/aux")||SHA256("ECDSAadaptor/aux"). */
static void dominterop_secp_v0_10_0_nonce_function_ecdsa_adaptor_sha256_tagged_aux(dominterop_secp_v0_10_0_sha256 *sha) {
    dominterop_secp_v0_10_0_sha256_initialize(sha);
    sha->s[0] = 0xd14c7bd9ul;
    sha->s[1] = 0x095d35e6ul;
    sha->s[2] = 0xb8490a88ul;
    sha->s[3] = 0xfb00ef74ul;
    sha->s[4] = 0x0baa488ful;
    sha->s[5] = 0x69366693ul;
    sha->s[6] = 0x1c81c5baul;
    sha->s[7] = 0xc33b296aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_ecdsa_adaptor to derive the nonce using a tagged hash function. */
static const unsigned char ecdsa_adaptor_algo[16] = "ECDSAadaptor/non";

/* Modified BIP-340 nonce function */
static int nonce_function_ecdsa_adaptor(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *pk33, const unsigned char *algo, size_t algolen, void *data) {
    dominterop_secp_v0_10_0_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        dominterop_secp_v0_10_0_nonce_function_ecdsa_adaptor_sha256_tagged_aux(&sha);
        dominterop_secp_v0_10_0_sha256_write(&sha, data, 32);
        dominterop_secp_v0_10_0_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithims. An optimized tagging implementation is used if the default
     * tag is provided. */
    if (algolen == sizeof(ecdsa_adaptor_algo)
            && dominterop_secp_v0_10_0_memcmp_var(algo, ecdsa_adaptor_algo, algolen) == 0) {
        dominterop_secp_v0_10_0_nonce_function_ecdsa_adaptor_sha256_tagged(&sha);
    } else if (algolen == sizeof(dleq_algo)
            && dominterop_secp_v0_10_0_memcmp_var(algo, dleq_algo, algolen) == 0) {
        dominterop_secp_v0_10_0_nonce_function_dleq_sha256_tagged(&sha);
    } else {
        dominterop_secp_v0_10_0_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash (masked-)key||pk||msg using the tagged hash as per BIP-340 */
    if (data != NULL) {
        dominterop_secp_v0_10_0_sha256_write(&sha, masked_key, 32);
    } else {
        dominterop_secp_v0_10_0_sha256_write(&sha, key32, 32);
    }
    dominterop_secp_v0_10_0_sha256_write(&sha, pk33, 33);
    dominterop_secp_v0_10_0_sha256_write(&sha, msg32, 32);
    dominterop_secp_v0_10_0_sha256_finalize(&sha, nonce32);
    return 1;
}

const dominterop_secp_v0_10_0_nonce_function_hardened_ecdsa_adaptor dominterop_secp_v0_10_0_nonce_function_ecdsa_adaptor = nonce_function_ecdsa_adaptor;

int dominterop_secp_v0_10_0_ecdsa_adaptor_encrypt(const dominterop_secp_v0_10_0_context* ctx, unsigned char *adaptor_sig162, unsigned char *seckey32, const dominterop_secp_v0_10_0_pubkey *enckey, const unsigned char *msg32, dominterop_secp_v0_10_0_nonce_function_hardened_ecdsa_adaptor noncefp, void *ndata) {
    dominterop_secp_v0_10_0_scalar k;
    dominterop_secp_v0_10_0_gej rj, rpj;
    dominterop_secp_v0_10_0_ge r, rp;
    dominterop_secp_v0_10_0_ge enckey_ge;
    dominterop_secp_v0_10_0_scalar dleq_proof_s;
    dominterop_secp_v0_10_0_scalar dleq_proof_e;
    dominterop_secp_v0_10_0_scalar sk;
    dominterop_secp_v0_10_0_scalar msg;
    dominterop_secp_v0_10_0_scalar sp;
    dominterop_secp_v0_10_0_scalar sigr;
    dominterop_secp_v0_10_0_scalar n;
    unsigned char nonce32[32] = { 0 };
    unsigned char buf33[33];
    size_t size = 33;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(dominterop_secp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(seckey32 != NULL);
    ARG_CHECK(enckey != NULL);
    ARG_CHECK(msg32 != NULL);

    dominterop_secp_v0_10_0_scalar_clear(&dleq_proof_e);
    dominterop_secp_v0_10_0_scalar_clear(&dleq_proof_s);

    if (noncefp == NULL) {
        noncefp = dominterop_secp_v0_10_0_nonce_function_ecdsa_adaptor;
    }

    ret &= dominterop_secp_v0_10_0_pubkey_load(ctx, &enckey_ge, enckey);
    ret &= dominterop_secp_v0_10_0_eckey_pubkey_serialize(&enckey_ge, buf33, &size, 1);
    ret &= !!noncefp(nonce32, msg32, seckey32, buf33, ecdsa_adaptor_algo, sizeof(ecdsa_adaptor_algo), ndata);
    dominterop_secp_v0_10_0_scalar_set_b32(&k, nonce32, NULL);
    ret &= !dominterop_secp_v0_10_0_scalar_is_zero(&k);
    dominterop_secp_v0_10_0_scalar_cmov(&k, &dominterop_secp_v0_10_0_scalar_one, !ret);

    /* R' := k*G */
    dominterop_secp_v0_10_0_ecmult_gen(&ctx->ecmult_gen_ctx, &rpj, &k);
    dominterop_secp_v0_10_0_ge_set_gej(&rp, &rpj);
    /* R = k*Y; */
    dominterop_secp_v0_10_0_ecmult_const(&rj, &enckey_ge, &k);
    dominterop_secp_v0_10_0_ge_set_gej(&r, &rj);
    /* We declassify the non-secret values rp and r to allow using them
     * as branch points. */
    dominterop_secp_v0_10_0_declassify(ctx, &rp, sizeof(rp));
    dominterop_secp_v0_10_0_declassify(ctx, &r, sizeof(r));

    /* dleq_proof = DLEQ_prove(k, (R', Y, R)) */
    ret &= dominterop_secp_v0_10_0_dleq_prove(ctx, &dleq_proof_s, &dleq_proof_e, &k, &enckey_ge, &rp, &r, noncefp, ndata);

    ret &= dominterop_secp_v0_10_0_scalar_set_b32_seckey(&sk, seckey32);
    dominterop_secp_v0_10_0_scalar_cmov(&sk, &dominterop_secp_v0_10_0_scalar_one, !ret);
    dominterop_secp_v0_10_0_scalar_set_b32(&msg, msg32, NULL);
    dominterop_secp_v0_10_0_fe_normalize(&r.x);
    dominterop_secp_v0_10_0_fe_get_b32(buf33, &r.x);
    dominterop_secp_v0_10_0_scalar_set_b32(&sigr, buf33, NULL);
    ret &= !dominterop_secp_v0_10_0_scalar_is_zero(&sigr);
    /* s' = k⁻¹(m + R.x * x) */
    dominterop_secp_v0_10_0_scalar_mul(&n, &sigr, &sk);
    dominterop_secp_v0_10_0_scalar_add(&n, &n, &msg);
    dominterop_secp_v0_10_0_scalar_inverse(&sp, &k);
    dominterop_secp_v0_10_0_scalar_mul(&sp, &sp, &n);
    ret &= !dominterop_secp_v0_10_0_scalar_is_zero(&sp);

    /* return (R, R', s', dleq_proof) */
    ret &= dominterop_secp_v0_10_0_ecdsa_adaptor_sig_serialize(adaptor_sig162, &r, &rp, &sp, &dleq_proof_e, &dleq_proof_s);

    dominterop_secp_v0_10_0_memczero(adaptor_sig162, 162, !ret);
    dominterop_secp_v0_10_0_scalar_clear(&n);
    dominterop_secp_v0_10_0_scalar_clear(&k);
    dominterop_secp_v0_10_0_scalar_clear(&sk);

    return ret;
}

int dominterop_secp_v0_10_0_ecdsa_adaptor_verify(const dominterop_secp_v0_10_0_context* ctx, const unsigned char *adaptor_sig162, const dominterop_secp_v0_10_0_pubkey *pubkey, const unsigned char *msg32, const dominterop_secp_v0_10_0_pubkey *enckey) {
    dominterop_secp_v0_10_0_scalar dleq_proof_s, dleq_proof_e;
    dominterop_secp_v0_10_0_scalar msg;
    dominterop_secp_v0_10_0_ge pubkey_ge;
    dominterop_secp_v0_10_0_ge r, rp;
    dominterop_secp_v0_10_0_scalar sp;
    dominterop_secp_v0_10_0_scalar sigr;
    dominterop_secp_v0_10_0_ge enckey_ge;
    dominterop_secp_v0_10_0_gej derived_rp;
    dominterop_secp_v0_10_0_scalar sn, u1, u2;
    dominterop_secp_v0_10_0_gej pubkeyj;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(enckey != NULL);

    if (!dominterop_secp_v0_10_0_ecdsa_adaptor_sig_deserialize(&r, &sigr, &rp, &sp, &dleq_proof_e, &dleq_proof_s, adaptor_sig162)) {
        return 0;
    }
    if (!dominterop_secp_v0_10_0_pubkey_load(ctx, &enckey_ge, enckey)) {
        return 0;
    }
    /* DLEQ_verify((R', Y, R), dleq_proof) */
    if(!dominterop_secp_v0_10_0_dleq_verify(&dleq_proof_s, &dleq_proof_e, &rp, &enckey_ge, &r)) {
        return 0;
    }
    dominterop_secp_v0_10_0_scalar_set_b32(&msg, msg32, NULL);
    if (!dominterop_secp_v0_10_0_pubkey_load(ctx, &pubkey_ge, pubkey)) {
        return 0;
    }

    /* return R' == s'⁻¹(m * G + R.x * X) */
    dominterop_secp_v0_10_0_scalar_inverse_var(&sn, &sp);
    dominterop_secp_v0_10_0_scalar_mul(&u1, &sn, &msg);
    dominterop_secp_v0_10_0_scalar_mul(&u2, &sn, &sigr);
    dominterop_secp_v0_10_0_gej_set_ge(&pubkeyj, &pubkey_ge);
    dominterop_secp_v0_10_0_ecmult(&derived_rp, &pubkeyj, &u2, &u1);
    if (dominterop_secp_v0_10_0_gej_is_infinity(&derived_rp)) {
        return 0;
    }
    dominterop_secp_v0_10_0_gej_neg(&derived_rp, &derived_rp);
    dominterop_secp_v0_10_0_gej_add_ge_var(&derived_rp, &derived_rp, &rp, NULL);
    return dominterop_secp_v0_10_0_gej_is_infinity(&derived_rp);
}

int dominterop_secp_v0_10_0_ecdsa_adaptor_decrypt(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_ecdsa_signature *sig, const unsigned char *deckey32, const unsigned char *adaptor_sig162) {
    dominterop_secp_v0_10_0_scalar deckey;
    dominterop_secp_v0_10_0_scalar sp;
    dominterop_secp_v0_10_0_scalar s;
    dominterop_secp_v0_10_0_scalar sigr;
    int overflow;
    int high;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(deckey32 != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);

    dominterop_secp_v0_10_0_scalar_clear(&sp);
    dominterop_secp_v0_10_0_scalar_set_b32(&deckey, deckey32, &overflow);
    ret &= !overflow;
    ret &= dominterop_secp_v0_10_0_ecdsa_adaptor_sig_deserialize(NULL, &sigr, NULL, &sp, NULL, NULL, adaptor_sig162);
    ret &= !dominterop_secp_v0_10_0_scalar_is_zero(&deckey);
    dominterop_secp_v0_10_0_scalar_inverse(&s, &deckey);
    /* s = s' * y⁻¹ */
    dominterop_secp_v0_10_0_scalar_mul(&s, &s, &sp);
    high = dominterop_secp_v0_10_0_scalar_is_high(&s);
    dominterop_secp_v0_10_0_scalar_cond_negate(&s, high);
    dominterop_secp_v0_10_0_ecdsa_signature_save(sig, &sigr, &s);

    dominterop_secp_v0_10_0_memczero(&sig->data[0], 64, !ret);
    dominterop_secp_v0_10_0_scalar_clear(&deckey);
    dominterop_secp_v0_10_0_scalar_clear(&sp);
    dominterop_secp_v0_10_0_scalar_clear(&s);

    return ret;
}

int dominterop_secp_v0_10_0_ecdsa_adaptor_recover(const dominterop_secp_v0_10_0_context* ctx, unsigned char *deckey32, const dominterop_secp_v0_10_0_ecdsa_signature *sig, const unsigned char *adaptor_sig162, const dominterop_secp_v0_10_0_pubkey *enckey) {
    dominterop_secp_v0_10_0_scalar sp, adaptor_sigr;
    dominterop_secp_v0_10_0_scalar s, r;
    dominterop_secp_v0_10_0_scalar deckey;
    dominterop_secp_v0_10_0_ge enckey_expected_ge;
    dominterop_secp_v0_10_0_gej enckey_expected_gej;
    unsigned char enckey33[33];
    unsigned char enckey_expected33[33];
    size_t size = 33;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(dominterop_secp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(deckey32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(enckey != NULL);

    if (!dominterop_secp_v0_10_0_ecdsa_adaptor_sig_deserialize(NULL, &adaptor_sigr, NULL, &sp, NULL, NULL, adaptor_sig162)) {
        return 0;
    }
    dominterop_secp_v0_10_0_ecdsa_signature_load(ctx, &r, &s, sig);
    /* Check that we're not looking at some unrelated signature */
    ret &= dominterop_secp_v0_10_0_scalar_eq(&adaptor_sigr, &r);
    /* y = s⁻¹ * s' */
    ret &= !dominterop_secp_v0_10_0_scalar_is_zero(&s);
    dominterop_secp_v0_10_0_scalar_inverse(&deckey, &s);
    dominterop_secp_v0_10_0_scalar_mul(&deckey, &deckey, &sp);

    /* Deal with ECDSA malleability */
    dominterop_secp_v0_10_0_ecmult_gen(&ctx->ecmult_gen_ctx, &enckey_expected_gej, &deckey);
    dominterop_secp_v0_10_0_ge_set_gej(&enckey_expected_ge, &enckey_expected_gej);
    /* We declassify non-secret enckey_expected_ge to allow using it as a
     * branch point. */
    dominterop_secp_v0_10_0_declassify(ctx, &enckey_expected_ge, sizeof(enckey_expected_ge));
    if (!dominterop_secp_v0_10_0_eckey_pubkey_serialize(&enckey_expected_ge, enckey_expected33, &size, SECP256K1_EC_COMPRESSED)) {
        /* Unreachable from tests (and other VERIFY builds) and therefore this
         * branch should be ignored in test coverage analysis.
         *
         * Proof:
         *     eckey_pubkey_serialize fails <=> deckey = 0
         *     deckey = 0 <=> s^-1 = 0 or sp = 0
         *     case 1: s^-1 = 0 impossible by the definition of multiplicative
         *             inverse and because the scalar_inverse implementation
         *             VERIFY_CHECKs that the inputs are valid scalars.
         *     case 2: sp = 0 impossible because ecdsa_adaptor_sig_deserialize would have already failed
         */
        return 0;
    }
    if (!dominterop_secp_v0_10_0_ec_pubkey_serialize(ctx, enckey33, &size, enckey, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    if (dominterop_secp_v0_10_0_memcmp_var(&enckey_expected33[1], &enckey33[1], 32) != 0) {
        return 0;
    }
    if (enckey_expected33[0] != enckey33[0]) {
        /* try Y_implied == -Y */
        dominterop_secp_v0_10_0_scalar_negate(&deckey, &deckey);
    }
    dominterop_secp_v0_10_0_scalar_get_b32(deckey32, &deckey);

    dominterop_secp_v0_10_0_scalar_clear(&deckey);
    dominterop_secp_v0_10_0_scalar_clear(&sp);
    dominterop_secp_v0_10_0_scalar_clear(&s);

    return ret;
}

#endif
