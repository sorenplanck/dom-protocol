/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_ADAPTOR_IMPL_H
#define SECP256K1_MODULE_MUSIG_ADAPTOR_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"

#include "session.h"
#include "../../scalar.h"

int dominterop_secp_v0_10_0_musig_nonce_parity(const dominterop_secp_v0_10_0_context* ctx, int *nonce_parity, const dominterop_secp_v0_10_0_musig_session *session) {
    dominterop_secp_v0_10_0_musig_session_internal session_i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(nonce_parity != NULL);
    ARG_CHECK(session != NULL);

    if (!dominterop_secp_v0_10_0_musig_session_load(ctx, &session_i, session)) {
        return 0;
    }
    *nonce_parity = session_i.fin_nonce_parity;
    return 1;
}

int dominterop_secp_v0_10_0_musig_adapt(const dominterop_secp_v0_10_0_context* ctx, unsigned char *sig64, const unsigned char *pre_sig64, const unsigned char *sec_adaptor32, int nonce_parity) {
    dominterop_secp_v0_10_0_scalar s;
    dominterop_secp_v0_10_0_scalar t;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(nonce_parity == 0 || nonce_parity == 1);

    dominterop_secp_v0_10_0_scalar_set_b32(&s, &pre_sig64[32], &overflow);
    if (overflow) {
        return 0;
    }
    dominterop_secp_v0_10_0_scalar_set_b32(&t, sec_adaptor32, &overflow);
    ret &= !overflow;

    /* Determine if the secret adaptor should be negated.
     *
     * The musig_session stores the X-coordinate and the parity of the "final nonce"
     * (r + t)*G, where r*G is the aggregate public nonce and t is the secret adaptor.
     *
     * Since a BIP340 signature requires an x-only public nonce, in the case where
     * (r + t)*G has odd Y-coordinate (i.e. nonce_parity == 1), the x-only public nonce
     * corresponding to the signature is actually (-r - t)*G. Thus adapting a
     * pre-signature requires negating t in this case.
     */
    if (nonce_parity) {
        dominterop_secp_v0_10_0_scalar_negate(&t, &t);
    }

    dominterop_secp_v0_10_0_scalar_add(&s, &s, &t);
    dominterop_secp_v0_10_0_scalar_get_b32(&sig64[32], &s);
    memmove(sig64, pre_sig64, 32);
    dominterop_secp_v0_10_0_scalar_clear(&t);
    return ret;
}

int dominterop_secp_v0_10_0_musig_extract_adaptor(const dominterop_secp_v0_10_0_context* ctx, unsigned char *sec_adaptor32, const unsigned char *sig64, const unsigned char *pre_sig64, int nonce_parity) {
    dominterop_secp_v0_10_0_scalar t;
    dominterop_secp_v0_10_0_scalar s;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(nonce_parity == 0 || nonce_parity == 1);

    dominterop_secp_v0_10_0_scalar_set_b32(&t, &sig64[32], &overflow);
    ret &= !overflow;
    dominterop_secp_v0_10_0_scalar_negate(&t, &t);

    dominterop_secp_v0_10_0_scalar_set_b32(&s, &pre_sig64[32], &overflow);
    if (overflow) {
        return 0;
    }
    dominterop_secp_v0_10_0_scalar_add(&t, &t, &s);

    if (!nonce_parity) {
        dominterop_secp_v0_10_0_scalar_negate(&t, &t);
    }
    dominterop_secp_v0_10_0_scalar_get_b32(sec_adaptor32, &t);
    dominterop_secp_v0_10_0_scalar_clear(&t);
    return ret;
}

#endif
