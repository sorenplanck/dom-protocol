/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_SESSION_H
#define SECP256K1_MODULE_MUSIG_SESSION_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"

#include "../../scalar.h"

typedef struct {
    int fin_nonce_parity;
    unsigned char fin_nonce[32];
    dominterop_secp_v0_10_0_scalar noncecoef;
    dominterop_secp_v0_10_0_scalar challenge;
    dominterop_secp_v0_10_0_scalar s_part;
} dominterop_secp_v0_10_0_musig_session_internal;

static int dominterop_secp_v0_10_0_musig_session_load(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_musig_session_internal *session_i, const dominterop_secp_v0_10_0_musig_session *session);

#endif
