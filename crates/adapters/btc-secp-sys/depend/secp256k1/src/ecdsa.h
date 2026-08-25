/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECDSA_H
#define SECP256K1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int dominterop_secp_v0_10_0_ecdsa_sig_parse(dominterop_secp_v0_10_0_scalar *r, dominterop_secp_v0_10_0_scalar *s, const unsigned char *sig, size_t size);
static int dominterop_secp_v0_10_0_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const dominterop_secp_v0_10_0_scalar *r, const dominterop_secp_v0_10_0_scalar *s);
static int dominterop_secp_v0_10_0_ecdsa_sig_verify(const dominterop_secp_v0_10_0_scalar* r, const dominterop_secp_v0_10_0_scalar* s, const dominterop_secp_v0_10_0_ge *pubkey, const dominterop_secp_v0_10_0_scalar *message);
static int dominterop_secp_v0_10_0_ecdsa_sig_sign(const dominterop_secp_v0_10_0_ecmult_gen_context *ctx, dominterop_secp_v0_10_0_scalar* r, dominterop_secp_v0_10_0_scalar* s, const dominterop_secp_v0_10_0_scalar *seckey, const dominterop_secp_v0_10_0_scalar *message, const dominterop_secp_v0_10_0_scalar *nonce, int *recid);

#endif /* SECP256K1_ECDSA_H */
