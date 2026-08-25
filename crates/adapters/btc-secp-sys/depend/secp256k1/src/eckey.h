/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECKEY_H
#define SECP256K1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int dominterop_secp_v0_10_0_eckey_pubkey_parse(dominterop_secp_v0_10_0_ge *elem, const unsigned char *pub, size_t size);
static int dominterop_secp_v0_10_0_eckey_pubkey_serialize(dominterop_secp_v0_10_0_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int dominterop_secp_v0_10_0_eckey_privkey_tweak_add(dominterop_secp_v0_10_0_scalar *key, const dominterop_secp_v0_10_0_scalar *tweak);
static int dominterop_secp_v0_10_0_eckey_pubkey_tweak_add(dominterop_secp_v0_10_0_ge *key, const dominterop_secp_v0_10_0_scalar *tweak);
static int dominterop_secp_v0_10_0_eckey_privkey_tweak_mul(dominterop_secp_v0_10_0_scalar *key, const dominterop_secp_v0_10_0_scalar *tweak);
static int dominterop_secp_v0_10_0_eckey_pubkey_tweak_mul(dominterop_secp_v0_10_0_ge *key, const dominterop_secp_v0_10_0_scalar *tweak);

#endif /* SECP256K1_ECKEY_H */
