/**********************************************************************
 * Copyright (c) 2020 The libsecp256k1-zkp Developers                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECCOMMIT_H
#define SECP256K1_ECCOMMIT_H

/** Helper function to add a 32-byte value to a scalar */
static int dominterop_secp_v0_10_0_ec_seckey_tweak_add_helper(dominterop_secp_v0_10_0_scalar *sec, const unsigned char *tweak);
/** Helper function to add a 32-byte value, times G, to an EC point */
static int dominterop_secp_v0_10_0_ec_pubkey_tweak_add_helper(const dominterop_secp_v0_10_0_ecmult_context* ecmult_ctx, dominterop_secp_v0_10_0_ge *p, const unsigned char *tweak);

/** Serializes elem as a 33 byte array. This is non-constant time with respect to
 *  whether pubp is the point at infinity. Thus, you may need to declassify
 *  pubp->infinity before calling this function. */
static int dominterop_secp_v0_10_0_ec_commit_pubkey_serialize_const(dominterop_secp_v0_10_0_ge *pubp, unsigned char *buf33);
/** Compute an ec commitment tweak as hash(pubkey, data). */
static int dominterop_secp_v0_10_0_ec_commit_tweak(unsigned char *tweak32, dominterop_secp_v0_10_0_ge* pubp, dominterop_secp_v0_10_0_sha256* sha, const unsigned char *data, size_t data_size);
/** Compute an ec commitment as pubkey + hash(pubkey, data)*G. */
static int dominterop_secp_v0_10_0_ec_commit(const dominterop_secp_v0_10_0_ecmult_context* ecmult_ctx, dominterop_secp_v0_10_0_ge* commitp, const dominterop_secp_v0_10_0_ge* pubp, dominterop_secp_v0_10_0_sha256* sha, const unsigned char *data, size_t data_size);
/** Compute a secret key commitment as seckey + hash(pubkey, data). */
static int dominterop_secp_v0_10_0_ec_commit_seckey(const dominterop_secp_v0_10_0_ecmult_gen_context* ecmult_gen_ctx, dominterop_secp_v0_10_0_scalar* seckey, dominterop_secp_v0_10_0_ge* pubp, dominterop_secp_v0_10_0_sha256* sha, const unsigned char *data, size_t data_size);
/** Verify an ec commitment as pubkey + hash(pubkey, data)*G ?= commitment. */
static int dominterop_secp_v0_10_0_ec_commit_verify(const dominterop_secp_v0_10_0_ecmult_context* ecmult_ctx, const dominterop_secp_v0_10_0_ge* commitp, const dominterop_secp_v0_10_0_ge* pubp, dominterop_secp_v0_10_0_sha256* sha, const unsigned char *data, size_t data_size);

#endif /* SECP256K1_ECCOMMIT_H */
