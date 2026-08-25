/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_CONST_H
#define SECP256K1_ECMULT_CONST_H

#include "scalar.h"
#include "group.h"

/**
 * Multiply: R = q*A (in constant-time for q)
 */
static void dominterop_secp_v0_10_0_ecmult_const(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_ge *a, const dominterop_secp_v0_10_0_scalar *q);

/**
 * Same as dominterop_secp_v0_10_0_ecmult_const, but takes in an x coordinate of the base point
 * only, specified as fraction n/d (numerator/denominator). Only the x coordinate of the result is
 * returned.
 *
 * If known_on_curve is 0, a verification is performed that n/d is a valid X
 * coordinate, and 0 is returned if not. Otherwise, 1 is returned.
 *
 * d being NULL is interpreted as d=1. If non-NULL, d must not be zero. q must not be zero.
 *
 * Constant time in the value of q, but not any other inputs.
 */
static int dominterop_secp_v0_10_0_ecmult_const_xonly(
    dominterop_secp_v0_10_0_fe *r,
    const dominterop_secp_v0_10_0_fe *n,
    const dominterop_secp_v0_10_0_fe *d,
    const dominterop_secp_v0_10_0_scalar *q,
    int known_on_curve
);

#endif /* SECP256K1_ECMULT_CONST_H */
