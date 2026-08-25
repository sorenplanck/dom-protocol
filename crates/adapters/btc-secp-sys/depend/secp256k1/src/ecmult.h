/***********************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_H
#define SECP256K1_ECMULT_H

#include "group.h"
#include "scalar.h"
#include "scratch.h"

#ifndef ECMULT_WINDOW_SIZE
#  define ECMULT_WINDOW_SIZE 15
#  ifdef DEBUG_CONFIG
#     pragma message DEBUG_CONFIG_MSG("ECMULT_WINDOW_SIZE undefined, assuming default value")
#  endif
#endif

#ifdef DEBUG_CONFIG
#  pragma message DEBUG_CONFIG_DEF(ECMULT_WINDOW_SIZE)
#endif

/* No one will ever need more than a window size of 24. The code might
 * be correct for larger values of ECMULT_WINDOW_SIZE but this is not
 * tested.
 *
 * The following limitations are known, and there are probably more:
 * If WINDOW_G > 27 and size_t has 32 bits, then the code is incorrect
 * because the size of the memory object that we allocate (in bytes)
 * will not fit in a size_t.
 * If WINDOW_G > 31 and int has 32 bits, then the code is incorrect
 * because certain expressions will overflow.
 */
#if ECMULT_WINDOW_SIZE < 2 || ECMULT_WINDOW_SIZE > 24
#  error Set ECMULT_WINDOW_SIZE to an integer in range [2..24].
#endif

/** The number of entries a table with precomputed multiples needs to have. */
#define ECMULT_TABLE_SIZE(w) (1L << ((w)-2))

/** Double multiply: R = na*A + ng*G */
static void dominterop_secp_v0_10_0_ecmult(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a, const dominterop_secp_v0_10_0_scalar *na, const dominterop_secp_v0_10_0_scalar *ng);

typedef int (dominterop_secp_v0_10_0_ecmult_multi_callback)(dominterop_secp_v0_10_0_scalar *sc, dominterop_secp_v0_10_0_ge *pt, size_t idx, void *data);

/**
 * Multi-multiply: R = inp_g_sc * G + sum_i ni * Ai.
 * Chooses the right algorithm for a given number of points and scratch space
 * size. Resets and overwrites the given scratch space. If the points do not
 * fit in the scratch space the algorithm is repeatedly run with batches of
 * points. If no scratch space is given then a simple algorithm is used that
 * simply multiplies the points with the corresponding scalars and adds them up.
 * Returns: 1 on success (including when inp_g_sc is NULL and n is 0)
 *          0 if there is not enough scratch space for a single point or
 *          callback returns 0
 */
static int dominterop_secp_v0_10_0_ecmult_multi_var(const dominterop_secp_v0_10_0_callback* error_callback, dominterop_secp_v0_10_0_scratch *scratch, dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_scalar *inp_g_sc, dominterop_secp_v0_10_0_ecmult_multi_callback cb, void *cbdata, size_t n);

#endif /* SECP256K1_ECMULT_H */
