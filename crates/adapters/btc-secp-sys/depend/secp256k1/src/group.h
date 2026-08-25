/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_GROUP_H
#define SECP256K1_GROUP_H

#include "field.h"

/** A group element in affine coordinates on the secp256k1 curve,
 *  or occasionally on an isomorphic curve of the form y^2 = x^3 + 7*t^6.
 *  Note: For exhaustive test mode, secp256k1 is replaced by a small subgroup of a different curve.
 */
typedef struct {
    dominterop_secp_v0_10_0_fe x;
    dominterop_secp_v0_10_0_fe y;
    int infinity; /* whether this represents the point at infinity */
} dominterop_secp_v0_10_0_ge;

#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define SECP256K1_GE_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

/** A group element of the secp256k1 curve, in jacobian coordinates.
 *  Note: For exhastive test mode, secp256k1 is replaced by a small subgroup of a different curve.
 */
typedef struct {
    dominterop_secp_v0_10_0_fe x; /* actual X: x/z^2 */
    dominterop_secp_v0_10_0_fe y; /* actual Y: y/z^3 */
    dominterop_secp_v0_10_0_fe z;
    int infinity; /* whether this represents the point at infinity */
} dominterop_secp_v0_10_0_gej;

#define SECP256K1_GEJ_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), 0}
#define SECP256K1_GEJ_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

typedef struct {
    dominterop_secp_v0_10_0_fe_storage x;
    dominterop_secp_v0_10_0_fe_storage y;
} dominterop_secp_v0_10_0_ge_storage;

#define SECP256K1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

#define SECP256K1_GE_STORAGE_CONST_GET(t) SECP256K1_FE_STORAGE_CONST_GET(t.x), SECP256K1_FE_STORAGE_CONST_GET(t.y)

/** Maximum allowed magnitudes for group element coordinates
 *  in affine (x, y) and jacobian (x, y, z) representation. */
#define SECP256K1_GE_X_MAGNITUDE_MAX  4
#define SECP256K1_GE_Y_MAGNITUDE_MAX  3
#define SECP256K1_GEJ_X_MAGNITUDE_MAX 4
#define SECP256K1_GEJ_Y_MAGNITUDE_MAX 4
#define SECP256K1_GEJ_Z_MAGNITUDE_MAX 1

/** Set a group element equal to the point with given X and Y coordinates */
static void dominterop_secp_v0_10_0_ge_set_xy(dominterop_secp_v0_10_0_ge *r, const dominterop_secp_v0_10_0_fe *x, const dominterop_secp_v0_10_0_fe *y);

/** Set a group element (affine) equal to the point with the given X coordinate
 *  and a Y coordinate that is a quadratic residue modulo p. The return value
 *  is true iff a coordinate with the given X coordinate exists.
 */
static int dominterop_secp_v0_10_0_ge_set_xquad(dominterop_secp_v0_10_0_ge *r, const dominterop_secp_v0_10_0_fe *x);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int dominterop_secp_v0_10_0_ge_set_xo_var(dominterop_secp_v0_10_0_ge *r, const dominterop_secp_v0_10_0_fe *x, int odd);

/** Determine whether x is a valid X coordinate on the curve. */
static int dominterop_secp_v0_10_0_ge_x_on_curve_var(const dominterop_secp_v0_10_0_fe *x);

/** Determine whether fraction xn/xd is a valid X coordinate on the curve (xd != 0). */
static int dominterop_secp_v0_10_0_ge_x_frac_on_curve_var(const dominterop_secp_v0_10_0_fe *xn, const dominterop_secp_v0_10_0_fe *xd);

/** Check whether a group element is the point at infinity. */
static int dominterop_secp_v0_10_0_ge_is_infinity(const dominterop_secp_v0_10_0_ge *a);

/** Check whether a group element is valid (i.e., on the curve). */
static int dominterop_secp_v0_10_0_ge_is_valid_var(const dominterop_secp_v0_10_0_ge *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void dominterop_secp_v0_10_0_ge_neg(dominterop_secp_v0_10_0_ge *r, const dominterop_secp_v0_10_0_ge *a);

/** Set a group element equal to another which is given in jacobian coordinates. Constant time. */
static void dominterop_secp_v0_10_0_ge_set_gej(dominterop_secp_v0_10_0_ge *r, dominterop_secp_v0_10_0_gej *a);

/** Set a group element equal to another which is given in jacobian coordinates. */
static void dominterop_secp_v0_10_0_ge_set_gej_var(dominterop_secp_v0_10_0_ge *r, dominterop_secp_v0_10_0_gej *a);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void dominterop_secp_v0_10_0_ge_set_all_gej_var(dominterop_secp_v0_10_0_ge *r, const dominterop_secp_v0_10_0_gej *a, size_t len);

/** Bring a batch of inputs to the same global z "denominator", based on ratios between
 *  (omitted) z coordinates of adjacent elements.
 *
 *  Although the elements a[i] are _ge rather than _gej, they actually represent elements
 *  in Jacobian coordinates with their z coordinates omitted.
 *
 *  Using the notation z(b) to represent the omitted z coordinate of b, the array zr of
 *  z coordinate ratios must satisfy zr[i] == z(a[i]) / z(a[i-1]) for 0 < 'i' < len.
 *  The zr[0] value is unused.
 *
 *  This function adjusts the coordinates of 'a' in place so that for all 'i', z(a[i]) == z(a[len-1]).
 *  In other words, the initial value of z(a[len-1]) becomes the global z "denominator". Only the
 *  a[i].x and a[i].y coordinates are explicitly modified; the adjustment of the omitted z coordinate is
 *  implicit.
 *
 *  The coordinates of the final element a[len-1] are not changed.
 */
static void dominterop_secp_v0_10_0_ge_table_set_globalz(size_t len, dominterop_secp_v0_10_0_ge *a, const dominterop_secp_v0_10_0_fe *zr);

/** Check two group elements (affine) for equality in variable time. */
static int dominterop_secp_v0_10_0_ge_eq_var(const dominterop_secp_v0_10_0_ge *a, const dominterop_secp_v0_10_0_ge *b);

/** Set a group element (affine) equal to the point at infinity. */
static void dominterop_secp_v0_10_0_ge_set_infinity(dominterop_secp_v0_10_0_ge *r);

/** Set a group element (jacobian) equal to the point at infinity. */
static void dominterop_secp_v0_10_0_gej_set_infinity(dominterop_secp_v0_10_0_gej *r);

/** Set a group element (jacobian) equal to another which is given in affine coordinates. */
static void dominterop_secp_v0_10_0_gej_set_ge(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_ge *a);

/** Check two group elements (jacobian) for equality in variable time. */
static int dominterop_secp_v0_10_0_gej_eq_var(const dominterop_secp_v0_10_0_gej *a, const dominterop_secp_v0_10_0_gej *b);

/** Check two group elements (jacobian and affine) for equality in variable time. */
static int dominterop_secp_v0_10_0_gej_eq_ge_var(const dominterop_secp_v0_10_0_gej *a, const dominterop_secp_v0_10_0_ge *b);

/** Compare the X coordinate of a group element (jacobian).
  * The magnitude of the group element's X coordinate must not exceed 31. */
static int dominterop_secp_v0_10_0_gej_eq_x_var(const dominterop_secp_v0_10_0_fe *x, const dominterop_secp_v0_10_0_gej *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void dominterop_secp_v0_10_0_gej_neg(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a);

/** Check whether a group element is the point at infinity. */
static int dominterop_secp_v0_10_0_gej_is_infinity(const dominterop_secp_v0_10_0_gej *a);

/** Check whether a group element's y coordinate is a quadratic residue. */
static int dominterop_secp_v0_10_0_gej_has_quad_y_var(const dominterop_secp_v0_10_0_gej *a);

/** Set r equal to the double of a. Constant time. */
static void dominterop_secp_v0_10_0_gej_double(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a);

/** Set r equal to the double of a. If rzr is not-NULL this sets *rzr such that r->z == a->z * *rzr (where infinity means an implicit z = 0). */
static void dominterop_secp_v0_10_0_gej_double_var(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a, dominterop_secp_v0_10_0_fe *rzr);

/** Set r equal to the sum of a and b. If rzr is non-NULL this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
static void dominterop_secp_v0_10_0_gej_add_var(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a, const dominterop_secp_v0_10_0_gej *b, dominterop_secp_v0_10_0_fe *rzr);

/** Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity). */
static void dominterop_secp_v0_10_0_gej_add_ge(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a, const dominterop_secp_v0_10_0_ge *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
    than dominterop_secp_v0_10_0_gej_add_var. It is identical to dominterop_secp_v0_10_0_gej_add_ge but without constant-time
    guarantee, and b is allowed to be infinity. If rzr is non-NULL this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
static void dominterop_secp_v0_10_0_gej_add_ge_var(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a, const dominterop_secp_v0_10_0_ge *b, dominterop_secp_v0_10_0_fe *rzr);

/** Set r equal to the sum of a and b (with the inverse of b's Z coordinate passed as bzinv). */
static void dominterop_secp_v0_10_0_gej_add_zinv_var(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a, const dominterop_secp_v0_10_0_ge *b, const dominterop_secp_v0_10_0_fe *bzinv);

/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void dominterop_secp_v0_10_0_ge_mul_lambda(dominterop_secp_v0_10_0_ge *r, const dominterop_secp_v0_10_0_ge *a);

/** Clear a dominterop_secp_v0_10_0_gej to prevent leaking sensitive information. */
static void dominterop_secp_v0_10_0_gej_clear(dominterop_secp_v0_10_0_gej *r);

/** Clear a dominterop_secp_v0_10_0_ge to prevent leaking sensitive information. */
static void dominterop_secp_v0_10_0_ge_clear(dominterop_secp_v0_10_0_ge *r);

/** Convert a group element to the storage type. */
static void dominterop_secp_v0_10_0_ge_to_storage(dominterop_secp_v0_10_0_ge_storage *r, const dominterop_secp_v0_10_0_ge *a);

/** Convert a group element back from the storage type. */
static void dominterop_secp_v0_10_0_ge_from_storage(dominterop_secp_v0_10_0_ge *r, const dominterop_secp_v0_10_0_ge_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void dominterop_secp_v0_10_0_gej_cmov(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_gej *a, int flag);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void dominterop_secp_v0_10_0_ge_storage_cmov(dominterop_secp_v0_10_0_ge_storage *r, const dominterop_secp_v0_10_0_ge_storage *a, int flag);

/** Rescale a jacobian point by b which must be non-zero. Constant-time. */
static void dominterop_secp_v0_10_0_gej_rescale(dominterop_secp_v0_10_0_gej *r, const dominterop_secp_v0_10_0_fe *b);

/** Convert a group element that is not infinity to a 64-byte array. The output
 *  array is platform-dependent. */
static void dominterop_secp_v0_10_0_ge_to_bytes(unsigned char *buf, dominterop_secp_v0_10_0_ge *a);

/** Convert a 64-byte array into group element. This function assumes that the
 *  provided buffer correctly encodes a group element. */
static void dominterop_secp_v0_10_0_ge_from_bytes(dominterop_secp_v0_10_0_ge *r, const unsigned char *buf);

/** Determine if a point (which is assumed to be on the curve) is in the correct (sub)group of the curve.
 *
 * In normal mode, the used group is secp256k1, which has cofactor=1 meaning that every point on the curve is in the
 * group, and this function returns always true.
 *
 * When compiling in exhaustive test mode, a slightly different curve equation is used, leading to a group with a
 * (very) small subgroup, and that subgroup is what is used for all cryptographic operations. In that mode, this
 * function checks whether a point that is on the curve is in fact also in that subgroup.
 */
static int dominterop_secp_v0_10_0_ge_is_in_correct_subgroup(const dominterop_secp_v0_10_0_ge* ge);

/** Check invariants on an affine group element (no-op unless VERIFY is enabled). */
static void dominterop_secp_v0_10_0_ge_verify(const dominterop_secp_v0_10_0_ge *a);
#define SECP256K1_GE_VERIFY(a) dominterop_secp_v0_10_0_ge_verify(a)

/** Check invariants on a Jacobian group element (no-op unless VERIFY is enabled). */
static void dominterop_secp_v0_10_0_gej_verify(const dominterop_secp_v0_10_0_gej *a);
#define SECP256K1_GEJ_VERIFY(a) dominterop_secp_v0_10_0_gej_verify(a)

#endif /* SECP256K1_GROUP_H */
