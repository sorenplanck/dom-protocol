/***********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SCRATCH_IMPL_H
#define SECP256K1_SCRATCH_IMPL_H

#include "util.h"
#include "scratch.h"

static size_t dominterop_secp_v0_10_0_scratch_checkpoint(const dominterop_secp_v0_10_0_callback* error_callback, const dominterop_secp_v0_10_0_scratch* scratch) {
    if (dominterop_secp_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        dominterop_secp_v0_10_0_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    return scratch->alloc_size;
}

static void dominterop_secp_v0_10_0_scratch_apply_checkpoint(const dominterop_secp_v0_10_0_callback* error_callback, dominterop_secp_v0_10_0_scratch* scratch, size_t checkpoint) {
    if (dominterop_secp_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        dominterop_secp_v0_10_0_callback_call(error_callback, "invalid scratch space");
        return;
    }
    if (checkpoint > scratch->alloc_size) {
        dominterop_secp_v0_10_0_callback_call(error_callback, "invalid checkpoint");
        return;
    }
    scratch->alloc_size = checkpoint;
}

static size_t dominterop_secp_v0_10_0_scratch_max_allocation(const dominterop_secp_v0_10_0_callback* error_callback, const dominterop_secp_v0_10_0_scratch* scratch, size_t objects) {
    if (dominterop_secp_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        dominterop_secp_v0_10_0_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    /* Ensure that multiplication will not wrap around */
    if (ALIGNMENT > 1 && objects > SIZE_MAX/(ALIGNMENT - 1)) {
        return 0;
    }
    if (scratch->max_size - scratch->alloc_size <= objects * (ALIGNMENT - 1)) {
        return 0;
    }
    return scratch->max_size - scratch->alloc_size - objects * (ALIGNMENT - 1);
}

static void *dominterop_secp_v0_10_0_scratch_alloc(const dominterop_secp_v0_10_0_callback* error_callback, dominterop_secp_v0_10_0_scratch* scratch, size_t size) {
    void *ret;
    size_t rounded_size;

    rounded_size = ROUND_TO_ALIGN(size);
    /* Check that rounding did not wrap around */
    if (rounded_size < size) {
        return NULL;
    }
    size = rounded_size;

    if (dominterop_secp_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        dominterop_secp_v0_10_0_callback_call(error_callback, "invalid scratch space");
        return NULL;
    }

    if (size > scratch->max_size - scratch->alloc_size) {
        return NULL;
    }
    ret = (void *) ((char *) scratch->data + scratch->alloc_size);
    memset(ret, 0, size);
    scratch->alloc_size += size;

    return ret;
}

#endif
