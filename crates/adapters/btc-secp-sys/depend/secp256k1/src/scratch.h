/***********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SCRATCH_H
#define SECP256K1_SCRATCH_H

/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
typedef struct dominterop_secp_v0_10_0_scratch_space_struct {
    /** guard against interpreting this object as other types */
    unsigned char magic[8];
    /** actual allocated data */
    void *data;
    /** amount that has been allocated (i.e. `data + offset` is the next
     *  available pointer)  */
    size_t alloc_size;
    /** maximum size available to allocate */
    size_t max_size;
} dominterop_secp_v0_10_0_scratch;

static dominterop_secp_v0_10_0_scratch* dominterop_secp_v0_10_0_scratch_create(const dominterop_secp_v0_10_0_callback* error_callback, size_t max_size);

static void dominterop_secp_v0_10_0_scratch_destroy(const dominterop_secp_v0_10_0_callback* error_callback, dominterop_secp_v0_10_0_scratch* scratch);

/** Returns an opaque object used to "checkpoint" a scratch space. Used
 *  with `dominterop_secp_v0_10_0_scratch_apply_checkpoint` to undo allocations. */
static size_t dominterop_secp_v0_10_0_scratch_checkpoint(const dominterop_secp_v0_10_0_callback* error_callback, const dominterop_secp_v0_10_0_scratch* scratch);

/** Applies a check point received from `dominterop_secp_v0_10_0_scratch_checkpoint`,
 *  undoing all allocations since that point. */
static void dominterop_secp_v0_10_0_scratch_apply_checkpoint(const dominterop_secp_v0_10_0_callback* error_callback, dominterop_secp_v0_10_0_scratch* scratch, size_t checkpoint);

/** Returns the maximum allocation the scratch space will allow */
static size_t dominterop_secp_v0_10_0_scratch_max_allocation(const dominterop_secp_v0_10_0_callback* error_callback, const dominterop_secp_v0_10_0_scratch* scratch, size_t n_objects);

/** Returns a pointer into the most recently allocated frame, or NULL if there is insufficient available space */
static void *dominterop_secp_v0_10_0_scratch_alloc(const dominterop_secp_v0_10_0_callback* error_callback, dominterop_secp_v0_10_0_scratch* scratch, size_t n);

#endif
