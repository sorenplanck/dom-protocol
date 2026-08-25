/* C1a driver (Annex M M.11.1).
 *
 * Runs the PINNED upstream secp256k1-zkp test suite — unmodified — which
 * embeds the official BIP327 vector families in
 * src/modules/musig/vectors.h (auto-generated upstream from the vectors
 * published with BIP327): key aggregation (valid + error), nonce
 * generation, nonce aggregation, sign/verify (via the upstream
 * secnonce-loading test helper), tweaks and signature aggregation.
 *
 * Nothing here adapts, filters or reorders a vector: the vector-running
 * functions are upstream's own, compiled from the vendored pin.
 *
 * The only additions live BELOW the include and exist because the
 * vendored production tree strips the malloc-based convenience API
 * (context_create/clone/destroy, scratch_space_*) that tests.c calls:
 * they are reinstated here, equivalent to upstream's definitions, backed
 * by the preallocated API that IS compiled. This file is part of a
 * dev-only conformance crate and is never linked into production.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "../include/secp256k1.h"
#include "util.h"

/* The vendor tarball strips both the definitions AND the declarations of
 * the malloc-based convenience API; tests.c still calls it. Declare the
 * prototypes first so the calls type-check, then define them after the
 * include (equivalent to upstream's own definitions). */
typedef struct dominterop_secp_v0_10_0_scratch_space_struct dominterop_secp_v0_10_0_scratch_space;

/* util.h at the pin also lost the checked_malloc definition (stripped by
 * the vendor together with every malloc path). Reinstated verbatim from
 * upstream for this test TU. */
static void *checked_malloc(const dominterop_secp_v0_10_0_callback* cb, size_t size) {
    void *ret = malloc(size);
    if (ret == NULL) {
        dominterop_secp_v0_10_0_callback_call(cb, "Out of memory");
    }
    return ret;
}
dominterop_secp_v0_10_0_context* dominterop_secp_v0_10_0_context_create(unsigned int flags);
dominterop_secp_v0_10_0_context* dominterop_secp_v0_10_0_context_clone(const dominterop_secp_v0_10_0_context* ctx);
void dominterop_secp_v0_10_0_context_destroy(dominterop_secp_v0_10_0_context* ctx);
dominterop_secp_v0_10_0_scratch_space* dominterop_secp_v0_10_0_scratch_space_create(const dominterop_secp_v0_10_0_context* ctx, size_t max_size);
void dominterop_secp_v0_10_0_scratch_space_destroy(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_scratch_space* scratch);

#define main dominterop_c1a_upstream_tests_main
#include "tests.c"
#undef main

/* These three are reinstated VERBATIM from upstream secp256k1.c at the
 * pin (only the symbol prefix differs, matching the vendored tree). The
 * exact bodies matter: the upstream test suite asserts on the precise
 * illegal-callback firing behaviour (e.g. context_clone must ARG_CHECK
 * is_proper BEFORE sizing, so a static context fires the callback exactly
 * once). ARG_CHECK, default_error_callback, secp256k1_context_is_proper
 * and EXPECT are all in scope from the included tests.c/secp256k1.c. */
dominterop_secp_v0_10_0_context* dominterop_secp_v0_10_0_context_create(unsigned int flags) {
    size_t const prealloc_size = dominterop_secp_v0_10_0_context_preallocated_size(flags);
    dominterop_secp_v0_10_0_context* ctx = (dominterop_secp_v0_10_0_context*)checked_malloc(&default_error_callback, prealloc_size);
    if (EXPECT(dominterop_secp_v0_10_0_context_preallocated_create(ctx, flags) == NULL, 0)) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

dominterop_secp_v0_10_0_context* dominterop_secp_v0_10_0_context_clone(const dominterop_secp_v0_10_0_context* ctx) {
    dominterop_secp_v0_10_0_context* ret;
    size_t prealloc_size;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(dominterop_secp_v0_10_0_context_is_proper(ctx));

    prealloc_size = dominterop_secp_v0_10_0_context_preallocated_clone_size(ctx);
    ret = (dominterop_secp_v0_10_0_context*)checked_malloc(&ctx->error_callback, prealloc_size);
    ret = dominterop_secp_v0_10_0_context_preallocated_clone(ctx, ret);
    return ret;
}

void dominterop_secp_v0_10_0_context_destroy(dominterop_secp_v0_10_0_context* ctx) {
    ARG_CHECK_VOID(ctx == NULL || dominterop_secp_v0_10_0_context_is_proper(ctx));

    if (ctx == NULL) {
        return;
    }
    dominterop_secp_v0_10_0_context_preallocated_destroy(ctx);
    free(ctx);
}

/* scratch_impl.h at the pin lost these two static definitions (declared
 * in scratch.h, stripped with the malloc paths). Reinstated verbatim
 * from upstream. */
static dominterop_secp_v0_10_0_scratch* dominterop_secp_v0_10_0_scratch_create(const dominterop_secp_v0_10_0_callback* error_callback, size_t size) {
    const size_t base_alloc = ROUND_TO_ALIGN(sizeof(dominterop_secp_v0_10_0_scratch));
    void *alloc = checked_malloc(error_callback, base_alloc + size);
    dominterop_secp_v0_10_0_scratch* ret = (dominterop_secp_v0_10_0_scratch *)alloc;
    if (ret != NULL) {
        memset(ret, 0, sizeof(*ret));
        memcpy(ret->magic, "scratch", 8);
        ret->data = (void *) ((char *) alloc + base_alloc);
        ret->max_size = size;
    }
    return ret;
}

static void dominterop_secp_v0_10_0_scratch_destroy(const dominterop_secp_v0_10_0_callback* error_callback, dominterop_secp_v0_10_0_scratch* scratch) {
    if (scratch != NULL) {
        if (dominterop_secp_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
            dominterop_secp_v0_10_0_callback_call(error_callback, "invalid scratch space");
            return;
        }
        VERIFY_CHECK(scratch->alloc_size == 0);
        memset(scratch->magic, 0, sizeof(scratch->magic));
        free(scratch);
    }
}

dominterop_secp_v0_10_0_scratch_space* dominterop_secp_v0_10_0_scratch_space_create(const dominterop_secp_v0_10_0_context* ctx, size_t max_size) {
    VERIFY_CHECK(ctx != NULL);
    return dominterop_secp_v0_10_0_scratch_create(&ctx->error_callback, max_size);
}

void dominterop_secp_v0_10_0_scratch_space_destroy(const dominterop_secp_v0_10_0_context* ctx, dominterop_secp_v0_10_0_scratch_space* scratch) {
    VERIFY_CHECK(ctx != NULL);
    dominterop_secp_v0_10_0_scratch_destroy(&ctx->error_callback, scratch);
}

/* ── C1b shims (Annex M M.11.2) ──────────────────────────────────────────
 *
 * C1b freezes the two distinct semantics of a tagged-hash integer ≥ n.
 * The natural probability of that event is ~2^-128, so the harness
 * injects the post-hash integer directly (it does not implement SHA-256).
 *
 * Shim 1 exposes the library's scalar interpretation — scalar_set_b32 —
 * which is exactly what the KeyAgg coefficient uses: an integer ≥ n is
 * REDUCED modulo n (with the overflow reported), never rejected.
 *
 * The opposite semantic — TapTweak ≥ n must FAIL, never reduce — is
 * proved through the public tweak APIs, whose tweak32 argument IS the
 * injection point (the caller computes the tagged hash and passes it).
 * That path needs no shim and is exercised from the Rust tests.
 */

int dominterop_c1b_scalar_set_b32_semantics(const unsigned char *in32, unsigned char *out32) {
    dominterop_secp_v0_10_0_scalar s;
    int overflow = 0;
    dominterop_secp_v0_10_0_scalar_set_b32(&s, in32, &overflow);
    dominterop_secp_v0_10_0_scalar_get_b32(out32, &s);
    return overflow;
}

/* xonly tweak-add rejection probe: returns the C API result (1 success,
 * 0 failure) for tweaking the generator-based pubkey below with tweak32.
 * Used by C1b to prove tweak ≥ n fails closed at the exact boundary the
 * production wrapper calls. */
int dominterop_c1b_xonly_tweak_add_accepts(const unsigned char *tweak32) {
    unsigned char seckey[32] = {0};
    dominterop_secp_v0_10_0_keypair keypair;
    dominterop_secp_v0_10_0_xonly_pubkey base;
    dominterop_secp_v0_10_0_pubkey out;
    seckey[31] = 42;
    CHECK(dominterop_secp_v0_10_0_keypair_create(CTX, &keypair, seckey));
    CHECK(dominterop_secp_v0_10_0_keypair_xonly_pub(CTX, &base, NULL, &keypair));
    return dominterop_secp_v0_10_0_xonly_pubkey_tweak_add(CTX, &out, &base, tweak32);
}

/* Minimal environment for the C1b probes when the full suite has not
 * run in this process: creates the global CTX once. */
int dominterop_c1b_init(void) {
    if (CTX == NULL) {
        CTX = dominterop_secp_v0_10_0_context_create(SECP256K1_CONTEXT_NONE);
    }
    return CTX != NULL;
}
