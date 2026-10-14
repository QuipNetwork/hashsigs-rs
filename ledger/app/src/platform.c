// SPDX-License-Identifier: AGPL-3.0-or-later
// All throwing OS calls terminate their exception boundary in C, never Rust.
#include "exceptions.h"
#include "cx.h"
#include "os_seed.h"
#include "os_nvm.h"
#include "lcx_hmac.h"

unsigned int wallet_app_key(unsigned char out[32]) {
    unsigned int path[24] = {0}; // Legacy firewall checks 4 * path_len bytes.
    unsigned char raw[64] = {0};
    const char label[] = "\0quip.network/SHRINCS/v1";
    memcpy(path, label, sizeof(label) - 1);
    cx_err_t error = os_derive_bip32_with_seed_no_throw(
        HDW_SLIP21, CX_CURVE_SECP256K1, path, sizeof(label) - 1, raw, NULL, NULL, 0);
    // The OS returns the symmetric key in the FIRST half of its output.
    if (error == CX_OK) memcpy(out, raw, 32);
    else explicit_bzero(out, 32);
    explicit_bzero(raw, sizeof(raw));
    explicit_bzero(path, sizeof(path));
    return error;
}

unsigned int wallet_hmac(const unsigned char key[32], const unsigned char *data,
                         unsigned int len, unsigned char out[32]) {
    cx_hmac_sha256_t ctx;
    cx_err_t error = cx_hmac_sha256_init_no_throw(&ctx, key, 32);
    if (error == CX_OK) error = cx_hmac_no_throw((cx_hmac_t *)&ctx, CX_LAST, data, len, out, 32);
    explicit_bzero(&ctx, sizeof(ctx));
    if (error != CX_OK) {
        explicit_bzero(out, 32);
        return 1;
    }
    return 0;
}

unsigned int wallet_nvm_write(void *dst, const void *src) {
    volatile unsigned int error = 0;
    BEGIN_TRY {
        TRY { nvm_write(dst, (void *)src, 512); }
        CATCH_OTHER(e) { error = e; }
        FINALLY {}
    } END_TRY;
    return error;
}
