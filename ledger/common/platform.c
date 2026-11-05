// SPDX-License-Identifier: AGPL-3.0-or-later
// Shared by the wallet and PUBLIC-fixture diagnostics. No seed derivation here.
#include "exceptions.h"
#include "cx.h"
#include "os_nvm.h"
#include "lcx_hmac.h"

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
