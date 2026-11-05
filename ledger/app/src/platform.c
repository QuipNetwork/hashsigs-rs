// SPDX-License-Identifier: AGPL-3.0-or-later
// All throwing OS calls terminate their exception boundary in C, never Rust.
#include "exceptions.h"
#include "cx.h"
#include "os_seed.h"
#include "../../common/platform.c"

#ifndef SHRINCS_APP_LABEL
#define SHRINCS_APP_LABEL "\0quip.network/SHRINCS/v1"
#endif

unsigned int wallet_app_key(unsigned char out[32]) {
    const char label[] = SHRINCS_APP_LABEL;
    // Legacy firewall checks 4 * path_len bytes even for byte-counted SLIP21.
    unsigned int path[sizeof(label) - 1] = {0};
    unsigned char raw[64] = {0};
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
