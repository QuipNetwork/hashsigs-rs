// SPDX-License-Identifier: AGPL-3.0-or-later
// Expose these curve identifiers to the C probe. The install mask still denies
// EC derivation; these compile-time declarations grant no OS permissions.
#define HAVE_SECP256R1_CURVE
#define HAVE_ED25519_CURVE
#define HAVE_ECC_TWISTED_EDWARDS
#define SHRINCS_APP_LABEL "\0quip.network/SHRINCS/HW-CHECK/v1"
#include "../../app/src/platform.c"

// Fixed probes only. Never return derived bytes, regardless of OS behaviour.
void hardware_probe(unsigned int id, unsigned int *status, unsigned char flags[2]) {
    unsigned int path[40] = {0};
    unsigned char raw[64] = {0};
    unsigned char chain[32] = {0};
    const char allowed[] = SHRINCS_APP_LABEL;
    const char neighbor[] = "\0quip.network/SHRINCS/HW-CHECK/v2";
    const char parent[] = "\0quip.network/SHRINCS";
    const char wallet[] = "\0quip.network/SHRINCS/v1";
    unsigned int mode = HDW_SLIP21;
    cx_curve_t curve = CX_CURVE_SECP256K1;
    unsigned int length = 0;
    const char *label = NULL;
    switch (id) {
        case 0: label = allowed; length = sizeof(allowed) - 1; break;
        case 1: label = neighbor; length = sizeof(neighbor) - 1; break;
        case 2: label = parent; length = sizeof(parent) - 1; break;
        case 3: label = wallet; length = sizeof(wallet) - 1; break;
        case 4: mode = HDW_NORMAL; break;
        case 5: mode = HDW_NORMAL; curve = CX_CURVE_SECP256R1; break;
        case 6: mode = HDW_ED25519_SLIP10; curve = CX_CURVE_Ed25519; break;
        default: *status = CX_INVALID_PARAMETER; flags[0] = 0; flags[1] = 1; return;
    }
    if (label) memcpy(path, label, length);
    else {
        path[0] = 0x8000002c;
        path[1] = id == 6 ? 0x800001f5 : 0x80000000;
        path[2] = 0x80000000;
        path[3] = id == 6 ? 0x80000000 : 0;
        path[4] = 0;
        length = id == 6 ? 4 : 5;
    }
    *status = os_derive_bip32_with_seed_no_throw(mode, curve, path, length, raw,
                                              chain, NULL, 0);
    unsigned char any = 0;
    for (unsigned int i = 0; i < sizeof(raw); i++) any |= raw[i];
    flags[0] = any != 0;
    explicit_bzero(raw, sizeof(raw));
    explicit_bzero(chain, sizeof(chain));
    explicit_bzero(path, sizeof(path));
    any = 0;
    // Volatile reads make the post-erasure diagnostic observation explicit.
    for (unsigned int i = 0; i < sizeof(raw); i++) any |= ((volatile unsigned char *)raw)[i];
    for (unsigned int i = 0; i < sizeof(chain); i++) any |= ((volatile unsigned char *)chain)[i];
    for (unsigned int i = 0; i < sizeof(path); i++) any |= ((volatile unsigned char *)path)[i];
    flags[1] = any == 0;
}
