// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{env, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    assert!(command.status().expect("run C shim toolchain").success());
}

fn main() {
    println!("cargo:rerun-if-changed=src/platform.c");
    println!("cargo:rerun-if-env-changed=BOLOS_SDK");
    let sdk = PathBuf::from(env::var("BOLOS_SDK").expect("BOLOS_SDK is required"));
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let include = Command::new("arm-none-eabi-gcc")
        .arg("-print-file-name=include")
        .output()
        .unwrap();
    assert!(include.status.success());
    let mut cc = Command::new("clang");
    // Match the pinned secure SDK's Gen5 ABI, including PIC and static base r9.
    cc.args([
        "--target=arm-none-eabi",
        "--sysroot=/usr/lib/arm-none-eabi",
        "-mcpu=cortex-m35p+nodsp",
        "-mthumb",
        "-msoft-float",
        "-mno-unaligned-access",
        "-fropi",
        "-frwpi",
        "-fshort-enums",
        "-funsigned-char",
        "-ffunction-sections",
        "-fdata-sections",
        "-fno-jump-tables",
        "-fstack-protector-strong",
        "-Oz",
        "-std=gnu99",
        "-DHAVE_SHA256",
        "-DHAVE_HASH",
        "-DHAVE_HMAC",
        "-DHAVE_ECC",
        "-DHAVE_ECC_WEIERSTRASS",
        "-DHAVE_SECP256K1_CURVE",
        "-DNATIVE_LITTLE_ENDIAN",
        "-Dgcc",
    ]);
    cc.arg("-I")
        .arg(String::from_utf8(include.stdout).unwrap().trim());
    for path in ["include", "lib_cxng/include", "target/apex_p/include"] {
        cc.arg("-I").arg(sdk.join(path));
    }
    run(cc
        .arg("-c")
        .arg("src/platform.c")
        .arg("-o")
        .arg(out.join("platform.o")));
    run(Command::new("arm-none-eabi-ar")
        .arg("crs")
        .arg(out.join("libwallet_platform.a"))
        .arg(out.join("platform.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=wallet_platform");
}
