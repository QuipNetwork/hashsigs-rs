use sha3::{Digest, Keccak256};
use std::env;
use std::fs;
use std::path::PathBuf;

struct SelectedProfile {
    cfg_name: &'static str,
    profile_name: &'static str,
    /// Scheme-hash suite for this profile. EVM-domain hashes stay on keccak
    /// under every profile; this governs only the scheme hashes.
    hash_suite_sha2: bool,
}

fn feature_enabled(name: &str) -> bool {
    env::var_os(name).is_some()
}

fn selected_profile() -> SelectedProfile {
    let default_profile_256s = feature_enabled("CARGO_FEATURE_DEFAULT_PROFILE_256S");
    let profile_256s = feature_enabled("CARGO_FEATURE_PROFILE_256S");
    let profile_128s_q18 = feature_enabled("CARGO_FEATURE_PROFILE_128S_Q18");
    let profile_128s_q20 = feature_enabled("CARGO_FEATURE_PROFILE_128S_Q20");
    let profile_256s_sha2 = feature_enabled("CARGO_FEATURE_PROFILE_256S_SHA2");

    let explicit_count = usize::from(profile_256s)
        + usize::from(profile_128s_q18)
        + usize::from(profile_128s_q20)
        + usize::from(profile_256s_sha2);

    if explicit_count > 1 {
        panic!(
            "select at most one explicit SHRINCS profile feature \
             (profile-256s, profile-128s-q18, profile-128s-q20, or profile-256s-sha2)"
        );
    }

    if explicit_count == 0 {
        if default_profile_256s {
            return SelectedProfile {
                cfg_name: "shrincs_profile_256s",
                profile_name: "shrincs-256s-keccak",
                hash_suite_sha2: false,
            };
        }
        panic!(
            "select a SHRINCS profile feature \
             (profile-256s, profile-128s-q18, profile-128s-q20, or profile-256s-sha2)"
        );
    }

    match (
        profile_256s,
        profile_128s_q18,
        profile_128s_q20,
        profile_256s_sha2,
    ) {
        (true, false, false, false) => SelectedProfile {
            cfg_name: "shrincs_profile_256s",
            profile_name: "shrincs-256s-keccak",
            hash_suite_sha2: false,
        },
        (false, true, false, false) => SelectedProfile {
            cfg_name: "shrincs_profile_128s_q18",
            profile_name: "shrincs-128s-q18-keccak",
            hash_suite_sha2: false,
        },
        (false, false, true, false) => SelectedProfile {
            cfg_name: "shrincs_profile_128s_q20",
            profile_name: "shrincs-128s-q20-keccak",
            hash_suite_sha2: false,
        },
        (false, false, false, true) => SelectedProfile {
            cfg_name: "shrincs_profile_256s_sha2",
            profile_name: "shrincs-256s-sha2",
            hash_suite_sha2: true,
        },
        _ => unreachable!("explicit profile count already validated"),
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEFAULT_PROFILE_256S");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PROFILE_256S");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PROFILE_128S_Q18");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PROFILE_128S_Q20");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PROFILE_256S_SHA2");

    println!("cargo:rustc-check-cfg=cfg(shrincs_profile_256s)");
    println!("cargo:rustc-check-cfg=cfg(shrincs_profile_128s_q18)");
    println!("cargo:rustc-check-cfg=cfg(shrincs_profile_128s_q20)");
    println!("cargo:rustc-check-cfg=cfg(shrincs_profile_256s_sha2)");
    println!("cargo:rustc-check-cfg=cfg(shrincs_hash_suite_sha2)");

    let selected = selected_profile();
    println!("cargo:rustc-cfg={}", selected.cfg_name);
    if selected.hash_suite_sha2 {
        println!("cargo:rustc-cfg=shrincs_hash_suite_sha2");
    }

    let profile_id = Keccak256::digest(selected.profile_name.as_bytes());

    let profile_id_bytes = profile_id
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");

    let generated = format!(
        "pub const PROFILE_NAME: &str = \"{}\";\n\
         pub const PROFILE_ID: [u8; 32] = [{profile_id_bytes}];\n"
        ,
        selected.profile_name
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    fs::write(out_dir.join("shrincs_profile_identity.rs"), generated)
        .expect("write generated SHRINCS profile identity");
}
