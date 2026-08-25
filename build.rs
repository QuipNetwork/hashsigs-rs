use sha3::{Digest, Keccak256};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

/// One SHRINCS profile known to the build.
struct ProfileIdentity {
    /// Module name in the generated identity file, matching `src/profiles/`.
    module: &'static str,
    /// Cargo feature that compiles this profile.
    feature_env: &'static str,
    /// Cfg naming this profile as the build's default profile.
    default_cfg: &'static str,
    /// ABI-bearing identity string. `PROFILE_ID` is `keccak256` of this and the
    /// Solidity contracts compare against it: never edit without changing the
    /// contracts in lockstep.
    profile_name: &'static str,
}

/// Every profile, in the fixed priority order that picks the default profile
/// when more than one profile feature is enabled.
const PROFILES: [ProfileIdentity; 4] = [
    ProfileIdentity {
        module: "p256s",
        feature_env: "CARGO_FEATURE_PROFILE_256S",
        default_cfg: "shrincs_default_profile_256s",
        profile_name: "shrincs-256s-keccak",
    },
    ProfileIdentity {
        module: "p256s_sha2",
        feature_env: "CARGO_FEATURE_PROFILE_256S_SHA2",
        default_cfg: "shrincs_default_profile_256s_sha2",
        profile_name: "shrincs-256s-sha2",
    },
    ProfileIdentity {
        module: "p128s_q18",
        feature_env: "CARGO_FEATURE_PROFILE_128S_Q18",
        default_cfg: "shrincs_default_profile_128s_q18",
        profile_name: "shrincs-128s-q18-keccak",
    },
    ProfileIdentity {
        module: "p128s_q20",
        feature_env: "CARGO_FEATURE_PROFILE_128S_Q20",
        default_cfg: "shrincs_default_profile_128s_q20",
        profile_name: "shrincs-128s-q20-keccak",
    },
];

fn feature_enabled(name: &str) -> bool {
    env::var_os(name).is_some()
}

/// The build's default profile: the surfaces that still name exactly one
/// profile (`ShrincsVerifier`, the wasm bindings, the golden-vector tests) bind
/// to it. Every enabled profile compiles regardless; this only picks which one
/// those non-generic surfaces use.
///
/// Exactly one profile feature selects itself. Two or more take the first in
/// `PROFILES` order, which keeps `--all-features` deterministic.
fn default_profile() -> &'static ProfileIdentity {
    PROFILES
        .iter()
        .find(|profile| feature_enabled(profile.feature_env))
        .unwrap_or_else(|| {
            panic!(
                "select a SHRINCS profile feature \
                 (profile-256s, profile-128s-q18, profile-128s-q20, or profile-256s-sha2)"
            )
        })
}

/// A `[u8; 32]` array literal for `keccak256(profile_name)`.
fn profile_id_literal(profile_name: &str) -> String {
    let digest = Keccak256::digest(profile_name.as_bytes());
    let bytes = digest
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{bytes}]")
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for profile in &PROFILES {
        println!("cargo:rerun-if-env-changed={}", profile.feature_env);
        println!("cargo:rustc-check-cfg=cfg({})", profile.default_cfg);
    }

    println!("cargo:rustc-cfg={}", default_profile().default_cfg);

    // Identity for every profile, not just the default one: `PROFILE_ID` is an
    // associated constant of each profile type, so two profiles in one build
    // each carry their own.
    let mut generated = String::new();
    for profile in &PROFILES {
        writeln!(
            generated,
            "pub mod {} {{\n    \
                 pub const PROFILE_NAME: &str = \"{}\";\n    \
                 pub const PROFILE_ID: [u8; 32] = {};\n\
             }}",
            profile.module,
            profile.profile_name,
            profile_id_literal(profile.profile_name),
        )
        .expect("write generated SHRINCS profile identity into a String");
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    fs::write(out_dir.join("shrincs_profile_identities.rs"), generated)
        .expect("write generated SHRINCS profile identity");
}
