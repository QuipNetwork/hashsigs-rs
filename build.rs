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
/// New profiles are appended, never inserted: the order is what `default_profile`
/// falls back to when several profile features are on at once, so inserting one
/// ahead of an existing entry would silently re-point an existing multi-profile
/// build at a different profile.
const PROFILES: [ProfileIdentity; 6] = [
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
        feature_env: "CARGO_FEATURE_EXPERIMENTAL_PROFILE_128S_Q18",
        default_cfg: "shrincs_default_profile_128s_q18",
        profile_name: "shrincs-128s-q18-keccak",
    },
    ProfileIdentity {
        module: "p128s_q20",
        feature_env: "CARGO_FEATURE_EXPERIMENTAL_PROFILE_128S_Q20",
        default_cfg: "shrincs_default_profile_128s_q20",
        profile_name: "shrincs-128s-q20-keccak",
    },
    ProfileIdentity {
        module: "p128s_q18_sha2",
        feature_env: "CARGO_FEATURE_EXPERIMENTAL_PROFILE_128S_Q18_SHA2",
        default_cfg: "shrincs_default_profile_128s_q18_sha2",
        profile_name: "shrincs-128s-q18-sha2",
    },
    ProfileIdentity {
        module: "p128s_q20_sha2",
        feature_env: "CARGO_FEATURE_EXPERIMENTAL_PROFILE_128S_Q20_SHA2",
        default_cfg: "shrincs_default_profile_128s_q20_sha2",
        profile_name: "shrincs-128s-q20-sha2",
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
/// Cargo features are additive, so `--features experimental-profile-128s-q18` leaves the
/// default `profile-256s` enabled too. Picking by priority alone would then bind
/// to 256s and silently test the wrong profile's constants and golden vectors.
/// `default-profile-256s` exists to tell the two cases apart: it is set only
/// when 256s is on because it is the default, never when the user asked for it.
///
/// So: if 256s is merely the default and exactly one other profile is enabled,
/// that profile wins. Otherwise take the first enabled in `PROFILES` order,
/// which covers a lone profile, an explicitly named 256s, and `--all-features`
/// (deterministically 256s). No profile at all is a build error.
fn default_profile() -> &'static ProfileIdentity {
    let is_default_fallback = feature_enabled("CARGO_FEATURE_DEFAULT_PROFILE_256S");

    let mut explicit = PROFILES
        .iter()
        .filter(|profile| profile.module != "p256s" && feature_enabled(profile.feature_env));

    // `next()` twice rather than counting: the override applies only when there
    // is exactly one other profile, so several fall through to priority order.
    if is_default_fallback {
        if let (Some(only), None) = (explicit.next(), explicit.next()) {
            return only;
        }
    }

    PROFILES
        .iter()
        .find(|profile| feature_enabled(profile.feature_env))
        .unwrap_or_else(|| {
            panic!(
                "select a SHRINCS profile feature \
                 (profile-256s, profile-256s-sha2, experimental-profile-128s-q18, \
                  experimental-profile-128s-q20, experimental-profile-128s-q18-sha2, or experimental-profile-128s-q20-sha2)"
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
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEFAULT_PROFILE_256S");
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
