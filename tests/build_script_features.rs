//! The four profile features must be additive, not mutually exclusive.

#[test]
#[cfg(all(feature = "profile-256s", feature = "profile-128s-q18"))]
fn two_profiles_coexist_in_one_build() {
    use hashsigs_rs::profile::Profile;
    use hashsigs_rs::profiles::{p128s_q18::Profile128sQ18, p256s::Profile256s};

    assert_eq!(Profile256s::NUM_WOTS_CHAINS, 64);
    assert_eq!(Profile128sQ18::NUM_WOTS_CHAINS, 32);
    assert_ne!(Profile256s::PROFILE_NAME, Profile128sQ18::PROFILE_NAME);
}
