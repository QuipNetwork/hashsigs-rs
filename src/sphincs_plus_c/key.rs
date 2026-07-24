// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Structured SPHINCS+C key types.
//!
//! The stateless scheme's keypair, decomposed into the values that are
//! actually secret (`sk_seed`, `prf_seed`) and the values that are public
//! (`pk_seed`, `root`). Each 32-byte role is its own newtype: a public seed
//! can never be passed where a secret one is expected, and the two `pk_seed`s
//! that appear across the SHRINCS hybrid ([`crate::sphincs_plus_c`] vs
//! [`crate::shrincs::uxmss`]) are different types, so they cannot be swapped.
//!
//! This same [`Key`] is embedded as the stateless half of a
//! `shrincs::Keys` (composition, not duplication).
//!
//! Flat byte layout (matching the wasm ABI):
//! `Secret` = `sk_seed(32) ‖ prf_seed(32)` (64 bytes), `PublicKey` =
//! `pk_seed(32) ‖ root(32)` (64 bytes), `Key` = `Secret ‖ PublicKey`
//! (128 bytes).

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::primitives::hash::word32;
use crate::types::HASH_LEN;

/// Secret `SK.seed` material: derives FORS-C and hypertree WOTS-C secrets.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SkSeed([u8; HASH_LEN]);

/// Secret `SK.prf` material: derives stateless message randomizers.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrfSeed([u8; HASH_LEN]);

/// Public seed used in FORS-C, hypertree WOTS-C, and Merkle node hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PkSeed([u8; HASH_LEN]);

/// Top hypertree root committed in the public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root([u8; HASH_LEN]);

impl SkSeed {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Wrap a slice, returning `None` for any length other than 32.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(word32(bytes)?))
    }
    /// Borrow the raw bytes for hashing.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl PrfSeed {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Wrap a slice, returning `None` for any length other than 32.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(word32(bytes)?))
    }
    /// Borrow the raw bytes for hashing.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl PkSeed {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Wrap a slice, returning `None` for any length other than 32.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(word32(bytes)?))
    }
    /// Borrow the raw bytes for hashing.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl Root {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Wrap a slice, returning `None` for any length other than 32.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(word32(bytes)?))
    }
    /// Borrow the raw bytes for hashing.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

// Secret newtypes redact their bytes so seeds never reach logs or telemetry.
impl fmt::Debug for SkSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SkSeed(<redacted>)")
    }
}

impl fmt::Debug for PrfSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrfSeed(<redacted>)")
    }
}

/// The secret half of a SPHINCS+C key: the 64 bytes that are actually secret.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    /// Derives FORS-C and hypertree WOTS-C secrets.
    pub sk_seed: SkSeed,
    /// Derives stateless message randomizers.
    pub prf_seed: PrfSeed,
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("sk_seed", &"<redacted>")
            .field("prf_seed", &"<redacted>")
            .finish()
    }
}

/// The public half of a SPHINCS+C key: `pk_seed ‖ root`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// Global public seed used in FORS-C, hypertree WOTS-C, and Merkle hashing.
    pub pk_seed: PkSeed,
    /// Top hypertree root committed in the public key.
    pub root: Root,
}

/// A full SPHINCS+C keypair: the stateless scheme, and the stateless half of
/// a SHRINCS key.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    /// Secret seeds.
    pub secret: Secret,
    /// Public seed and root.
    pub public_key: PublicKey,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("secret", &self.secret)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Secret {
    /// Flat layout `sk_seed(32) ‖ prf_seed(32)`, 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..HASH_LEN].copy_from_slice(self.sk_seed.as_bytes());
        out[HASH_LEN..].copy_from_slice(self.prf_seed.as_bytes());
        out
    }
    /// Parse the 64-byte flat layout; `None` on wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        Some(Self {
            sk_seed: SkSeed::from_slice(bytes.get(..HASH_LEN)?)?,
            prf_seed: PrfSeed::from_slice(bytes.get(HASH_LEN..)?)?,
        })
    }
}

impl PublicKey {
    /// Flat layout `pk_seed(32) ‖ root(32)`, 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..HASH_LEN].copy_from_slice(self.pk_seed.as_bytes());
        out[HASH_LEN..].copy_from_slice(self.root.as_bytes());
        out
    }
    /// Parse the 64-byte flat layout; `None` on wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        Some(Self {
            pk_seed: PkSeed::from_slice(bytes.get(..HASH_LEN)?)?,
            root: Root::from_slice(bytes.get(HASH_LEN..)?)?,
        })
    }

    /// Build from two 32-byte slices `pk_seed` and `root`; `None` on wrong
    /// length. (`root` is the hypertree root.)
    pub fn from_slices(pk_seed: &[u8], root: &[u8]) -> Option<Self> {
        Some(Self {
            pk_seed: PkSeed::from_slice(pk_seed)?,
            root: Root::from_slice(root)?,
        })
    }
}

impl Key {
    /// Flat layout `Secret(64) ‖ PublicKey(64)`, 128 bytes — the SPHINCS+C
    /// `secretKey` bytes exactly.
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[..64].copy_from_slice(&self.secret.to_bytes());
        out[64..].copy_from_slice(&self.public_key.to_bytes());
        out
    }
    /// Parse the 128-byte flat layout; `None` on wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 128 {
            return None;
        }
        Some(Self {
            secret: Secret::from_bytes(bytes.get(..64)?)?,
            public_key: PublicKey::from_bytes(bytes.get(64..)?)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> Key {
        Key {
            secret: Secret {
                sk_seed: SkSeed::new([1u8; HASH_LEN]),
                prf_seed: PrfSeed::new([2u8; HASH_LEN]),
            },
            public_key: PublicKey {
                pk_seed: PkSeed::new([3u8; HASH_LEN]),
                root: Root::new([4u8; HASH_LEN]),
            },
        }
    }

    #[test]
    fn key_bytes_round_trip() {
        let key = sample_key();
        let bytes = key.to_bytes();
        assert_eq!(Key::from_bytes(&bytes), Some(key));
    }

    #[test]
    fn secret_and_public_split_at_64() {
        let key = sample_key();
        let bytes = key.to_bytes();
        assert_eq!(&key.secret.to_bytes(), &bytes[..64]);
        assert_eq!(&key.public_key.to_bytes(), &bytes[64..]);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert_eq!(Key::from_bytes(&[0u8; 127]), None);
        assert_eq!(Secret::from_bytes(&[0u8; 63]), None);
        assert_eq!(PublicKey::from_bytes(&[0u8; 65]), None);
    }

    #[test]
    fn secret_debug_is_redacted() {
        let key = sample_key();
        let shown = alloc::format!("{:?}", key.secret);
        assert!(!shown.contains("01"));
        assert!(shown.contains("redacted"));
    }
}
