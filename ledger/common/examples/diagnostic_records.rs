//! PUBLIC test secrets, generated only on the host. Never wallet seed material.
use hashsigs_ledger_common::{diagnostics, keygen_seed, Crypto, Error, CAPACITY};
use hashsigs_rs::profiles::selected::{SelectedProfile, NUM_CHAINS, NUM_LAYERS};
use hashsigs_rs::shrincs::{Keys, ShrincsSigner};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{self, Write};

struct HostCrypto;
impl Crypto for HostCrypto {
    fn hmac(&self, key: &[u8; 32], data: &[u8], out: &mut [u8; 32]) -> Result<(), Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(data);
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }
}

fn main() {
    let seed = keygen_seed(&HostCrypto, &[7; 32], &[9; 32]).unwrap();
    let (keys, _) =
        ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(&seed[..], CAPACITY)
            .unwrap();
    for next in [1u32, 2, 4, 5] {
        let mut public_test_secret = keys.to_bytes();
        // Deliberately simulate advanced counters without enabling signing.
        public_test_secret[132..136].copy_from_slice(&next.to_be_bytes());
        let keys = Keys::from_bytes::<SelectedProfile>(&public_test_secret).unwrap();
        let record = diagnostics::record(&keys, &[9; 32], &HostCrypto, &[7; 32]).unwrap();
        io::stdout().write_all(&record[..]).unwrap();
    }
}
