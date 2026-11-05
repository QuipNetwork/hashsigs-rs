extern crate std;
use super::*;
use hashsigs_rs::profiles::selected::{NUM_CHAINS, NUM_LAYERS};
use hashsigs_rs::shrincs::ShrincsSigner;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;

struct HostCrypto;
impl Crypto for HostCrypto {
    fn hmac(&self, key: &[u8; 32], data: &[u8], out: &mut [u8; 32]) -> Result<(), Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(data);
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }
}
const APP_KEY: [u8; 32] = [7; 32];
const GENERATION: [u8; 32] = [9; 32];

#[test]
fn cooperative_keygen_preserves_keys_and_yields_for_both_trees() {
    let seed = keygen_seed(&HostCrypto, &APP_KEY, &GENERATION).unwrap();
    let mut leaves = 0usize;
    let (keys, public) = ShrincsSigner::keygen_with_progress::<
        SelectedProfile,
        NUM_CHAINS,
        NUM_LAYERS,
    >(&seed[..], CAPACITY, || leaves += 1)
    .unwrap();
    assert_eq!(leaves, 256 + CAPACITY as usize);
    assert_eq!(
        &*encode(&keys, &GENERATION, &HostCrypto, &APP_KEY).unwrap(),
        fixture()
    );
    assert_eq!(
        public.to_bytes(),
        validate(fixture(), &HostCrypto, &APP_KEY).unwrap().public
    );
    let mut invalid_calls = 0;
    assert!(
        ShrincsSigner::keygen_with_progress::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
            &seed[..],
            0,
            || invalid_calls += 1,
        )
        .is_none()
    );
    assert_eq!(invalid_calls, 0);
}

fn fixture() -> &'static [u8; 512] {
    static RECORD: OnceLock<[u8; 512]> = OnceLock::new();
    RECORD.get_or_init(|| {
        let seed = keygen_seed(&HostCrypto, &APP_KEY, &GENERATION).unwrap();
        let (keys, public) =
            ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(&seed[..], CAPACITY)
                .unwrap();
        let record = encode(&keys, &GENERATION, &HostCrypto, &APP_KEY).unwrap();
        assert_eq!(
            validate(&record, &HostCrypto, &APP_KEY)
                .unwrap()
                .public
                .as_slice(),
            public.to_bytes()
        );
        *record
    })
}
#[derive(Clone)]
struct Memory {
    blocks: [[u8; 512]; 2],
    writes: usize,
    fault: Option<(usize, usize, bool)>,
}
impl Memory {
    fn empty() -> Self {
        Self {
            blocks: [[0; 512]; 2],
            writes: 0,
            fault: None,
        }
    }
    fn committed() -> Self {
        Self {
            blocks: [[0xa5; 512], *fixture()],
            ..Self::empty()
        }
    }
}
impl Storage for Memory {
    fn read(&self, block: Block, out: &mut [u8; 512]) {
        *out = self.blocks[block as usize];
    }
    fn write(&mut self, block: Block, data: &[u8; 512]) -> Result<(), Error> {
        self.writes += 1;
        let (length, fail) = self
            .fault
            .filter(|(n, _, _)| *n == self.writes)
            .map(|(_, len, fail)| (len, fail))
            .unwrap_or((512, false));
        self.blocks[block as usize][..length].copy_from_slice(&data[..length]);
        if fail {
            Err(Error::Storage)
        } else {
            Ok(())
        }
    }
}
fn load(memory: &Memory) -> Wallet {
    Wallet::load(memory, &HostCrypto, &APP_KEY)
}
fn install(wallet: &mut Wallet, memory: &mut Memory) -> Result<(), Error> {
    let keys = Keys::from_bytes::<SelectedProfile>(&fixture()[136..400]).unwrap();
    wallet.install(memory, &HostCrypto, &APP_KEY, &GENERATION, &keys)
}
fn retag(record: &mut [u8; 512]) {
    let generation = record[56..88].try_into().unwrap();
    let key = derive(&HostCrypto, &APP_KEY, &generation, false).unwrap();
    let mut tag = [0; 32];
    HostCrypto.hmac(&key, &record[..480], &mut tag).unwrap();
    record[480..].copy_from_slice(&tag);
}

fn advanced_fixture(next: u32) -> [u8; 512] {
    let mut record = *fixture();
    record[12..20].copy_from_slice(&u64::from(next).to_be_bytes());
    record[124..128].copy_from_slice(&next.to_be_bytes());
    record[268..272].copy_from_slice(&next.to_be_bytes());
    retag(&mut record);
    record
}

#[test]
fn commit_checkpoints_preserve_exact_expected_records() {
    for (source, target) in [(0, 1), (1, 2), (4, 5)] {
        for cut in 0..=9 {
            let mut memory = if source == 0 {
                Memory::empty()
            } else {
                Memory {
                    blocks: [[0xa5; 512], advanced_fixture(source)],
                    ..Memory::empty()
                }
            };
            let before = memory.clone();
            let next = advanced_fixture(target);
            let mut stages = std::vec::Vec::new();
            let result = commit_record(&mut memory, &HostCrypto, &APP_KEY, &next, |stage| {
                stages.push(stage);
                if stage == cut {
                    Err(Error::Storage)
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.is_ok(), cut == 0);
            assert_eq!(
                stages,
                (1..=if cut == 0 { 9 } else { cut }).collect::<std::vec::Vec<_>>()
            );
            let expected = match cut {
                1 => before.blocks,
                2..=4 => [[0; 512], before.blocks[1]],
                5..=7 => [[0; 512], next],
                _ => [[0xa5; 512], next],
            };
            assert_eq!(memory.blocks, expected);
            let loaded = load(&memory);
            let expected_next = match cut {
                1 => source,
                0 | 8 | 9 => target,
                _ => 0,
            };
            if expected_next != 0 {
                assert_eq!(loaded.identity().unwrap().next_leaf, expected_next);
                assert_eq!(
                    loaded.state(),
                    if expected_next == 5 {
                        State::Exhausted
                    } else {
                        State::Ready
                    }
                );
            } else {
                assert_eq!(
                    loaded.state(),
                    if source == 0 && (1..=4).contains(&cut) {
                        State::Empty
                    } else {
                        State::Locked
                    }
                );
            }
        }
    }
}

#[test]
fn interrupted_advancement_never_restores_old_counter_after_invalidation() {
    for (source, target) in [(1, 2), (4, 5)] {
        for write in 1..=3 {
            for prefix in 0..=512 {
                let old = advanced_fixture(source);
                let next = advanced_fixture(target);
                let mut memory = Memory {
                    blocks: [[0xa5; 512], old],
                    fault: Some((write, prefix, true)),
                    ..Memory::empty()
                };
                assert!(
                    commit_record(&mut memory, &HostCrypto, &APP_KEY, &next, |_| Ok(())).is_err()
                );
                let loaded = load(&memory);
                if write == 1 && prefix == 0 {
                    assert_eq!(loaded.identity().unwrap().next_leaf, source);
                } else if write == 3 && prefix == 512 {
                    assert_eq!(loaded.identity().unwrap().next_leaf, target);
                } else {
                    assert_eq!(
                        loaded.state(),
                        State::Locked,
                        "source {source}, write {write}, prefix {prefix}"
                    );
                    assert!(loaded.identity().is_none());
                }
            }
        }
    }
}

#[test]
fn derivation_matches_public_spec_vector() {
    let key: [u8; 32] =
        hex::decode("4f3192b0115669ae19a3022ace6ec54f15a2e06da876e8622ab783f72dacd58e")
            .unwrap()
            .try_into()
            .unwrap();
    let generation = core::array::from_fn(|i| i as u8);
    assert_eq!(
        hex::encode(*keygen_seed(&HostCrypto, &key, &generation).unwrap()),
        "47163ca595dd040f3ad002f79c1581731017177815acb75402d795283d9d8912"
    );
    assert_eq!(
        hex::encode(*derive(&HostCrypto, &key, &generation, false).unwrap()),
        "ffab234a9abf88e459c29f4466540023e8d3faa30c0f9031a1dbc4a8b7d77ee9"
    );
    assert!(keygen_seed(&HostCrypto, &key, &[0; 32]).is_err());
}

#[test]
fn create_reload_and_no_replacement() {
    let mut memory = Memory::empty();
    let mut wallet = load(&memory);
    assert_eq!(wallet.state(), State::Empty);
    assert_eq!(wallet.state_bytes(false), [0; 110]);
    install(&mut wallet, &mut memory).unwrap();
    assert_eq!(memory.writes, 3);
    let reloaded = load(&memory);
    assert_eq!(reloaded.state(), State::Ready);
    assert_eq!(
        reloaded.identity().unwrap().public,
        wallet.identity().unwrap().public
    );
    assert_eq!(reloaded.state_bytes(false), wallet.state_bytes(false));
    assert_eq!(install(&mut wallet, &mut memory), Err(Error::BadState));
    assert_eq!(memory.writes, 3);
    assert_eq!(wallet.state_bytes(true)[89], 1);
    assert_eq!(wallet.state_bytes(true)[90..], [0; 20]);
}

#[test]
fn every_single_byte_corruption_locks() {
    for block in 0..2 {
        for offset in 0..512 {
            let mut memory = Memory::committed();
            memory.blocks[block][offset] ^= 1;
            let wallet = load(&memory);
            assert_eq!(
                wallet.state(),
                State::Locked,
                "block {block}, offset {offset}"
            );
            assert_eq!(wallet.state_bytes(false)[1..], [0; 109]);
        }
    }
}

#[test]
fn wrong_seed_or_generation_cannot_authenticate() {
    assert_eq!(
        Wallet::load(&Memory::committed(), &HostCrypto, &[8; 32]).state(),
        State::Locked
    );
    let mut memory = Memory::committed();
    memory.blocks[1][56] ^= 1;
    assert_eq!(load(&memory).state(), State::Locked);
}

#[test]
fn authenticated_semantic_corruption_is_rejected() {
    // All metadata, duplicated counters/capacity, commitment, and padding are
    // checked independently of the MAC. Secret bytes are never host imports.
    for offset in [
        0, 8, 10, 12, 20, 21, 22, 24, 88, 120, 124, 128, 132, 264, 268, 400, 479,
    ] {
        let mut memory = Memory::committed();
        memory.blocks[1][offset] ^= 1;
        retag(&mut memory.blocks[1]);
        assert_eq!(load(&memory).state(), State::Locked, "offset {offset}");
    }
    for next in [0u32, 6, u32::MAX] {
        let mut memory = Memory::committed();
        memory.blocks[1][12..20].copy_from_slice(&u64::from(next).to_be_bytes());
        memory.blocks[1][124..128].copy_from_slice(&next.to_be_bytes());
        memory.blocks[1][268..272].copy_from_slice(&next.to_be_bytes());
        retag(&mut memory.blocks[1]);
        assert_eq!(load(&memory).state(), State::Locked);
    }
}

#[test]
fn exhaustion_is_preserved() {
    let mut memory = Memory::committed();
    memory.blocks[1][12..20].copy_from_slice(&5u64.to_be_bytes());
    memory.blocks[1][124..128].copy_from_slice(&5u32.to_be_bytes());
    memory.blocks[1][268..272].copy_from_slice(&5u32.to_be_bytes());
    retag(&mut memory.blocks[1]);
    let mut wallet = load(&memory);
    assert_eq!(wallet.state(), State::Exhausted);
    assert_eq!(wallet.identity().unwrap().next_leaf, 5);
    assert_eq!(install(&mut wallet, &mut memory), Err(Error::BadState));
}

#[test]
fn interruption_at_every_write_prefix_never_exposes_partial_identity() {
    for write in 1..=3 {
        for prefix in 0..=512 {
            let mut memory = Memory::empty();
            memory.fault = Some((write, prefix, true));
            let mut wallet = load(&memory);
            assert_eq!(install(&mut wallet, &mut memory), Err(Error::Storage));
            assert_eq!(wallet.state(), State::Locked);
            assert!(wallet.identity().is_none());
            assert_eq!(install(&mut wallet, &mut memory), Err(Error::BadState));
            let reboot = load(&memory);
            let expected = if write == 1 || (write == 2 && prefix == 0) {
                State::Empty
            } else if write == 3 && prefix == 512 {
                State::Ready
            } else {
                State::Locked
            };
            assert_eq!(reboot.state(), expected, "write {write}, prefix {prefix}");
        }
    }
}

#[test]
fn silent_partial_writes_are_caught_by_readback() {
    for write in [2, 3] {
        let mut memory = Memory::empty();
        memory.fault = Some((write, 200, false));
        let mut wallet = load(&memory);
        assert_eq!(install(&mut wallet, &mut memory), Err(Error::Storage));
        assert_eq!(wallet.state(), State::Locked);
        assert_eq!(load(&memory).state(), State::Locked);
    }
}
