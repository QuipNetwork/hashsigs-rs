// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device-independent protocol-2 derivation and authenticated storage policy.
#![no_std]
extern crate alloc;

use hashsigs_rs::profiles::selected::SelectedProfile;
use hashsigs_rs::shrincs::{Keys, PublicKey, PROFILE_ID};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const CAPACITY: u32 = 4;
pub const STATELESS_LIMIT: u32 = 1 << 20;
pub const PUBLIC_LEN: usize = 480;
pub const RECORD_LEN: usize = 512;
pub const MAX_CHUNK: usize = 200;
pub const SLIP21_LABEL: &[u8] = b"quip.network/SHRINCS/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Crypto,
    Invalid,
    Storage,
    BadState,
}

/// Implementations must check errors and erase secret intermediate contexts.
pub trait Crypto {
    fn hmac(&self, key: &[u8; 32], data: &[u8], out: &mut [u8; 32]) -> Result<(), Error>;
}

fn derive(
    crypto: &impl Crypto,
    app_key: &[u8; 32],
    generation: &[u8; 32],
    keygen: bool,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let label: &[u8] = if keygen {
        b"shrincs-ledger/keygen/v1\0"
    } else {
        b"shrincs-ledger/state-mac/v1\0"
    };
    let mut data = [0u8; 96];
    let len = label.len();
    data[..len].copy_from_slice(label);
    data[len..len + 32].copy_from_slice(&PROFILE_ID);
    data[len + 32..len + 64].copy_from_slice(generation);
    let end = if keygen {
        data[len + 64..len + 68].copy_from_slice(&CAPACITY.to_be_bytes());
        len + 68
    } else {
        len + 64
    };
    let mut result = Zeroizing::new([0; 32]);
    crypto.hmac(app_key, &data[..end], &mut result)?;
    Ok(result)
}

pub fn keygen_seed(
    crypto: &impl Crypto,
    app_key: &[u8; 32],
    generation: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if generation == &[0; 32] {
        return Err(Error::Invalid);
    }
    derive(crypto, app_key, generation, true)
}

#[derive(Clone, Copy)]
pub enum Block {
    Marker,
    Payload,
}

/// Two distinct, erase-unit-aligned blocks. Reads must observe actual NVM.
pub trait Storage {
    fn read(&self, block: Block, out: &mut [u8; RECORD_LEN]);
    fn write(&mut self, block: Block, data: &[u8; RECORD_LEN]) -> Result<(), Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Empty = 0,
    Ready = 1,
    Exhausted = 2,
    Locked = 3,
}

pub struct Identity {
    pub commitment: [u8; 32],
    pub generation: [u8; 32],
    pub next_leaf: u32,
    pub sequence: u64,
    pub public: [u8; PUBLIC_LEN],
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Authenticate before interpreting secret key fields. This intentionally does
/// not re-run tree generation; only records created by this app are accepted.
fn validate(
    record: &[u8; RECORD_LEN],
    crypto: &impl Crypto,
    app_key: &[u8; 32],
) -> Result<Identity, Error> {
    let generation = record[56..88].try_into().unwrap();
    let mac_key = derive(crypto, app_key, &generation, false)?;
    let mut tag = Zeroizing::new([0u8; 32]);
    crypto.hmac(&mac_key, &record[..480], &mut tag)?;
    if !bool::from(tag[..].ct_eq(&record[480..])) {
        return Err(Error::Invalid);
    }
    let sequence = u64::from_be_bytes(record[12..20].try_into().unwrap());
    let next_leaf = u32_at(record, 124);
    if &record[..8] != b"SHRINCS2"
        || record[8..12] != [0, 1, 2, 0]
        || record[20..24] != [1, 1, 0, 0]
        || record[24..56] != PROFILE_ID
        || generation == [0; 32]
        || record[88..120] == [0; 32]
        || u32_at(record, 120) != CAPACITY
        || !(1..=CAPACITY + 1).contains(&next_leaf)
        || sequence != u64::from(next_leaf)
        || u32_at(record, 128) != 0
        || u32_at(record, 132) != STATELESS_LIMIT
        || record[400..480] != [0; 80]
    {
        return Err(Error::Invalid);
    }
    let keys = Keys::from_bytes::<SelectedProfile>(&record[136..400]).ok_or(Error::Invalid)?;
    if keys.stateful().public_key().max_signatures != CAPACITY
        || keys.stateful().next_leaf_index() != next_leaf
        || keys.public_key_commitment().as_bytes()[..] != record[88..120]
    {
        return Err(Error::Invalid);
    }
    let public = PublicKey {
        stateful_public_key: keys.stateful().public_key().to_bytes().to_vec(),
        public_key_commitment: keys.public_key_commitment().as_bytes().to_vec(),
        pk_seed: keys.stateless().public_key.pk_seed.as_bytes().to_vec(),
        hypertree_root: keys.stateless().public_key.root.as_bytes().to_vec(),
    };
    Ok(Identity {
        commitment: *keys.public_key_commitment().as_bytes(),
        generation,
        next_leaf,
        sequence,
        public: public.to_bytes().try_into().map_err(|_| Error::Invalid)?,
    })
}

fn encode(
    keys: &Keys,
    generation: &[u8; 32],
    crypto: &impl Crypto,
    app_key: &[u8; 32],
) -> Result<Zeroizing<[u8; RECORD_LEN]>, Error> {
    let mut record = Zeroizing::new([0; RECORD_LEN]);
    record[..8].copy_from_slice(b"SHRINCS2");
    record[8..12].copy_from_slice(&[0, 1, 2, 0]);
    record[12..20].copy_from_slice(&u64::from(keys.stateful().next_leaf_index()).to_be_bytes());
    record[20..24].copy_from_slice(&[1, 1, 0, 0]);
    record[24..56].copy_from_slice(&PROFILE_ID);
    record[56..88].copy_from_slice(generation);
    record[88..120].copy_from_slice(keys.public_key_commitment().as_bytes());
    record[120..124].copy_from_slice(&CAPACITY.to_be_bytes());
    record[124..128].copy_from_slice(&keys.stateful().next_leaf_index().to_be_bytes());
    record[132..136].copy_from_slice(&STATELESS_LIMIT.to_be_bytes());
    let secret = Zeroizing::new(keys.to_bytes());
    record[136..400].copy_from_slice(&secret[..]);
    let mac_key = derive(crypto, app_key, generation, false)?;
    let mut tag = Zeroizing::new([0; 32]);
    crypto.hmac(&mac_key, &record[..480], &mut tag)?;
    record[480..].copy_from_slice(&tag[..]);
    validate(&record, crypto, app_key)?;
    Ok(record)
}

/// No older-record fallback and no reset/import operation. An ambiguous write
/// locks this instance even when reboot would find a fully committed record.
pub struct Wallet {
    state: State,
    identity: Option<Identity>,
}

impl Wallet {
    pub fn locked() -> Self {
        Self {
            state: State::Locked,
            identity: None,
        }
    }

    pub fn load(storage: &impl Storage, crypto: &impl Crypto, app_key: &[u8; 32]) -> Self {
        let mut marker = [0; RECORD_LEN];
        let mut payload = Zeroizing::new([0; RECORD_LEN]);
        storage.read(Block::Marker, &mut marker);
        storage.read(Block::Payload, &mut payload);
        if marker == [0; RECORD_LEN] && *payload == [0; RECORD_LEN] {
            return Self {
                state: State::Empty,
                identity: None,
            };
        }
        if marker == [0xa5; RECORD_LEN] {
            if let Ok(identity) = validate(&payload, crypto, app_key) {
                return Self {
                    state: if identity.next_leaf > CAPACITY {
                        State::Exhausted
                    } else {
                        State::Ready
                    },
                    identity: Some(identity),
                };
            }
        }
        Self::locked()
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    pub fn install(
        &mut self,
        storage: &mut impl Storage,
        crypto: &impl Crypto,
        app_key: &[u8; 32],
        generation: &[u8; 32],
        keys: &Keys,
    ) -> Result<(), Error> {
        if self.state != State::Empty || keys.stateful().next_leaf_index() != 1 {
            return Err(Error::BadState);
        }
        let record = encode(keys, generation, crypto, app_key)?;
        *self = Self::locked();
        let mut readback = Zeroizing::new([0; RECORD_LEN]);
        for (block, bytes) in [
            (Block::Marker, &[0; RECORD_LEN]),
            (Block::Payload, &*record),
            (Block::Marker, &[0xa5; RECORD_LEN]),
        ] {
            storage.write(block, bytes).map_err(|_| Error::Storage)?;
            storage.read(block, &mut readback);
            if !bool::from(readback[..].ct_eq(bytes)) {
                return Err(Error::Storage);
            }
            if matches!(block, Block::Payload) {
                validate(&readback, crypto, app_key).map_err(|_| Error::Storage)?;
            }
        }
        let loaded = Self::load(storage, crypto, app_key);
        if loaded.state != State::Ready {
            return Err(Error::Storage);
        }
        *self = loaded;
        Ok(())
    }

    pub fn state_bytes(&self, verifying: bool) -> [u8; 110] {
        let mut out = [0; 110];
        out[0] = self.state as u8;
        if let Some(id) = &self.identity {
            out[1..33].copy_from_slice(&id.commitment);
            out[33..65].copy_from_slice(&id.generation);
            out[65..69].copy_from_slice(&CAPACITY.to_be_bytes());
            out[69..73].copy_from_slice(&id.next_leaf.to_be_bytes());
            out[77..81].copy_from_slice(&STATELESS_LIMIT.to_be_bytes());
            out[81..89].copy_from_slice(&id.sequence.to_be_bytes());
        }
        out[89] = u8::from(verifying);
        out
    }
}

#[cfg(test)]
mod tests;
