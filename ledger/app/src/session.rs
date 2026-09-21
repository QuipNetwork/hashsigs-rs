// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::AppSW;
use alloc::vec::Vec;
use hashsigs_rs::shrincs::ShrincsVerifier;
use hashsigs_rs::{VerifierInterface, VerifyOutcome};

pub const MAX_ENVELOPE: usize = 4096;
struct Upload {
    id: u32,
    commitment: [u8; 32],
    hash: [u8; 32],
    length: usize,
    bytes: Vec<u8>,
}
pub struct VerificationSession {
    next_id: u32,
    upload: Option<Upload>,
}
impl VerificationSession {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            upload: None,
        }
    }
    pub fn begin(&mut self, data: &[u8]) -> Result<[u8; 4], AppSW> {
        if data.len() != 68 {
            return Err(AppSW::BadData);
        }
        if self.upload.is_some() {
            return Err(AppSW::BadState);
        }
        let commitment = data[..32].try_into().map_err(|_| AppSW::BadData)?;
        let hash = data[32..64].try_into().map_err(|_| AppSW::BadData)?;
        let length =
            u32::from_be_bytes(data[64..].try_into().map_err(|_| AppSW::BadData)?) as usize;
        if length == 0 || length > MAX_ENVELOPE {
            return Err(AppSW::BadData);
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(AppSW::BadState)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| AppSW::InternalError)?;
        self.upload = Some(Upload {
            id,
            commitment,
            hash,
            length,
            bytes,
        });
        Ok(id.to_be_bytes())
    }
    pub fn write(&mut self, offset: u16, data: &[u8]) -> Result<[u8; 2], AppSW> {
        let upload = self.upload.as_mut().ok_or(AppSW::BadState)?;
        if data.len() < 5 || data[..4] != upload.id.to_be_bytes() {
            return Err(AppSW::BadData);
        }
        let chunk = &data[4..];
        if offset as usize != upload.bytes.len() || chunk.len() > upload.length - upload.bytes.len()
        {
            return Err(AppSW::BadData);
        }
        upload.bytes.extend_from_slice(chunk);
        Ok((upload.bytes.len() as u16).to_be_bytes())
    }
    pub fn finish(&mut self, data: &[u8]) -> Result<u8, AppSW> {
        let upload = self.upload.as_ref().ok_or(AppSW::BadState)?;
        if data != upload.id.to_be_bytes() {
            return Err(AppSW::BadData);
        }
        if upload.bytes.len() != upload.length {
            return Err(AppSW::BadState);
        }
        // Consume before verification so the request cannot be finalized twice.
        let upload = self.upload.take().ok_or(AppSW::BadState)?;
        Ok(
            match ShrincsVerifier::new().verify(&upload.commitment, &upload.hash, &upload.bytes) {
                VerifyOutcome::Valid => 0,
                VerifyOutcome::Invalid => 1,
                VerifyOutcome::Malformed => 2,
            },
        )
    }
    pub fn cancel(&mut self, data: &[u8]) -> Result<(), AppSW> {
        if !data.is_empty() {
            return Err(AppSW::BadData);
        }
        self.upload = None;
        Ok(())
    }
}
