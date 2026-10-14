// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::AppSW;
use hashsigs_ledger_common::{
    self as common, Block, Crypto, Error, State, Storage, Wallet, RECORD_LEN,
};
use hashsigs_rs::profiles::selected::{SelectedProfile, NUM_CHAINS, NUM_LAYERS};
use hashsigs_rs::shrincs::ShrincsSigner;
use ledger_device_sdk::{random::rand_bytes, NVMData};
use zeroize::Zeroizing;

unsafe extern "C" {
    fn wallet_app_key(out: *mut u8) -> u32;
    fn wallet_hmac(key: *const u8, data: *const u8, len: u32, out: *mut u8) -> u32;
    fn wallet_nvm_write(dst: *mut u8, src: *const u8) -> u32;
}

pub struct DeviceCrypto;
impl Crypto for DeviceCrypto {
    fn hmac(&self, key: &[u8; 32], data: &[u8], out: &mut [u8; 32]) -> Result<(), Error> {
        // C validates status and erases its keyed context on every return path.
        if unsafe {
            wallet_hmac(
                key.as_ptr(),
                data.as_ptr(),
                data.len() as u32,
                out.as_mut_ptr(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(Error::Crypto)
        }
    }
}

#[repr(C, align(512))]
struct Page([u8; RECORD_LEN]);
#[repr(C)]
struct Pages {
    marker: Page,
    payload: Page,
}
#[link_section = ".nvm_data"]
static mut WALLET_NVM: NVMData<Pages> = NVMData::new(Pages {
    marker: Page([0; RECORD_LEN]),
    payload: Page([0; RECORD_LEN]),
});

struct DeviceStorage;
impl DeviceStorage {
    fn address(block: Block) -> *mut u8 {
        // NVMData applies the SDK's RWPI/PIC translation. No reference survives
        // the syscall; volatile reads below force actual flash readback.
        unsafe {
            let pages = (&mut *core::ptr::addr_of_mut!(WALLET_NVM)).get_mut() as *mut Pages;
            match block {
                Block::Marker => core::ptr::addr_of_mut!((*pages).marker.0).cast(),
                Block::Payload => core::ptr::addr_of_mut!((*pages).payload.0).cast(),
            }
        }
    }
}
impl Storage for DeviceStorage {
    fn read(&self, block: Block, out: &mut [u8; RECORD_LEN]) {
        let address = Self::address(block);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = unsafe { core::ptr::read_volatile(address.add(i)) };
        }
    }
    fn write(&mut self, block: Block, data: &[u8; RECORD_LEN]) -> Result<(), Error> {
        if unsafe { wallet_nvm_write(Self::address(block), data.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(Error::Storage)
        }
    }
}

pub struct DeviceWallet {
    app_key: Zeroizing<[u8; 32]>,
    pub wallet: Wallet,
    pub boot_nonce: [u8; 16],
}
impl DeviceWallet {
    pub fn new() -> Self {
        let mut app_key = Zeroizing::new([0; 32]);
        let mut boot_nonce = [0; 16];
        rand_bytes(&mut boot_nonce);
        let derived = unsafe { wallet_app_key(app_key.as_mut_ptr()) } == 0 && *app_key != [0; 32];
        let wallet = if derived && boot_nonce != [0; 16] {
            Wallet::load(&DeviceStorage, &DeviceCrypto, &app_key)
        } else {
            Wallet::locked()
        };
        Self {
            app_key,
            wallet,
            boot_nonce,
        }
    }

    pub fn check_create(&self, data: &[u8], verifying: bool) -> Result<(), AppSW> {
        if data.len() != 36 {
            return Err(AppSW::BadData);
        }
        if self.wallet.state() == State::Locked {
            return Err(AppSW::Locked);
        }
        if data[..32] != hashsigs_rs::shrincs::PROFILE_ID
            || data[32..] != common::CAPACITY.to_be_bytes()
        {
            return Err(AppSW::UnsupportedMode);
        }
        if self.wallet.state() != State::Empty || verifying {
            return Err(AppSW::BadState);
        }
        Ok(())
    }

    /// Called only after device approval; no host seed/generation input exists.
    pub fn create(&mut self) -> Result<(), AppSW> {
        let mut generation = [0; 32];
        rand_bytes(&mut generation);
        let seed = common::keygen_seed(&DeviceCrypto, &self.app_key, &generation)
            .map_err(|_| AppSW::InternalError)?;
        // Full hybrid generation, including the real SPHINCS+C hypertree root.
        let (keys, _) = ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
            &seed[..],
            common::CAPACITY,
        )
        .ok_or(AppSW::InternalError)?;
        self.wallet
            .install(
                &mut DeviceStorage,
                &DeviceCrypto,
                &self.app_key,
                &generation,
                &keys,
            )
            .map_err(|error| match error {
                Error::Storage => AppSW::StorageFailure,
                _ => AppSW::InternalError,
            })
    }

    pub fn public_chunk(&self, data: &[u8]) -> Result<([u8; 37], &[u8]), AppSW> {
        if data.len() != 35 {
            return Err(AppSW::BadData);
        }
        let offset = u16::from_be_bytes([data[32], data[33]]) as usize;
        let length = data[34] as usize;
        if length == 0
            || length > common::MAX_CHUNK
            || offset >= common::PUBLIC_LEN
            || offset + length > common::PUBLIC_LEN
        {
            return Err(AppSW::BadData);
        }
        if self.wallet.state() == State::Locked {
            return Err(AppSW::Locked);
        }
        let id = self.wallet.identity().ok_or(AppSW::BadState)?;
        if data[..32] != id.commitment {
            return Err(AppSW::UnknownKey);
        }
        let mut prefix = [0; 37];
        prefix[..32].copy_from_slice(&id.commitment);
        prefix[32..34].copy_from_slice(&(common::PUBLIC_LEN as u16).to_be_bytes());
        prefix[34..36].copy_from_slice(&(offset as u16).to_be_bytes());
        prefix[36] = length as u8;
        Ok((prefix, &id.public[offset..offset + length]))
    }
}
