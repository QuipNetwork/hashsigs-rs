// SPDX-License-Identifier: AGPL-3.0-or-later
use hashsigs_ledger_common::{Block, Crypto, Error, Storage};
use ledger_device_sdk::{
    hash::{sha2::Sha2_256, HashInit},
    NVMData,
};

unsafe extern "C" {
    fn wallet_hmac(key: *const u8, data: *const u8, len: u32, out: *mut u8) -> u32;
    fn wallet_nvm_write(dst: *mut u8, src: *const u8) -> u32;
}

pub struct DeviceCrypto;
impl Crypto for DeviceCrypto {
    fn hmac(&self, key: &[u8; 32], data: &[u8], out: &mut [u8; 32]) -> Result<(), Error> {
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
struct Page([u8; 512]);
#[link_section = ".nvm_data"]
static mut DIAG_NVM: NVMData<[Page; 4]> = NVMData::new([
    Page([0; 512]),
    Page([0; 512]),
    Page([0; 512]),
    Page([0; 512]),
]);

pub struct DeviceStorage;
impl DeviceStorage {
    fn address(page: usize) -> *mut u8 {
        assert!(page < 4);
        unsafe {
            let pages = (&mut *core::ptr::addr_of_mut!(DIAG_NVM)).get_mut() as *mut [Page; 4];
            core::ptr::addr_of_mut!((*pages)[page].0).cast()
        }
    }
    pub fn read_page(page: usize) -> [u8; 512] {
        let address = Self::address(page);
        let mut bytes = [0; 512];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = unsafe { core::ptr::read_volatile(address.add(index)) };
        }
        bytes
    }
    pub fn digest(page: usize) -> Result<[u8; 32], Error> {
        let mut out = [0; 32];
        Sha2_256::new()
            .hash(&Self::read_page(page), &mut out)
            .map_err(|_| Error::Crypto)?;
        Ok(out)
    }
    pub fn guards() -> u8 {
        u8::from(Self::read_page(0) == [0x3c; 512])
            | (u8::from(Self::read_page(3) == [0xc3; 512]) << 1)
    }
    pub fn write_page(page: usize, bytes: &[u8; 512]) -> Result<(), Error> {
        // Verify every neighbouring logical block around each completed write.
        // This is NOT proof of physical erase-unit isolation during power loss.
        let mut before = [[0; 32]; 4];
        for (i, digest) in before.iter_mut().enumerate() {
            if i != page {
                *digest = Self::digest(i)?;
            }
        }
        if unsafe { wallet_nvm_write(Self::address(page), bytes.as_ptr()) } != 0 {
            return Err(Error::Storage);
        }
        for (i, digest) in before.iter().enumerate() {
            if i != page && *digest != Self::digest(i)? {
                return Err(Error::Storage);
            }
        }
        Ok(())
    }
}
impl Storage for DeviceStorage {
    fn read(&self, block: Block, out: &mut [u8; 512]) {
        *out = Self::read_page(match block {
            Block::Marker => 1,
            Block::Payload => 2,
        });
    }
    fn write(&mut self, block: Block, bytes: &[u8; 512]) -> Result<(), Error> {
        Self::write_page(
            match block {
                Block::Marker => 1,
                Block::Payload => 2,
            },
            bytes,
        )
    }
}
