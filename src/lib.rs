use std::marker::PhantomData;

use librypt_hash::HashFn;
use librypt_kdf::{Kdf, Key};
use librypt_mac::MacFn;
use librypt_mac_hmac::Hmac;

/// HMAC-based Key Derivation Function (HKDF).
pub struct Hkdf<const BLOCK_SIZE: usize, const HASH_SIZE: usize, H: HashFn<BLOCK_SIZE, HASH_SIZE>>(
    PhantomData<H>,
);

impl<const BLOCK_SIZE: usize, const HASH_SIZE: usize, H: HashFn<BLOCK_SIZE, HASH_SIZE>> Kdf
    for Hkdf<BLOCK_SIZE, HASH_SIZE, H>
{
    fn kdf(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) {
        let prk = Hmac::<BLOCK_SIZE, HASH_SIZE, H>::mac(ikm, salt);
        let mut mac = Hmac::<BLOCK_SIZE, HASH_SIZE, H>::new(&prk);

        let mut t = [0u8; HASH_SIZE];
        let mut written = 0;

        let n = (okm.len() / HASH_SIZE) + (okm.len() % HASH_SIZE != 0) as usize;

        for i in 1..n + 1 {
            mac.update(&t);
            mac.update(info);
            mac.update(&[(i as u8)]);

            t = mac.finalize_reset();

            let to_write = if okm.len() - written > HASH_SIZE {
                HASH_SIZE
            } else {
                okm.len() - written
            };

            okm[written..(written + to_write)].copy_from_slice(&t[..to_write]);
            written += to_write;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;
    use librypt_hash_md5::Md5;

    #[test]
    fn test_hkdf() {
        let mut key = [0u8; 32];
        Hkdf::<64, 16, Md5>::kdf(b"test", b"test", b"test", &mut key);

        println!("Key: {}", key.encode_hex::<String>());
    }
}
