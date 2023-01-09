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
    fn kdf<const KEY_SIZE: usize>(km: &[u8], salt: &[u8], info: &[u8]) -> Key<KEY_SIZE> {
        let mut key = [0u8; KEY_SIZE];

        let prk = Hmac::<BLOCK_SIZE, HASH_SIZE, H>::compute(km, salt);

        let mut t = [0u8; HASH_SIZE];
        let mut l = 0;

        for i in 0..(KEY_SIZE / HASH_SIZE) + 1 {
            t = Hmac::<BLOCK_SIZE, HASH_SIZE, H>::compute(&t, &prk);

            for i in t {
                if l >= key.len() {
                    break;
                }

                key[l] = i;
                l += 1;
            }
        }

        key
    }
}
