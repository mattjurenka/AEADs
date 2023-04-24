#![no_main]
use libfuzzer_sys::fuzz_target;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};

use rand::{rngs::StdRng, SeedableRng};

fuzz_target!(|value: &[u8]| {
    let key = Aes256Gcm::generate_key(&mut StdRng::seed_from_u64(100u64));
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, value.as_ref()).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    assert_eq!(&plaintext, value);
});