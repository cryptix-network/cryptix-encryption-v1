extern crate hmac;
extern crate sha2;
extern crate base64;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest}; 
use base64::engine::general_purpose::STANDARD;  
use base64::Engine;  

fn mod_shift(c: u8, shift: u8) -> u8 {
    ((c as u16 + shift as u16) % 256) as u8
}

fn scatter_transform(input: &str, salt: &str) -> String {
    let mut result = String::new();
    for (i, c) in input.chars().enumerate() {
        let shifted_char = mod_shift(c as u8, (i + salt.len()) as u8);
        result.push(shifted_char as char);
    }
    result
}

fn reverse_scatter_transform(input: &str, salt: &str) -> String {
    let mut result = String::new();
    for (i, c) in input.chars().enumerate() {
        let shift = (i + salt.len()) as u16;
        let unshifted = mod_shift(c as u8, (256 - shift) as u8);
        result.push(unshifted as char);
    }
    result
}

fn derive_key(input: &str, salt: &str) -> u8 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(salt.as_bytes()).expect("HMAC can take key of any size");
    hmac.update(input.as_bytes());
    let result = hmac.finalize();
    let key_bytes = result.into_bytes();
    key_bytes[0]
}

fn generate_salt_for_conversation(conversation_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(conversation_id.as_bytes());
    let result = hasher.finalize(); 
    hex::encode(result)
}

fn custom_encrypt(input: &str, key: u8, salt: &str) -> Vec<u8> {
    let transformed = scatter_transform(input, salt);
    transformed
        .bytes()
        .map(|b| mod_shift(b, key))
        .collect()
}

fn custom_decrypt(input: &[u8], key: u8, salt: &str) -> String {
    let decrypted: Vec<u8> = input
        .iter()
        .map(|b| mod_shift(*b, (256 - key as u16) as u8))
        .collect();
    reverse_scatter_transform(&String::from_utf8_lossy(&decrypted), salt)
}

fn main() {
    let input = "Cryptix is cool!";

    let conversation_id = "CUSTOM_ID_FROM_USERS"; 

    let salt = generate_salt_for_conversation(conversation_id);
    let key = derive_key(input, &salt);

    let encrypted_bytes = custom_encrypt(input, key, &salt);
    let encrypted_b64 = STANDARD.encode(&encrypted_bytes);
    println!("Encrypted (Base64): {}", encrypted_b64);

    let decoded_bytes = STANDARD.decode(&encrypted_b64).unwrap();
    let decrypted = custom_decrypt(&decoded_bytes, key, &salt);
    println!("Decrypted text: {}", decrypted);

    assert_eq!(input, decrypted);
}
