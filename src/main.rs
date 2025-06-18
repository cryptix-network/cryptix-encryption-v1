extern crate hmac;
extern crate sha2;
extern crate base64;
extern crate hex;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

type HmacSha256 = Hmac<Sha256>;

fn generate_salt(conversation_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(conversation_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn derive_key(message_id: &str, salt: &str) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(salt.as_bytes()).expect("HMAC needs a key");
    hmac.update(message_id.as_bytes());
    let result = hmac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

fn scatter_transform(input: &str, salt: &str) -> Vec<u8> {
    input
        .bytes()
        .enumerate()
        .map(|(i, b)| b.wrapping_add(((i + salt.len()) % 256) as u8))
        .collect()
}

fn reverse_scatter_transform(input: &[u8], salt: &str) -> String {
    let bytes: Vec<u8> = input
        .iter()
        .enumerate()
        .map(|(i, &b)| b.wrapping_sub(((i + salt.len()) % 256) as u8))
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

fn xor_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn xor_decrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    xor_encrypt(data, key) 
}

fn hmac_auth(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC needs a key");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

fn custom_encrypt(input: &str, conversation_id: &str, message_id: &str) -> String {
    let salt = generate_salt(conversation_id);
    let key = derive_key(message_id, &salt);

    let scattered = scatter_transform(input, &salt);
    let encrypted = xor_encrypt(&scattered, &key);

    let tag = hmac_auth(&encrypted, &key); 
    let mut output = encrypted;
    output.extend_from_slice(&tag[..16]); 

    STANDARD.encode(&output)
}

fn custom_decrypt(encoded: &str, conversation_id: &str, message_id: &str) -> Result<String, &'static str> {
    let salt = generate_salt(conversation_id);
    let key = derive_key(message_id, &salt);

    let decoded = STANDARD.decode(encoded).map_err(|_| "Invalid base64")?;

    if decoded.len() < 16 {
        return Err("Ciphertext too short");
    }

    let (ciphertext, tag) = decoded.split_at(decoded.len() - 16);
    let expected_tag = hmac_auth(ciphertext, &key);
    if expected_tag[..16] != tag[..] {
        return Err("HMAC verification failed!");
    }

    let decrypted = xor_decrypt(ciphertext, &key);
    Ok(reverse_scatter_transform(&decrypted, &salt))
}

fn main() {
    let message = "Cryptix Chat 🔒✨";
    let conversation_id = "CONV-001-ALPHA";
    let message_id = "MSG-007"; 

    let encrypted = custom_encrypt(message, conversation_id, message_id);
    println!("Encrypted (Base64): {}", encrypted);

    match custom_decrypt(&encrypted, conversation_id, message_id) {
        Ok(decrypted) => {
            println!("Decrypted: {}", decrypted);
            assert_eq!(message, decrypted);
        }
        Err(e) => println!("Failed to decrypt: {}", e),
    }
}
