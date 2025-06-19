extern crate hmac;
extern crate sha2;
extern crate base64;
extern crate hex;
extern crate rand;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::Rng;

type HmacSha256 = Hmac<Sha256>;

// Generate a salt by hashing the conversation_id
fn generate_salt(conversation_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(conversation_id.as_bytes());
    hex::encode(hasher.finalize())
}

// Generate a random 16-byte nonce
fn generate_nonce() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);
    nonce
}

// Derive a 32-byte key using HMAC with salt as key, message_id and nonce as input
fn derive_key(message_id: &str, salt: &str, nonce: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(salt.as_bytes()).expect("HMAC needs a key");
    hmac.update(message_id.as_bytes());
    hmac.update(nonce);
    let result = hmac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

// Stream cipher: XOR data with SHA256(key || nonce || counter)
fn stream_cipher(data: &[u8], key: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut counter: u64 = 0;

    for chunk in data.chunks(32) {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(counter.to_be_bytes());

        let keystream = hasher.finalize();
        for (i, &b) in chunk.iter().enumerate() {
            result.push(b ^ keystream[i]);
        }
        counter += 1;
    }

    result
}

// Compute HMAC-SHA256 tag for authentication
fn hmac_auth(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC needs a key");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

// Encrypt input string, returning Base64 encoded (nonce | ciphertext | tag)
fn custom_encrypt(input: &str, conversation_id: &str, message_id: &str) -> String {
    let salt = generate_salt(conversation_id);
    let nonce = generate_nonce();
    let key = derive_key(message_id, &salt, &nonce);

    let plaintext = input.as_bytes();
    let ciphertext = stream_cipher(plaintext, &key, &nonce);
    let tag = hmac_auth(&ciphertext, &key);

    let mut output = Vec::new();
    output.extend_from_slice(&nonce);             // 16-byte nonce
    output.extend_from_slice(&ciphertext);        // encrypted data
    output.extend_from_slice(&tag[..16]);         // first 16 bytes of HMAC tag

    STANDARD.encode(&output)
}

// Decrypt Base64 encoded data, verify HMAC, return plaintext string
fn custom_decrypt(encoded: &str, conversation_id: &str, message_id: &str) -> Result<String, &'static str> {
    let decoded = STANDARD.decode(encoded).map_err(|_| "Invalid base64")?;

    if decoded.len() < 32 {
        return Err("Ciphertext too short");
    }

    let (nonce, rest) = decoded.split_at(16);
    let (ciphertext, tag) = rest.split_at(rest.len() - 16);

    let salt = generate_salt(conversation_id);
    let key = derive_key(message_id, &salt, nonce);
    let expected_tag = hmac_auth(ciphertext, &key);

    if expected_tag[..16] != tag[..] {
        return Err("HMAC verification failed!");
    }

    let decrypted = stream_cipher(ciphertext, &key, nonce);
    String::from_utf8(decrypted).map_err(|_| "UTF-8 error")
}

fn main() {
    let message = "Hello, Cryptix 🔐";
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
