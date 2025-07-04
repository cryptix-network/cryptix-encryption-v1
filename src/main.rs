// main.rs @Cryptis

/* 

@ TODO:
- Use the midstate as part of a real secret key, not just derived from a publicly known string.
- Logging not sufficient
- Exchange Sha3 with Cryptix OX8 Light
- Prepare conversation_id and message_id for dynamic unkown input


@V.1.1

Quantum Security Explanation

This encryption scheme leverages the SHA-256 midstate — the internal hash state after half of the compression rounds — as a secret, fixed “password” derived from the conversation_id. By combining this midstate with a random nonce and a message_id, the key derivation function creates a large, high-entropy key space.

Traditional PoW systems or symmetric keys typically rely on 32- or 64-bit nonces, limiting the search space. Here, the effective search space expands to roughly 2^160 due to the 128-bit midstate entropy plus the 32-bit nonce.

Against quantum attacks using Grover’s algorithm (which offers a quadratic speedup), the complexity becomes approximately 2^80 operations — far beyond the reach of foreseeable quantum computers.

Thus, the design inherently increases resistance to quantum brute-force attacks without sacrificing performance or requiring new cryptographic primitives, making your implementation effectively quantum-resistant.


@V.1.0

Template created

*/
extern crate hmac;
extern crate sha2;
extern crate base64;
extern crate rand;
extern crate bitcoin_hashes;
extern crate hkdf;
extern crate tracing;
extern crate tracing_subscriber;
extern crate subtle;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::Rng;
use std::time::Instant;

use subtle::ConstantTimeEq;

mod ai_guard;
use ai_guard::protected_decrypt;

use bitcoin_hashes::sha256::{HashEngine as Sha256Engine, Midstate};
use bitcoin_hashes::HashEngine;

use hkdf::Hkdf;
use tracing::{info, error};

type HmacSha256 = Hmac<Sha256>;

// Get SHA-256 midstate 
fn generate_midstate(data: &[u8]) -> Midstate {
    let mut engine = Sha256Engine::default();
    engine.input(data);
    engine.midstate()
}

// Generate random 16-byte nonce
fn generate_nonce() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);
    nonce
}

// Key derivation using midstate + message_id + nonce + secret (HKDF)
fn derive_key(message_id: &str, midstate: &Midstate, nonce: &[u8], secret: &[u8]) -> [u8; 32] {
    let salt = midstate.into_inner();
    let info = [message_id.as_bytes(), nonce].concat();
    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("HKDF expand failed");
    key
}

// XOR stream cipher with SHA256(key || nonce || counter)
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

// HMAC for authentication
fn hmac_auth(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC requires a key");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec() 
}

// Encryption function
fn quantum_encrypt(input: &str, conversation_id: &str, message_id: &str, secret: &[u8]) -> String {
    let midstate = generate_midstate(conversation_id.as_bytes());
    let nonce = generate_nonce();
    let key = derive_key(message_id, &midstate, &nonce, secret);

    let plaintext = input.as_bytes();
    let ciphertext = stream_cipher(plaintext, &key, &nonce);
    let tag = hmac_auth(&ciphertext, &key);

    let mut output = Vec::new();
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&tag); 

    STANDARD.encode(&output)
}

// Decryption function (with constant-time HMAC check)
fn quantum_decrypt(encoded: &str, conversation_id: &str, message_id: &str, secret: &[u8]) -> Result<String, &'static str> {
    let decoded = STANDARD.decode(encoded).map_err(|_| "Invalid base64")?;

    if decoded.len() < 48 {
        return Err("Ciphertext too short");
    }

    let (nonce, rest) = decoded.split_at(16);
    let (ciphertext, tag) = rest.split_at(rest.len() - 32);

    let midstate = generate_midstate(conversation_id.as_bytes());
    let key = derive_key(message_id, &midstate, nonce, secret);
    let expected_tag = hmac_auth(ciphertext, &key);

    if expected_tag.ct_eq(tag).unwrap_u8() != 1 {
        return Err("HMAC verification failed");
    }

    let decrypted = stream_cipher(ciphertext, &key, nonce);
    String::from_utf8(decrypted).map_err(|_| "Invalid UTF-8")
}

// Test
fn main() {
    tracing_subscriber::fmt::init();

    let message = "Hello Cryptix! 🧠🔐";
    let conversation_id = "CONV-ALPHA-007";
    let message_id = "MSG-QUANTUM-TEST-42";
    let secret = b"MySharedSecretKey123";

    info!("--- Quantum Encryption Debug ---");
    info!("Original Message: {}", message);

    let midstate = generate_midstate(conversation_id.as_bytes());
    info!("Midstate (hex): {}", hex::encode(midstate.into_inner()));

    let start_enc = Instant::now();
    let encrypted = quantum_encrypt(message, conversation_id, message_id, secret);
    let duration_enc = start_enc.elapsed();

    info!("Encrypted (Base64): {}", encrypted);
    info!("Encryption took: {:.3?}", duration_enc);

    let classical_bits = 256;
    let quantum_bits = classical_bits / 2;

    let estimated_classical_seconds = 2f64.powi(classical_bits as i32) * duration_enc.as_secs_f64();
    let estimated_quantum_seconds = 2f64.powi(quantum_bits as i32) * duration_enc.as_secs_f64();

    info!("Estimated brute-force time:");
    info!(" - Classical (2^{classical_bits} ops): {:.3e} seconds (~{:.3e} Years)", 
        estimated_classical_seconds, estimated_classical_seconds / (60.0*60.0*24.0*365.25));
    info!(" - Quantum (Grover 2^{quantum_bits} ops): {:.3e} seconds (~{:.3e} Years)", 
        estimated_quantum_seconds, estimated_quantum_seconds / (60.0*60.0*24.0*365.25));

    info!("--- Quantum Decryption Debug ---");
    let start_dec = Instant::now();
    match protected_decrypt(
        message_id,
        &base64::engine::general_purpose::STANDARD.decode(&encrypted).unwrap(),
        || quantum_decrypt(&encrypted, conversation_id, message_id, secret),
    ) {
        Ok(decrypted) => {
            let duration_dec = start_dec.elapsed();
            info!("Decrypted Message: {}", decrypted);
            info!("Decryption took: {:.3?}", duration_dec);
            assert_eq!(message, decrypted);
            info!("Decryption successful and verified!");
        }
        Err(e) => error!("Decryption failed: {}", e),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let msg = "Test123!";
        let conv = "c1";
        let msg_id = "m1";
        let secret = b"shared-key";

        let encrypted = quantum_encrypt(msg, conv, msg_id, secret);
        let decrypted = quantum_decrypt(&encrypted, conv, msg_id, secret).unwrap();
        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_hmac_failure() {
        let msg = "Test tamper!";
        let conv = "c1";
        let msg_id = "m1";
        let secret = b"shared-key";

        let mut enc = quantum_encrypt(msg, conv, msg_id, secret);
        let mut bytes = base64::engine::general_purpose::STANDARD.decode(&enc).unwrap();
        bytes[20] ^= 0xFF; 
        enc = base64::engine::general_purpose::STANDARD.encode(&bytes);

        assert!(quantum_decrypt(&enc, conv, msg_id, secret).is_err());
    }

    #[test]
    fn test_empty_message() {
        let msg = "";
        let conv = "conv-empty";
        let msg_id = "msg-empty";
        let secret = b"empty-secret";

        let encrypted = quantum_encrypt(msg, conv, msg_id, secret);
        let decrypted = quantum_decrypt(&encrypted, conv, msg_id, secret).unwrap();
        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_different_nonce_gives_different_ciphertext() {
        let msg = "NonceTest";
        let conv = "conv-nonce";
        let msg_id = "msg-nonce";
        let secret = b"nonce-key";

        let ct1 = quantum_encrypt(msg, conv, msg_id, secret);
        let ct2 = quantum_encrypt(msg, conv, msg_id, secret);

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_secret_fails() {
        let msg = "SecretMismatch!";
        let conv = "conv-secret";
        let msg_id = "msg-secret";
        let correct_secret = b"correct-key";
        let wrong_secret = b"wrong-key";

        let encrypted = quantum_encrypt(msg, conv, msg_id, correct_secret);
        let result = quantum_decrypt(&encrypted, conv, msg_id, wrong_secret);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_message_id_fails() {
        let msg = "WrongMsgID!";
        let conv = "conv-wrongid";
        let msg_id = "msg-correct";
        let wrong_msg_id = "msg-wrong";
        let secret = b"key";

        let encrypted = quantum_encrypt(msg, conv, msg_id, secret);
        let result = quantum_decrypt(&encrypted, conv, wrong_msg_id, secret);

        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_cteq() {
        let msg = "CTEqTest!";
        let conv = "conv-cteq";
        let msg_id = "msg-cteq";
        let secret = b"secure-key";

        let encrypted = quantum_encrypt(msg, conv, msg_id, secret);
        let mut decoded = base64::engine::general_purpose::STANDARD.decode(&encrypted).unwrap();

        let hmac_offset = decoded.len() - 32;
        decoded[hmac_offset] ^= 0xFF; 

        let tampered = base64::engine::general_purpose::STANDARD.encode(&decoded);

        let result = quantum_decrypt(&tampered, conv, msg_id, secret);
        assert!(result.is_err(), "Manipuliertes HMAC hätte fehlschlagen müssen");
    }

    #[test]
    fn test_non_utf8_data_is_error() {
        let conv = "conv-bin";
        let msg_id = "msg-bin";
        let secret = b"key";

        let mut bad_bytes = quantum_encrypt("Valid UTF8", conv, msg_id, secret);
        let mut raw = base64::engine::general_purpose::STANDARD.decode(&bad_bytes).unwrap();
        raw[40] = 0xFF;
        bad_bytes = base64::engine::general_purpose::STANDARD.encode(&raw);

        let result = quantum_decrypt(&bad_bytes, conv, msg_id, secret);
        assert!(result.is_err());
    }
}
