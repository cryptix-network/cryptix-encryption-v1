// ai_guard.rs @Cryptis

/*
This module provides protective mechanisms for secure message decryption.

It defends against replay attacks, excessive HMAC failures, payload anomalies,
and high message rates to enhance overall decryption security.


 @TODO:
- Memory-Growth: USED_MESSAGE_IDS and FAILED_HMAC_COUNTER grow without limit.
- Mutex Locking: Under very high loads, mutex locks can become a bottleneck.
- Duration calculation: now.duration_since(*t).unwrap_or(Duration::ZERO) can panic when the system time changes.
- Missing rate limiting for HMAC fails
- Naming of context in case of HMAC fail
- Add AI mechanism

*/

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};
use once_cell::sync::Lazy;
use tracing::{warn, error};

static USED_MESSAGE_IDS: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));
static FAILED_HMAC_COUNTER: Lazy<Mutex<HashMap<String, u32>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static DECRYPTION_TIMES: Lazy<Mutex<Vec<Duration>>> = Lazy::new(|| Mutex::new(Vec::new()));
static MESSAGE_TIMESTAMPS: Lazy<Mutex<HashMap<String, Vec<SystemTime>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

const MAX_PAYLOAD_SIZE: usize = 1024;
const HMAC_FAIL_THRESHOLD: u32 = 5;
const ANOMALY_WINDOW_SIZE: usize = 20;
const MAX_MSGS_PER_MIN: usize = 30;

// Replay attack
pub fn check_replay(message_id: &str) -> bool {
    let mut used = USED_MESSAGE_IDS.lock().unwrap();
    if used.contains(message_id) {
        warn!("Replay detected: {}", message_id);
        return true;
    }
    used.insert(message_id.to_string());
    false
}

// Failed HMAC attempt
pub fn register_hmac_fail(context: &str) -> bool {
    let mut fails = FAILED_HMAC_COUNTER.lock().unwrap();
    let count = fails.entry(context.to_string()).or_insert(0);
    *count += 1;
    if *count > HMAC_FAIL_THRESHOLD {
        error!("Too many HMAC failures for {}", context);
        return true;
    }
    false
}

// Decryption duration / anomalies (3x average).
pub fn log_decryption_time(duration: Duration) {
    let mut times = DECRYPTION_TIMES.lock().unwrap();
    times.push(duration);
    if times.len() > ANOMALY_WINDOW_SIZE {
        times.remove(0);
    }

    let avg = times.iter().sum::<Duration>() / times.len() as u32;
    if duration > avg * 3 {
        warn!("Decryption time anomaly: {:?} (avg: {:?})", duration, avg);
    }
}

// Payload size
pub fn payload_anomaly_check(data: &[u8]) -> bool {
    if data.len() > MAX_PAYLOAD_SIZE {
        warn!("Payload too large: {} bytes", data.len());
        return true;
    }
    false
}

// Message rate per conversation
pub fn message_rate_check(conversation_id: &str) -> bool {
    let mut timestamps = MESSAGE_TIMESTAMPS.lock().unwrap();
    let now = SystemTime::now();
    let times = timestamps.entry(conversation_id.to_string()).or_insert_with(Vec::new);
    times.push(now);
    times.retain(|t| now.duration_since(*t).unwrap_or(Duration::ZERO) < Duration::from_secs(60));
    if times.len() > MAX_MSGS_PER_MIN {
        warn!("Message rate too high for {}: {} msgs/min", conversation_id, times.len());
        return true;
    }
    false
}

pub fn protected_decrypt<T>(
    message_id: &str,
    ciphertext: &[u8],
    decrypt_fn: impl FnOnce() -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    if check_replay(message_id) {
        return Err("Replay attack detected");
    }

    if payload_anomaly_check(ciphertext) {
        return Err("Payload anomaly detected");
    }

    let start = Instant::now();
    let result = decrypt_fn();
    let duration = start.elapsed();
    log_decryption_time(duration);

    if message_rate_check(message_id) {
        return Err("Message rate anomaly");
    }

    match &result {
        Err(e) if *e == "HMAC verification failed" => {
            if register_hmac_fail(message_id) {
                return Err("Too many failed attempts");
            }
        }
        _ => {}
    }

    result
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_detection() {
        let id = "msg1";
        assert!(!check_replay(id));
        assert!(check_replay(id));
    }

    #[test]
    fn test_hmac_fail_counter() {
        let ctx = "ctx1";
        for _i in 0..HMAC_FAIL_THRESHOLD {
            assert!(!register_hmac_fail(ctx));
        }
        assert!(register_hmac_fail(ctx));
    }

    #[test]
    fn test_payload_anomaly() {
        let normal_payload = vec![0u8; MAX_PAYLOAD_SIZE];
        assert!(!payload_anomaly_check(&normal_payload));
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(payload_anomaly_check(&large_payload));
    }

    #[test]
    fn test_message_rate_check() {
        let conv_id = "conv1";
        {
            let mut timestamps = MESSAGE_TIMESTAMPS.lock().unwrap();
            timestamps.remove(conv_id);
        }

        for _ in 0..MAX_MSGS_PER_MIN {
            assert!(!message_rate_check(conv_id));
        }

        assert!(message_rate_check(conv_id));
    }

    #[test]
    fn test_protected_decrypt_replay() {
        let id = "msg_replay";
        check_replay(id);

        let result: Result<(), &str> = protected_decrypt(id, b"payload", || Ok(()));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Replay attack detected");
    }

    #[test]
    fn test_protected_decrypt_payload_anomaly() {
        let id = "msg_payload";
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE + 10];

        let result: Result<(), &str> = protected_decrypt(id, &large_payload, || Ok(()));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Payload anomaly detected");
    }
}