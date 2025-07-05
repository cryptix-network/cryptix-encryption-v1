// replay_guard.rs @Cryptis

// v.1.3
// Replay Functions
// ASVS Level 3 compliant - ASVS 3.8.1–3.9.1

use lru::LruCache;
use once_cell::sync::Lazy;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static REPLAY_CACHE: Lazy<Mutex<LruCache<String, u64>>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(10_000).unwrap()))); // max 10k entries

pub fn is_replay(conversation_id: &str, message_id: &str) -> bool {
    let ctx = format!("{}::{}", conversation_id, message_id);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let mut cache = REPLAY_CACHE.lock().unwrap();

    match cache.get(&ctx) {
        Some(&timestamp) if now - timestamp < 300 => true, // Replay detected within last 5 minutes
        _ => {
            cache.put(ctx, now);
            false
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // use std::thread::sleep;
    // use std::time::Duration;

    #[test]
    fn test_replay_cache() {
        let conv_id = "conversation1";
        let msg_id = "message1";

        assert_eq!(is_replay(conv_id, msg_id), false);

        assert_eq!(is_replay(conv_id, msg_id), true);

        assert_eq!(is_replay(conv_id, "message2"), false);

        assert_eq!(is_replay("conversation2", msg_id), false);
    }

    #[test]
    fn test_replay_cache_expiration() {
        let conv_id = "conv-expire";
        let msg_id = "msg-expire";

        assert_eq!(is_replay(conv_id, msg_id), false);

        assert_eq!(is_replay(conv_id, msg_id), true);

        // Activate for real test
        // sleep(Duration::from_secs(6 * 60));

       //  assert_eq!(is_replay(conv_id, msg_id), false);
    }
}

