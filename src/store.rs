use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::crypto::Pkce;
use crate::util::ResponseMode;

/// Expired entries are swept at most this often.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct Entries<V> {
    map: HashMap<String, (V, Instant)>,
    last_sweep: Instant,
}

impl<V> Entries<V> {
    /// Drops expired entries, but only once per `SWEEP_INTERVAL`, so the cost is
    /// amortized over many calls instead of paid on every one.
    fn sweep_if_due(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) >= SWEEP_INTERVAL {
            self.map.retain(|_, (_, expires)| *expires > now);
            self.last_sweep = now;
        }
    }
}

/// In-memory map whose entries expire. Expired entries are never returned, and
/// are freed by a periodic sweep that piggybacks on normal use.
pub struct TtlMap<V> {
    entries: Mutex<Entries<V>>,
}

impl<V> Default for TtlMap<V> {
    fn default() -> Self {
        TtlMap {
            entries: Mutex::new(Entries {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }
}

impl<V: Clone> TtlMap<V> {
    fn lock(&self, now: Instant) -> MutexGuard<'_, Entries<V>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.sweep_if_due(now);
        entries
    }

    pub fn insert(&self, key: String, value: V, ttl: Duration) {
        let now = Instant::now();
        self.lock(now).map.insert(key, (value, now + ttl));
    }

    pub fn get(&self, key: &str) -> Option<V> {
        let now = Instant::now();
        self.lock(now)
            .map
            .get(key)
            .filter(|(_, expires)| *expires > now)
            .map(|(value, _)| value.clone())
    }

    /// Removes the entry and returns it if it was still valid.
    pub fn take(&self, key: &str) -> Option<V> {
        let now = Instant::now();
        self.lock(now)
            .map
            .remove(key)
            .filter(|(_, expires)| *expires > now)
            .map(|(value, _)| value)
    }
}

/// An authorization request waiting for the user to pick an account.
#[derive(Debug, Clone)]
pub struct LoginSession {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub pkce: Option<Pkce>,
    pub response_mode: ResponseMode,
    pub login_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub pkce: Option<Pkce>,
    pub auth_time: i64,
}

#[derive(Debug, Clone)]
pub struct AccessGrant {
    pub client_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshGrant {
    pub client_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub auth_time: i64,
}

#[derive(Default)]
pub struct Stores {
    pub sessions: TtlMap<LoginSession>,
    pub codes: TtlMap<AuthCode>,
    pub access_tokens: TtlMap<AccessGrant>,
    pub refresh_tokens: TtlMap<RefreshGrant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(last_sweep: Instant) -> Entries<u8> {
        let now = Instant::now();
        let mut map = HashMap::new();
        map.insert("expired".to_string(), (1, now - Duration::from_secs(1)));
        map.insert("live".to_string(), (2, now + Duration::from_secs(60)));
        Entries { map, last_sweep }
    }

    #[test]
    fn sweeping_is_amortized() {
        let now = Instant::now();
        let mut recent = entries(now);
        recent.sweep_if_due(now);
        assert_eq!(recent.map.len(), 2, "no sweep inside the interval");

        let mut due = entries(now - SWEEP_INTERVAL - Duration::from_secs(1));
        due.sweep_if_due(now);
        assert_eq!(due.map.len(), 1);
        assert!(due.map.contains_key("live"));
        assert_eq!(due.last_sweep, now);
    }

    #[test]
    fn expired_entries_are_never_returned() {
        let map = TtlMap::<u8>::default();
        map.insert("a".into(), 1, Duration::ZERO);
        map.insert("b".into(), 2, Duration::from_secs(60));
        assert_eq!(map.get("a"), None);
        assert_eq!(map.take("a"), None);
        assert_eq!(map.take("b"), Some(2));
        assert_eq!(map.take("b"), None);
    }
}
