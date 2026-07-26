//! The crate's one wall-clock reading: absolute Unix seconds.
//!
//! Provider records are TTL'd soft state (`expires_at` in absolute Unix seconds), so admission,
//! expiry, GC, and eviction all need the same notion of "now". Keeping the single `SystemTime` read
//! here means the service and the provider store cannot drift onto different clock sources, and the
//! decision points that need to be testable take `now` as a PARAMETER (`ProviderStore::put_at`,
//! `get`, `gc`) instead of reaching for the system clock themselves.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current time as absolute Unix seconds, saturating to 0 if the system clock predates the epoch.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
