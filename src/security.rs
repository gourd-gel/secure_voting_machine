//! Request deadlines and sanitized security events. Never accept log text as evidence.
use crate::services::AppResult;
use rusqlite::{params, Connection};
use std::{
    cell::Cell,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
thread_local! { static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) }; }
/// Return Unix milliseconds for the cross-hop request deadline.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
/// Clamp the request budget to ten seconds and store a monotonic worker deadline.
pub fn set_deadline(ms: u64) {
    DEADLINE.with(|d| {
        d.set(Some(
            Instant::now() + Duration::from_millis(ms.saturating_sub(now_ms()).min(10_000)),
        ))
    });
}
/// Clear the worker deadline before recording post-request security events.
pub fn clear_deadline() {
    DEADLINE.with(|d| d.set(None));
}
/// Return whether the current worker has exhausted its request budget.
pub fn expired() -> bool {
    DEADLINE.with(|d| d.get().is_some_and(|at| Instant::now() >= at))
}
/// Reject expired work before credential issuance or transaction commit.
pub fn check_deadline() -> AppResult<()> {
    if expired() {
        Err("Request timed out; refresh state before retrying.".into())
    } else {
        Ok(())
    }
}
/// Structured fields only: passwords, OTPs, request bodies and ballots never enter logs.
pub fn event(
    conn: &Connection,
    user: Option<i64>,
    kind: &str,
    scope: Option<&str>,
    attempts: i64,
) -> AppResult<()> {
    // Unknown PINs must also be treated as voter activity.
    let pin_activity = scope.is_some_and(|s| s.starts_with("pin:"));

    let voter_account = if let Some(id) = user {
        conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM users
                WHERE id=?1 AND role='voter'
            )",
            [id],
            |r| r.get::<_, bool>(0),
        )?
    } else {
        false
    };

    // Voter events must never enter an individual event log.
    if pin_activity || voter_account {
        return voter_metric(conn, kind);
    }

    // Staff/system events may retain attribution.
    let severity = if matches!(
        kind,
        "password_attempt" | "password_verified" | "otp_attempt"
    ) {
        0
    } else {
        3
    };

    conn.execute(
        "INSERT INTO security_events(
            user_id,event_type,scope,attempts
         ) VALUES (?1,?2,?3,?4)",
        params![user, kind, scope, attempts],
    )?;

    crate::services::audit(conn, None, user, None, kind, severity)?;

    Ok(())
}
pub fn voter_metric(conn: &Connection, kind: &str) -> AppResult<()> {
    // Only explicit, non-identifying categories are permitted.
    let allowed = matches!(
        kind,
        "pin_failed"
            | "otp_failed"
            | "otp_expired"
            | "authentication_locked"
            | "authentication_blocked"
            | "vote_rejected"
            | "client_error"
            | "authorization_denied"
            | "request_rejected"
            | "request_timeout"
    );

    if !allowed {
        return Ok(());
    }

    conn.execute(
        "INSERT INTO voter_security_counts(day,event_type,total)
         VALUES (strftime('%Y-%m-%d','now'), ?1, 1)
         ON CONFLICT(day,event_type)
         DO UPDATE SET total=total+1",
        [kind],
    )?;

    Ok(())
}
