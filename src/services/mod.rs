pub mod election;
pub mod voters;
use crate::{auth::login::Session, models::Role};
use rusqlite::{params, Connection, Transaction};
pub type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Recheck the session against the active database role; log rejected access.
pub(crate) fn require_role(conn: &Connection, session: &Session, role: Role) -> AppResult<()> {
    let valid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1 AND role=?2 AND active=1)",
        params![session.user_id(), role.as_str()],
        |r| r.get(0),
    )?;
    if !valid || session.role() != role {
        if session.role() == Role::Voter {
            crate::security::voter_metric(conn, "authorization_denied")?;
        } else {
            audit(
                conn,
                None,
                Some(session.user_id()),
                None,
                "authorization_denied",
                3,
            )?;
        }
        return Err("This action is not permitted for your account.".into());
    }
    Ok(())
}
/// Insert a structured audit event; database triggers enqueue permitted notifications.
pub(crate) fn audit(
    conn: &Connection,
    election: Option<i64>,
    actor: Option<i64>,
    subject: Option<i64>,
    event: &str,
    severity: i64,
) -> AppResult<()> {
    let contains_voter: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM users
            WHERE role='voter'
            AND (id=?1 OR id=?2)
        )",
        params![actor, subject],
        |r| r.get(0),
    )?;

    if contains_voter || matches!(event, "voter_participated" | "vote_rejected") {
        return Err("Voter-identifying events are prohibited in audit logs.".into());
    }
    conn.execute("INSERT INTO audit_events(election_id,actor_user_id,subject_user_id,event_type,severity) VALUES (?1,?2,?3,?4,?5)",
        params![election,actor,subject,event,severity])?;
    if conn.is_autocommit() {
        trace_audit(event, actor, election, severity);
    }
    Ok(())
}
pub(crate) use crate::validation::text;

#[cfg(test)]
mod tests;

/// Record a successful election change and commit only while its deadline is valid.
/// Taking ownership of the transaction ensures errors roll back both data and audit.
fn finish_change(
    tx: Transaction<'_>,
    session: &Session,
    election: i64,
    subject: Option<i64>,
    event: &str,
) -> AppResult<()> {
    let actor = session.user_id();

    audit(&tx, Some(election), Some(actor), subject, event, 0)?;

    crate::security::check_deadline()?;
    tx.commit()?;

    trace_audit(event, Some(actor), Some(election), 0);

    Ok(())
}

/// Emit only allowlisted fields, after the database transaction has committed.
pub(crate) fn trace_audit(event: &str, actor: Option<i64>, election: Option<i64>, severity: i64) {
    if severity > 0 {
        tracing::warn!(target: "security", event_type=event, actor_user_id=actor, election_id=election, severity, "Security event committed");
    } else {
        tracing::info!(target: "security", event_type=event, actor_user_id=actor, election_id=election, severity, "Administrative operation committed");
    }
}
