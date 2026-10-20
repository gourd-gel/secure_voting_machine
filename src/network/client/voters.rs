//! Typed voter calls. The backend checks role and ownership.
pub use super::provision;
use super::*;
/// Register identity, PIN verifier, enrollment and audit transactionally; deliver the PIN privately.
pub fn register(
    conn: &mut ApiClient,
    auth: &ClientAuth,
    session: &Session,
    election: i64,
    input: &VoterInput,
) -> AppResult<i64> {
    let _ = auth;
    conn.call(session, "voters.register", (election, input))
}
/// Return records visible to the authenticated role and ownership scope.
pub fn list(conn: &ApiClient, session: &Session, election: i64) -> AppResult<Vec<Voter>> {
    conn.call(session, "voters.list", (election,))
}
/// Enroll an existing voter by NID without regenerating their PIN.
pub fn enroll(conn: &mut ApiClient, session: &Session, election: i64, nid: &str) -> AppResult<()> {
    conn.call(session, "voters.enroll", (election, nid))
}
/// Remove an eligible unvoted enrollment; do not delete accepted voting history.
pub fn remove(conn: &mut ApiClient, session: &Session, election: i64, voter: i64) -> AppResult<()> {
    conn.call(session, "voters.remove", (election, voter))
}
/// Update allowed voter profile fields; forbid ordinary OTP-phone/NID reassignment.
pub fn update(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    voter: i64,
    input: &VoterInput,
) -> AppResult<()> {
    conn.call(session, "voters.update", (election, voter, input))
}

/// Confirm delivery without returning the credential to the administrator.
pub fn pin_receipt(
    conn: &ApiClient,
    session: &Session,
    election: i64,
    voter: i64,
    received: bool,
) -> AppResult<()> {
    conn.call(session, "voters.pin_receipt", (election, voter, received))
}
