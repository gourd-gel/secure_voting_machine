//! Typed election calls. The backend checks role, ownership and election state.
use super::*;
/// Return records visible to the authenticated role and ownership scope.
pub fn list(conn: &ApiClient, session: &Session) -> AppResult<Vec<Election>> {
    conn.call(session, "election.list", ())
}
/// Read one authorized election by its ID.
pub fn get(conn: &ApiClient, session: &Session, id: i64) -> AppResult<Election> {
    conn.call(session, "election.get", (id,))
}
/// Read the authorized election positions and their assigned candidates.
pub fn positions(conn: &ApiClient, session: &Session, election: i64) -> AppResult<Vec<Position>> {
    conn.call(session, "election.positions", (election,))
}
/// Create a draft election and default positions/candidates in one transaction.
pub fn create(conn: &mut ApiClient, session: &Session, name: &str) -> AppResult<i64> {
    conn.call(session, "election.create", (name,))
}
/// Rename an owned draft election and record the change.
pub fn rename(conn: &mut ApiClient, session: &Session, election: i64, name: &str) -> AppResult<()> {
    conn.call(session, "election.rename", (election, name))
}
/// Cancel an owned draft election while preserving its audit history.
pub fn delete(conn: &mut ApiClient, session: &Session, election: i64) -> AppResult<()> {
    conn.call(session, "election.delete", (election,))
}
/// Add a position to an owned draft and record the change.
pub fn add_position(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    name: &str,
) -> AppResult<()> {
    conn.call(session, "election.add_position", (election, name))
}
/// Rename an owned draft position after validating election membership.
pub fn rename_position(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    position: i64,
    name: &str,
) -> AppResult<()> {
    conn.call(
        session,
        "election.rename_position",
        (election, position, name),
    )
}
/// Remove a draft position and its assignments, preserving minimum constraints.
pub fn delete_position(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    position: i64,
) -> AppResult<()> {
    conn.call(session, "election.delete_position", (election, position))
}
/// Create and assign a candidate to a draft position transactionally.
pub fn add_candidate(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    position: i64,
    name: &str,
    party: &str,
) -> AppResult<()> {
    conn.call(
        session,
        "election.add_candidate",
        (election, position, name, party),
    )
}
/// Assign an existing candidate to another position in the same draft election.
pub fn link_candidate(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    position: i64,
    candidate: i64,
) -> AppResult<()> {
    conn.call(
        session,
        "election.link_candidate",
        (election, position, candidate),
    )
}
/// Update a draft candidate name/party and audit the change.
pub fn update_candidate(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    candidate: i64,
    name: &str,
    party: &str,
) -> AppResult<()> {
    conn.call(
        session,
        "election.update_candidate",
        (election, candidate, name, party),
    )
}
/// Remove a candidate assignment from a draft position.
pub fn unlink_candidate(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    position: i64,
    candidate: i64,
) -> AppResult<()> {
    conn.call(
        session,
        "election.unlink_candidate",
        (election, position, candidate),
    )
}
/// Require a district official, validate minimum ballot configuration and open voting.
pub fn start(conn: &mut ApiClient, session: &Session, election: i64) -> AppResult<()> {
    conn.call(session, "election.start", (election,))
}
/// Require a district official, close the open election and record its timestamp.
pub fn close(conn: &mut ApiClient, session: &Session, election: i64) -> AppResult<()> {
    conn.call(session, "election.close", (election,))
}
/// Atomically record an eligible voter’s complete ballot and participation; reject repeat votes.
pub fn cast(
    conn: &mut ApiClient,
    session: &Session,
    election: i64,
    choices: &[(i64, i64)],
) -> AppResult<()> {
    conn.call(session, "election.cast", (election, choices))
}
/// Require a closed election and district official; persist candidate/party totals.
pub fn tally(conn: &mut ApiClient, session: &Session, election: i64) -> AppResult<()> {
    conn.call(session, "election.tally", (election,))
}
/// Require district-official authorization and a tally; mark results announced.
pub fn announce(conn: &mut ApiClient, session: &Session, election: i64) -> AppResult<()> {
    conn.call(session, "election.announce", (election,))
}
/// Require a district official and return candidate vote totals without voter identities.
pub fn results(conn: &ApiClient, session: &Session, election: i64) -> AppResult<Vec<ResultRow>> {
    conn.call(session, "election.results", (election,))
}
/// Require a district official and return party totals by position.
pub fn party_results(conn: &ApiClient, session: &Session, election: i64) -> AppResult<Vec<String>> {
    conn.call(session, "election.party_results", (election,))
}
/// Return the owning admin’s lifecycle/participation view, excluding ballot choices.
pub fn audit_log(conn: &ApiClient, session: &Session, election: i64) -> AppResult<Vec<String>> {
    conn.call(session, "election.audit_log", (election,))
}
/// Record a suspicious election change for investigation.
pub fn flag_incident(conn: &ApiClient, session: &Session, election: i64) -> AppResult<()> {
    conn.call(session, "election.flag_incident", (election,))
}

pub fn audit_list(conn: &ApiClient, session: &Session) -> AppResult<Vec<Election>> {
    conn.call(session, "election.audit_list", ())
}
