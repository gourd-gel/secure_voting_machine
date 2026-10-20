//! Election CRUD and lifecycle. Every mutation checks the session in this layer.
use super::{audit, finish_change, require_role, text, AppResult};
use crate::{
    auth::login::Session,
    models::{Candidate, Election, Position, ResultRow, Role},
};
use rusqlite::{params, Connection, TransactionBehavior};
use std::collections::HashSet;
use uuid::Uuid;

/// Require election ownership by the administrator, optionally requiring draft status.
fn owned(conn: &Connection, session: &Session, election: i64, draft: bool) -> AppResult<()> {
    require_role(conn, session, Role::Admin)?;
    let found: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM elections WHERE election_id=?1 AND created_by=?2 AND (?3=0 OR status='draft'))",
        params![election,session.user_id(),draft],|r|r.get(0))?;
    if !found {
        return Err("Choose one of your elections; editing requires a draft.".into());
    }
    Ok(())
}
/// Check whether this role/session may read the requested election.
fn read_allowed(conn: &Connection, session: &Session, election: i64) -> AppResult<()> {
    require_role(conn, session, session.role())?;
    let yes: bool = match session.role() {
        Role::Admin => conn.query_row("SELECT EXISTS(SELECT 1 FROM elections WHERE election_id=?1 AND created_by=?2)",params![election,session.user_id()],|r|r.get(0))?,
        Role::DistrictOfficial => conn.query_row("SELECT EXISTS(SELECT 1 FROM elections WHERE election_id=?1)",[election],|r|r.get(0))?,
        Role::Voter => conn.query_row("SELECT EXISTS(SELECT 1 FROM election_voters v JOIN elections e USING(election_id) WHERE v.election_id=?1 AND v.user_id=?2 AND e.status='open')",params![election,session.user_id()],|r|r.get(0))?,
    };
    if session.role() == Role::Voter {
        let voted: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM election_voters WHERE election_id=?1 AND user_id=?2 AND has_voted=1)", params![election,session.user_id()], |r|r.get(0))?;
        if voted {
            return Err("you already voted bruh".into());
        }
    }
    if !yes {
        return Err("Election is unavailable for this account.".into());
    }
    Ok(())
}
/// Return records visible to the authenticated role and ownership scope.
pub fn list(conn: &Connection, session: &Session) -> AppResult<Vec<Election>> {
    election_list(conn, session, false)
}
/// Include cancelled elections when an owning administrator reviews history.
pub fn audit_list(conn: &Connection, session: &Session) -> AppResult<Vec<Election>> {
    require_role(conn, session, Role::Admin)?;
    election_list(conn, session, true)
}
fn election_list(
    conn: &Connection,
    session: &Session,
    include_cancelled: bool,
) -> AppResult<Vec<Election>> {
    require_role(conn, session, session.role())?;
    let mut q=conn.prepare("SELECT e.election_id,e.name,e.status,e.announced_at IS NOT NULL FROM elections e
        WHERE (?3 OR e.status<>'cancelled') AND (
            (?1='admin' AND e.created_by=?2) OR ?1='district_official' OR
            (?1='voter' AND e.status='open' AND EXISTS(SELECT 1 FROM election_voters v WHERE v.election_id=e.election_id AND v.user_id=?2)))
        ORDER BY e.election_id DESC")?;
    let rows = q.query_map(
        params![
            session.role().as_str(),
            session.user_id(),
            include_cancelled
        ],
        |r| {
            Ok(Election {
                id: r.get(0)?,
                name: r.get(1)?,
                status: r.get(2)?,
                announced: r.get(3)?,
            })
        },
    )?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
/// Read one authorized election by its ID.
pub fn get(conn: &Connection, session: &Session, id: i64) -> AppResult<Election> {
    read_allowed(conn, session, id)?;
    Ok(conn.query_row("SELECT election_id,name,status,announced_at IS NOT NULL FROM elections WHERE election_id=?1",[id],|r|Ok(Election{id:r.get(0)?,name:r.get(1)?,status:r.get(2)?,announced:r.get(3)?}))?)
}
/// Read the authorized election positions and their assigned candidates.
pub fn positions(conn: &Connection, session: &Session, election: i64) -> AppResult<Vec<Position>> {
    read_allowed(conn, session, election)?;
    let mut q=conn.prepare("SELECT position_id,name FROM election_positions WHERE election_id=?1 ORDER BY display_order,position_id")?;
    let rows = q.query_map([election], |r| {
        Ok(Position {
            id: r.get(0)?,
            name: r.get(1)?,
            candidates: vec![],
        })
    })?;
    let mut positions = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut q=conn.prepare("SELECT c.candidate_id,c.full_name,c.political_party FROM position_candidates pc JOIN candidates c ON c.election_id=pc.election_id AND c.candidate_id=pc.candidate_id WHERE pc.election_id=?1 AND pc.position_id=?2 ORDER BY c.candidate_id")?;
    for p in &mut positions {
        p.candidates = q
            .query_map(params![election, p.id], |r| {
                Ok(Candidate {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    party: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
    }
    Ok(positions)
}
/// Create a draft election and default positions/candidates in one transaction.
pub fn create(conn: &mut Connection, session: &Session, name: &str) -> AppResult<i64> {
    let name = text(name, "Election name")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_role(&tx, session, Role::Admin)?;
    tx.execute(
        "INSERT INTO elections(name,created_by) VALUES (?1,?2)",
        params![name, session.user_id()],
    )?;
    let id = tx.last_insert_rowid();
    // Shared candidate identities: both can stand in all three positions.
    let mut candidates = Vec::new();
    for (name, party) in [
        ("Hamberger Red", "Red Party"),
        ("Blue Sandwich", "Blue Party"),
    ] {
        tx.execute(
            "INSERT INTO candidates(election_id,full_name,political_party) VALUES (?1,?2,?3)",
            params![id, name, party],
        )?;
        candidates.push(tx.last_insert_rowid());
    }
    for (order, name) in ["President", "Vice President", "Secretary"]
        .iter()
        .enumerate()
    {
        tx.execute(
            "INSERT INTO election_positions(election_id,name,display_order) VALUES (?1,?2,?3)",
            params![id, name, order as i64],
        )?;
        let position = tx.last_insert_rowid();
        for candidate in &candidates {
            tx.execute(
                "INSERT INTO position_candidates VALUES (?1,?2,?3)",
                params![id, position, candidate],
            )?;
        }
    }
    finish_change(tx, session, id, None, "election_created")?;
    Ok(id)
}
/// Rename an owned draft election and record the change.
pub fn rename(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    name: &str,
) -> AppResult<()> {
    let name = text(name, "Election name")?;
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    tx.execute(
        "UPDATE elections SET name=?1 WHERE election_id=?2",
        params![name, election],
    )?;
    finish_change(tx, session, election, None, "election_renamed")
}
/// Draft deletion is a cancellation, preserving the audit trail.
pub fn delete(conn: &mut Connection, session: &Session, election: i64) -> AppResult<()> {
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    tx.execute(
        "UPDATE elections SET status='cancelled' WHERE election_id=?1",
        [election],
    )?;
    finish_change(tx, session, election, None, "election_cancelled")
}
/// Add a position to an owned draft and record the change.
pub fn add_position(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    name: &str,
) -> AppResult<()> {
    let name = text(name, "Position")?;
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    tx.execute("INSERT INTO election_positions(election_id,name,display_order) VALUES (?1,?2,(SELECT COALESCE(MAX(display_order),-1)+1 FROM election_positions WHERE election_id=?1))",params![election,name])?;
    let position = tx.last_insert_rowid();
    // New positions also start with two editable candidates.
    for (name, party) in [
        ("Hamberger Red", "Red Party"),
        ("Blue Sandwich", "Blue Party"),
    ] {
        tx.execute(
            "INSERT INTO candidates(election_id,full_name,political_party) VALUES (?1,?2,?3)",
            params![election, name, party],
        )?;
        tx.execute(
            "INSERT INTO position_candidates VALUES (?1,?2,?3)",
            params![election, position, tx.last_insert_rowid()],
        )?;
    }
    finish_change(tx, session, election, None, "position_added")
}
/// Reject a position that does not belong to the specified election.
fn position_exists(conn: &Connection, election: i64, position: i64) -> AppResult<()> {
    let found: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM election_positions WHERE election_id=?1 AND position_id=?2)",
        params![election, position],
        |r| r.get(0),
    )?;
    if !found {
        return Err("Position does not belong to this election.".into());
    }
    Ok(())
}
/// Rename an owned draft position after validating election membership.
pub fn rename_position(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    position: i64,
    name: &str,
) -> AppResult<()> {
    let name = text(name, "Position")?;
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    position_exists(&tx, election, position)?;
    tx.execute(
        "UPDATE election_positions SET name=?1 WHERE position_id=?2",
        params![name, position],
    )?;
    finish_change(tx, session, election, None, "position_updated")
}
/// Remove a draft position and its assignments, preserving minimum constraints.
pub fn delete_position(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    position: i64,
) -> AppResult<()> {
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    position_exists(&tx, election, position)?;
    let count: i64 = tx.query_row(
        "SELECT count(*) FROM election_positions WHERE election_id=?1",
        [election],
        |r| r.get(0),
    )?;
    if count <= 3 {
        return Err("Keep at least three positions.".into());
    }
    tx.execute(
        "DELETE FROM position_candidates WHERE election_id=?1 AND position_id=?2",
        params![election, position],
    )?;
    tx.execute(
        "DELETE FROM election_positions WHERE position_id=?1",
        [position],
    )?;
    delete_orphans(&tx, election)?;
    finish_change(tx, session, election, None, "position_deleted")
}
/// Remove candidate rows that have no remaining position assignments.
fn delete_orphans(conn: &Connection, election: i64) -> AppResult<()> {
    conn.execute("DELETE FROM candidates WHERE election_id=?1 AND NOT EXISTS(SELECT 1 FROM position_candidates pc WHERE pc.candidate_id=candidates.candidate_id)",[election])?;
    Ok(())
}
/// Create and assign a candidate to a draft position transactionally.
pub fn add_candidate(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    position: i64,
    name: &str,
    party: &str,
) -> AppResult<()> {
    let name = text(name, "Candidate name")?;
    let party = text(party, "Political party")?;
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    position_exists(&tx, election, position)?;
    tx.execute(
        "INSERT INTO candidates(election_id,full_name,political_party) VALUES (?1,?2,?3)",
        params![election, name, party],
    )?;
    tx.execute(
        "INSERT INTO position_candidates VALUES (?1,?2,?3)",
        params![election, position, tx.last_insert_rowid()],
    )?;
    finish_change(tx, session, election, None, "candidate_added")
}
/// Assign an existing candidate to another position in the same draft election.
pub fn link_candidate(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    position: i64,
    candidate: i64,
) -> AppResult<()> {
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    position_exists(&tx, election, position)?;
    tx.execute(
        "INSERT INTO position_candidates VALUES (?1,?2,?3)",
        params![election, position, candidate],
    )?;
    finish_change(tx, session, election, None, "candidate_linked")
}
/// Update a draft candidate name/party and audit the change.
pub fn update_candidate(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    candidate: i64,
    name: &str,
    party: &str,
) -> AppResult<()> {
    let name = text(name, "Candidate name")?;
    let party = text(party, "Political party")?;
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    if tx.execute("UPDATE candidates SET full_name=?1,political_party=?2 WHERE election_id=?3 AND candidate_id=?4",params![name,party,election,candidate])? != 1 {
        return Err("Candidate not found in election.".into());
    }
    finish_change(tx, session, election, None, "candidate_updated")
}
/// Remove a candidate assignment from a draft position.
pub fn unlink_candidate(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    position: i64,
    candidate: i64,
) -> AppResult<()> {
    let tx = conn.transaction()?;
    owned(&tx, session, election, true)?;
    position_exists(&tx, election, position)?;
    let count: i64 = tx.query_row(
        "SELECT count(*) FROM position_candidates WHERE election_id=?1 AND position_id=?2",
        params![election, position],
        |r| r.get(0),
    )?;
    if count <= 2 {
        return Err("Keep at least two candidates per position.".into());
    }
    if tx.execute("DELETE FROM position_candidates WHERE election_id=?1 AND position_id=?2 AND candidate_id=?3",params![election,position,candidate])? !=1 { return Err("Candidate not assigned to this position.".into()); }
    delete_orphans(&tx, election)?;
    finish_change(tx, session, election, None, "candidate_unlinked")
}
/// Require a district official, validate minimum ballot configuration and open voting.
pub fn start(conn: &mut Connection, session: &Session, election: i64) -> AppResult<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_role(&tx, session, Role::DistrictOfficial)?;
    let n: i64 = tx.query_row(
        "SELECT count(*) FROM election_positions WHERE election_id=?1",
        [election],
        |r| r.get(0),
    )?;
    let bad:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM election_positions p WHERE p.election_id=?1 AND (SELECT count(*) FROM position_candidates pc WHERE pc.position_id=p.position_id)<2)",[election],|r|r.get(0))?;
    if n < 3 || bad {
        return Err("At least three positions and two candidates each are required.".into());
    }
    if tx.execute("UPDATE elections SET status='open',opened_by=?1,started_at=CURRENT_TIMESTAMP,opened_at=CURRENT_TIMESTAMP WHERE election_id=?2 AND status='draft' AND opened_at IS NULL AND closed_at IS NULL",params![session.user_id(),election])? !=1 { return Err("Only a draft election can be opened.".into()); }
    finish_change(tx, session, election, None, "election_opened")
}
/// Require a district official, close the open election and record its timestamp.
pub fn close(conn: &mut Connection, session: &Session, election: i64) -> AppResult<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_role(&tx, session, Role::DistrictOfficial)?;
    if tx.execute("UPDATE elections SET status='closed',closed_by=?1,closed_at=CURRENT_TIMESTAMP WHERE election_id=?2 AND status='open'",params![session.user_id(),election])? !=1 { return Err("Only an open election can be closed.".into()); }
    finish_change(tx, session, election, None, "election_closed")
}
/// A whole ballot is submitted once. Editing selections before confirmation is allowed.
/// No identity or credential is written to ballots/ballot_choices.
pub fn cast(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    choices: &[(i64, i64)],
) -> AppResult<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_role(&tx, session, Role::Voter)?;
    let dob: String = tx.query_row(
        "SELECT dob FROM users WHERE id=?1",
        [session.user_id()],
        |r| r.get(0),
    )?;
    crate::validation::adult_on(
        chrono::NaiveDate::parse_from_str(&dob, "%Y-%m-%d")?,
        chrono::Utc::now()
            .with_timezone(&chrono_tz::America::New_York)
            .date_naive(),
    )?;
    let voted: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM election_voters WHERE election_id=?1 AND user_id=?2 AND has_voted=1)", params![election,session.user_id()], |r|r.get(0))?;
    if voted {
        return Err("you already voted bruh".into());
    }
    let open: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM elections WHERE election_id=?1 AND status='open')",
        [election],
        |r| r.get(0),
    )?;
    if !open {
        return Err("Election is not open.".into());
    }
    let count: i64 = tx.query_row(
        "SELECT count(*) FROM election_positions WHERE election_id=?1",
        [election],
        |r| r.get(0),
    )?;
    let distinct: HashSet<i64> = choices.iter().map(|c| c.0).collect();
    if choices.len() != count as usize || distinct.len() != choices.len() {
        return Err("Select exactly one candidate for every position.".into());
    }
    for (position, candidate) in choices {
        let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM position_candidates WHERE election_id=?1 AND position_id=?2 AND candidate_id=?3)",params![election,position,candidate],|r|r.get(0))?;
        if !valid {
            return Err("Invalid candidate selection.".into());
        }
    }
    if tx.execute("UPDATE election_voters SET has_voted=1 WHERE election_id=?1 AND user_id=?2 AND has_voted=0",params![election,session.user_id()])? !=1 {
        return Err("Not enrolled in this election.".into());
    }
    let ballot = Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO ballots VALUES (?1,?2)",
        params![ballot, election],
    )?;
    for (position, candidate) in choices {
        tx.execute(
            "INSERT INTO ballot_choices VALUES (?1,?2,?3,?4)",
            params![election, ballot, position, candidate],
        )?;
    }
    // Queue delivery in the same transaction: no thank-you for a rolled-back vote.
    tx.execute("INSERT INTO notification_outbox(phone,message) SELECT phone_number,'thank you for your vote!' FROM users WHERE id=?1", [session.user_id()])?;
    crate::security::check_deadline()?;
    tx.commit()?;
    Ok(())
}
/// Require a closed election and district official; persist candidate/party totals.
pub fn tally(conn: &mut Connection, session: &Session, election: i64) -> AppResult<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_role(&tx, session, Role::DistrictOfficial)?;
    let status: String = tx.query_row(
        "SELECT status FROM elections WHERE election_id=?1",
        [election],
        |r| r.get(0),
    )?;
    let finalized: bool = tx.query_row("SELECT tallied_at IS NOT NULL OR announced_at IS NOT NULL FROM elections WHERE election_id=?1", [election], |r| r.get(0))?;
    if status != "closed" || finalized {
        tx.rollback()?;
        audit(
            conn,
            Some(election),
            Some(session.user_id()),
            None,
            "tally_rejected",
            2,
        )?;
        return Err(
            "Tally requires a closed, never-tallied election. Announced results are final.".into(),
        );
    }
    // Persist once, including candidates with zero votes.
    tx.execute("INSERT INTO candidate_results SELECT pc.election_id,pc.position_id,pc.candidate_id,count(bc.ballot_id) FROM position_candidates pc LEFT JOIN ballot_choices bc ON bc.election_id=pc.election_id AND bc.position_id=pc.position_id AND bc.candidate_id=pc.candidate_id WHERE pc.election_id=?1 GROUP BY pc.election_id,pc.position_id,pc.candidate_id",[election])?;
    tx.execute("INSERT INTO party_results SELECT r.election_id,r.position_id,c.political_party,sum(r.votes) FROM candidate_results r JOIN candidates c ON c.candidate_id=r.candidate_id WHERE r.election_id=?1 GROUP BY r.election_id,r.position_id,c.political_party",[election])?;
    tx.execute("UPDATE elections SET status='tallied',tallied_by=?1,tallied_at=CURRENT_TIMESTAMP WHERE election_id=?2",params![session.user_id(),election])?;
    finish_change(tx, session, election, None, "election_tallied")
}
/// Require district-official authorization and a tally; mark results announced.
pub fn announce(conn: &mut Connection, session: &Session, election: i64) -> AppResult<()> {
    let tx = conn.transaction()?;
    require_role(&tx, session, Role::DistrictOfficial)?;
    if tx.execute("UPDATE elections SET announced_by=?1,announced_at=CURRENT_TIMESTAMP WHERE election_id=?2 AND status='tallied' AND announced_at IS NULL",params![session.user_id(),election])? !=1 { tx.rollback()?; audit(conn, Some(election), Some(session.user_id()), None, "announcement_rejected", 2)?; return Err("Tally first; results may already be announced.".into()); }
    finish_change(tx, session, election, None, "results_announced")
}
/// Require a district official and return candidate vote totals without voter identities.
pub fn results(conn: &Connection, session: &Session, election: i64) -> AppResult<Vec<ResultRow>> {
    require_role(conn, session, Role::DistrictOfficial)?;
    let mut q=conn.prepare("SELECT p.name,c.full_name,c.political_party,r.votes FROM candidate_results r JOIN election_positions p ON p.position_id=r.position_id JOIN candidates c ON c.candidate_id=r.candidate_id WHERE r.election_id=?1 ORDER BY p.display_order,r.votes DESC,c.candidate_id")?;
    let rows = q.query_map([election], |r| {
        Ok(ResultRow {
            position: r.get(0)?,
            candidate: r.get(1)?,
            party: r.get(2)?,
            votes: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
/// Require a district official and return party totals by position.
pub fn party_results(
    conn: &Connection,
    session: &Session,
    election: i64,
) -> AppResult<Vec<String>> {
    require_role(conn, session, Role::DistrictOfficial)?;
    let mut q=conn.prepare("SELECT p.name,r.party,r.votes FROM party_results r JOIN election_positions p ON p.position_id=r.position_id WHERE r.election_id=?1 ORDER BY p.display_order,r.votes DESC,r.party")?;
    let rows = q.query_map([election], |r| {
        Ok(format!(
            "{} | {}: {}",
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
/// Return the owning admin’s lifecycle/participation view, excluding ballot choices.
pub fn audit_log(conn: &Connection, session: &Session, election: i64) -> AppResult<Vec<String>> {
    owned(conn, session, election, false)?;
    // Explicit allowlist of columns: never expose credential or ballot tables.
    let mut q=conn.prepare("SELECT a.occurred_at,a.event_type,COALESCE(u.full_name,'System'),COALESCE(s.full_name,''),a.severity
        FROM audit_events a LEFT JOIN users u ON u.id=a.actor_user_id LEFT JOIN users s ON s.id=a.subject_user_id
        WHERE (a.election_id=?1 OR (a.election_id IS NULL AND a.actor_user_id=?2)) AND a.event_type NOT IN ('voter_participated','vote_rejected') ORDER BY a.event_id DESC LIMIT 1000")?;
    let rows = q.query_map(params![election, session.user_id()], |r| {
        Ok(format!(
            "{} | {} | actor: {} | subject: {} | level {}",
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Administrators can flag suspicious lifecycle changes without exposing ballots.
pub fn flag_incident(conn: &Connection, session: &Session, election: i64) -> AppResult<()> {
    owned(conn, session, election, false)?;
    audit(
        conn,
        Some(election),
        Some(session.user_id()),
        None,
        "unidentified_change_reported",
        2,
    )
}
