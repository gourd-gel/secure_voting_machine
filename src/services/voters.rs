//! Registration is one operation: identity, PIN credential, enrollment and audit.
use super::{audit, finish_change, require_role, text, AppResult};
use crate::validation;
use crate::{
    auth::login::{Auth, Session},
    models::{Role, Voter, VoterInput},
};
use rusqlite::{params, Connection, OptionalExtension};

/// Require the owning administrator and an enrollable election state.
pub(crate) fn enrollment_allowed(
    conn: &Connection,
    session: &Session,
    election: i64,
) -> AppResult<()> {
    require_role(conn, session, Role::Admin)?;
    let yes:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM elections WHERE election_id=?1 AND created_by=?2 AND status IN ('draft','open'))",params![election,session.user_id()],|r|r.get(0))?;
    if !yes {
        return Err("Choose your own draft or open election.".into());
    }
    Ok(())
}
/// Register identity, PIN verifier, enrollment and audit transactionally; deliver the PIN privately.
pub fn register(
    conn: &mut Connection,
    auth: &Auth,
    session: &Session,
    election: i64,
    input: &VoterInput,
) -> AppResult<i64> {
    let input = validation::voter(input)?;
    let tx = conn.transaction()?;
    enrollment_allowed(&tx, session, election)?;
    let duplicate: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE nid=?1 OR (?2<>'' AND lower(email)=?2))",
        params![input.nid, input.email],
        |r| r.get(0),
    )?;
    if duplicate {
        return Err("Voter already exists. Use Enroll existing voter by NID; a PIN will not be regenerated.".into());
    }
    let (pin, lookup, hash) = auth.new_pin()?;
    tx.execute("INSERT INTO users(email,phone_number,role,full_name,dob,nid) VALUES (NULLIF(?1,''),?2,'voter',?3,?4,?5)",params![input.email,input.phone,input.full_name,input.dob,input.nid])?;
    let id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO voter_pin_credentials VALUES (?1,?2,?3)",
        params![id, lookup, hash],
    )?;
    tx.execute(
        "INSERT INTO election_voters(election_id,user_id) VALUES (?1,?2)",
        params![election, id],
    )?;
    audit(
        &tx,
        Some(election),
        Some(session.user_id()),
        None,
        "voter_registered",
        0,
    )?;
    // The UI only reports delivery, never the PIN. File failures roll back DB writes.
    auth.deliver(
        &input.phone,
        &format!("Voting PIN: {pin}\nKeep this credential private.\n"),
    )?;
    crate::security::check_deadline()?;
    tx.commit()?;
    super::trace_audit(
        "voter_registered",
        Some(session.user_id()),
        Some(election),
        0,
    );
    Ok(id)
}
/// Return records visible to the authenticated role and ownership scope.
pub fn list(conn: &Connection, session: &Session, election: i64) -> AppResult<Vec<Voter>> {
    require_role(conn, session, Role::Admin)?;
    let owner: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM elections WHERE election_id=?1 AND created_by=?2)",
        params![election, session.user_id()],
        |r| r.get(0),
    )?;
    if !owner {
        return Err("Election does not belong to you.".into());
    }
    let mut q=conn.prepare("SELECT u.id,u.full_name,COALESCE(u.email,''),u.phone_number,COALESCE(u.dob,''),COALESCE(u.nid,''),v.has_voted FROM election_voters v JOIN users u ON u.id=v.user_id WHERE v.election_id=?1 ORDER BY u.full_name,u.id")?;
    let rows = q.query_map([election], |r| {
        Ok(Voter {
            id: r.get(0)?,
            full_name: r.get(1)?,
            email: r.get(2)?,
            phone: r.get(3)?,
            dob: r.get(4)?,
            nid: r.get(5)?,
            has_voted: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
/// Enroll an existing voter by NID without regenerating their PIN.
pub fn enroll(conn: &mut Connection, session: &Session, election: i64, nid: &str) -> AppResult<()> {
    let tx = conn.transaction()?;
    enrollment_allowed(&tx, session, election)?;
    let id:Option<i64>=tx.query_row("SELECT u.id FROM users u JOIN voter_pin_credentials p ON p.user_id=u.id WHERE u.nid=?1 AND u.role='voter' AND u.active=1",[nid.trim().to_uppercase()],|r|r.get(0)).optional()?;
    let id = id.ok_or("No active voter with a usable PIN has that NID.")?;
    tx.execute(
        "INSERT INTO election_voters(election_id,user_id) VALUES (?1,?2)",
        params![election, id],
    )?;
    finish_change(tx, session, election, None, "voter_enrolled")
}
/// Removes eligibility, not historical identity or credentials.
pub fn remove(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    voter: i64,
) -> AppResult<()> {
    let tx = conn.transaction()?;
    enrollment_allowed(&tx, session, election)?;
    let draft: bool = tx.query_row(
        "SELECT status='draft' FROM elections WHERE election_id=?1",
        [election],
        |r| r.get(0),
    )?;
    if !draft {
        return Err("Enrollment can only be removed before voting opens.".into());
    }
    if tx.execute(
        "DELETE FROM election_voters WHERE election_id=?1 AND user_id=?2 AND has_voted=0",
        params![election, voter],
    )? != 1
    {
        return Err("Voter not enrolled or already voted.".into());
    }
    finish_change(tx, session, election, None, "voter_unenrolled")
}
/// Update allowed voter profile fields; forbid ordinary OTP-phone/NID reassignment.
pub fn update(
    conn: &mut Connection,
    session: &Session,
    election: i64,
    voter: i64,
    input: &VoterInput,
) -> AppResult<()> {
    let input = validation::voter(input)?;
    let tx = conn.transaction()?;
    enrollment_allowed(&tx, session, election)?;
    let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM election_voters v JOIN elections e USING(election_id) WHERE v.election_id=?1 AND v.user_id=?2 AND v.has_voted=0 AND e.status='draft')",params![election,voter],|r|r.get(0))?;
    if !allowed {
        return Err("Only unvoted draft-enrolled voters can be edited.".into());
    }
    // Do not let an admin redirect another user's OTP or change their identity.
    let existing: (String, String) = tx.query_row(
        "SELECT nid,phone_number FROM users WHERE id=?1",
        [voter],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if existing.0 != input.nid || existing.1 != input.phone {
        return Err("NID and OTP phone cannot be changed here; require engineer-assisted identity verification.".into());
    }
    tx.execute(
        "UPDATE users SET email=NULLIF(?1,''),full_name=?2,dob=?3 WHERE id=?4 AND role='voter'",
        params![input.email, input.full_name, input.dob, voter],
    )?;
    finish_change(tx, session, election, None, "voter_updated")
}
/// Called only from the explicit engineer setup mode, never an ordinary role menu.
pub fn provision(
    conn: &mut Connection,
    auth: &Auth,
    email: &str,
    phone: &str,
    name: &str,
    password: &str,
    role: Role,
) -> AppResult<()> {
    if role == Role::Voter {
        return Err("Register voters through the administrator's R action.".into());
    }
    let email = validation::email(email, false)?;
    let phone = validation::phone(phone)?;
    let name = text(name, "Full name")?;
    let hashed = auth.password_hash(password)?;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO users(email,phone_number,role,full_name) VALUES (?1,?2,?3,?4)",
        params![email, phone, role.as_str(), name],
    )?;
    let id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO user_credentials VALUES (?1,?2)",
        params![id, hashed],
    )?;
    audit(&tx, None, None, Some(id), "engineer_provisioned_account", 0)?;
    crate::security::check_deadline()?;
    tx.commit()?;
    Ok(())
}

/// Record only the administrator's delivery confirmation, never the PIN or voter ID.
pub fn pin_receipt(
    conn: &Connection,
    session: &Session,
    election: i64,
    voter: i64,
    received: bool,
) -> AppResult<()> {
    enrollment_allowed(conn, session, election)?;
    let enrolled: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM election_voters WHERE election_id=?1 AND user_id=?2)",
        rusqlite::params![election, voter],
        |r| r.get(0),
    )?;
    if !enrolled {
        return Err("Voter is not enrolled in this election.".into());
    }
    audit(
        conn,
        Some(election),
        Some(session.user_id()),
        None,
        if received {
            "pin_receipt_confirmed"
        } else {
            "pin_receipt_not_confirmed"
        },
        if received { 0 } else { 2 },
    )
}
