//! Explicit endpoint allowlist; no endpoint accepts SQL or a caller-selected actor ID.
use super::*;
use crate::services::{election, voters};
use serde_json::{from_value, to_value};
/// Decode an allowlisted operation and invoke the matching domain service.
pub(super) fn service_call(
    state: &mut State,
    session: &auth::login::Session,
    operation: &str,
    args: Value,
) -> AppResult<Value> {
    let conn = &mut state.conn;
    match operation {
        "election.list" => {
            let (): () = from_value(args)?;
            Ok(to_value(election::list(conn, session)?)?)
        }
        "election.audit_list" => {
            let (): () = from_value(args)?;
            Ok(to_value(election::audit_list(conn, session)?)?)
        }
        "election.get" => {
            let (id,): (i64,) = from_value(args)?;
            Ok(to_value(election::get(conn, session, id)?)?)
        }
        "election.positions" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::positions(conn, session, election)?)?)
        }
        "election.create" => {
            let (name,): (String,) = from_value(args)?;
            Ok(to_value(election::create(conn, session, &name)?)?)
        }
        "election.rename" => {
            let (election, name): (i64, String) = from_value(args)?;
            Ok(to_value(election::rename(conn, session, election, &name)?)?)
        }
        "election.delete" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::delete(conn, session, election)?)?)
        }
        "election.add_position" => {
            let (election, name): (i64, String) = from_value(args)?;
            Ok(to_value(election::add_position(
                conn, session, election, &name,
            )?)?)
        }
        "election.rename_position" => {
            let (election, position, name): (i64, i64, String) = from_value(args)?;
            Ok(to_value(election::rename_position(
                conn, session, election, position, &name,
            )?)?)
        }
        "election.delete_position" => {
            let (election, position): (i64, i64) = from_value(args)?;
            Ok(to_value(election::delete_position(
                conn, session, election, position,
            )?)?)
        }
        "election.add_candidate" => {
            let (election, position, name, party): (i64, i64, String, String) = from_value(args)?;
            Ok(to_value(election::add_candidate(
                conn, session, election, position, &name, &party,
            )?)?)
        }
        "election.link_candidate" => {
            let (election, position, candidate): (i64, i64, i64) = from_value(args)?;
            Ok(to_value(election::link_candidate(
                conn, session, election, position, candidate,
            )?)?)
        }
        "election.update_candidate" => {
            let (election, candidate, name, party): (i64, i64, String, String) = from_value(args)?;
            Ok(to_value(election::update_candidate(
                conn, session, election, candidate, &name, &party,
            )?)?)
        }
        "election.unlink_candidate" => {
            let (election, position, candidate): (i64, i64, i64) = from_value(args)?;
            Ok(to_value(election::unlink_candidate(
                conn, session, election, position, candidate,
            )?)?)
        }
        "election.start" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::start(conn, session, election)?)?)
        }
        "election.close" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::close(conn, session, election)?)?)
        }
        "election.cast" => {
            let (election, choices): (i64, Vec<(i64, i64)>) = from_value(args)?;
            services::require_role(conn, session, Role::Voter)?;
            let (nid, name, dob, phone): (String, String, String, String) = conn.query_row(
                "SELECT nid,full_name,dob,phone_number FROM users WHERE id=?1",
                [session.user_id()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            state.registry.verify(&nid, &name, &dob, &phone)?;
            Ok(to_value(election::cast(
                conn, session, election, &choices,
            )?)?)
        }
        "election.tally" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::tally(conn, session, election)?)?)
        }
        "election.announce" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::announce(conn, session, election)?)?)
        }
        "election.results" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::results(conn, session, election)?)?)
        }
        "election.party_results" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::party_results(conn, session, election)?)?)
        }
        "election.audit_log" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::audit_log(conn, session, election)?)?)
        }
        "election.flag_incident" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(election::flag_incident(conn, session, election)?)?)
        }
        "voters.register" => {
            let (election, input): (i64, VoterInput) = from_value(args)?;
            let input = state
                .registry
                .registration(conn, session, election, &input)?;
            Ok(to_value(voters::register(
                conn,
                &state.auth,
                session,
                election,
                &input,
            )?)?)
        }
        "voters.pin_receipt" => {
            let (election, voter, received): (i64, i64, bool) = from_value(args)?;
            Ok(to_value(voters::pin_receipt(
                conn, session, election, voter, received,
            )?)?)
        }
        "voters.list" => {
            let (election,): (i64,) = from_value(args)?;
            Ok(to_value(voters::list(conn, session, election)?)?)
        }
        "voters.enroll" => {
            let (election, nid): (i64, String) = from_value(args)?;
            services::require_role(conn, session, Role::Admin)?;
            let (name, dob, phone): (String, String, String) = conn.query_row(
                "SELECT full_name,dob,phone_number FROM users WHERE nid=?1",
                [&nid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            state.registry.verify(&nid, &name, &dob, &phone)?;
            Ok(to_value(voters::enroll(conn, session, election, &nid)?)?)
        }
        "voters.remove" => {
            let (election, voter): (i64, i64) = from_value(args)?;
            Ok(to_value(voters::remove(conn, session, election, voter)?)?)
        }
        "voters.update" => {
            let (election, voter, input): (i64, i64, VoterInput) = from_value(args)?;
            let input = state
                .registry
                .registration(conn, session, election, &input)?;
            Ok(to_value(voters::update(
                conn, session, election, voter, &input,
            )?)?)
        }
        _ => Err("Unknown endpoint.".into()),
    }
}
