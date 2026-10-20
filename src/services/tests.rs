//! Database transactions, constraints, role boundaries, and authentication tests.
use super::*;
use crate::{auth::login::Session, database, models::*, test_support::*};
use rusqlite::{params, Connection};
use std::{fs, time::Duration};
use uuid::Uuid;
#[test]
fn initialization_is_idempotent_and_defaults_are_not_created_on_login() {
    let mut f = Fixture::new();
    database::initialize(&mut f.conn).unwrap();
    assert_eq!(count(&f.conn, "elections"), 0);
    let e = f.create();
    assert_eq!(count(&f.conn, "election_positions"), 3);
    assert_eq!(count(&f.conn, "candidates"), 2);
    assert_eq!(count(&f.conn, "position_candidates"), 6);
    let p = election::positions(&f.conn, &f.admin, e).unwrap();
    assert_eq!(p[0].name, "President");
    assert_eq!(p[0].candidates[0].id, p[1].candidates[0].id);
}

#[test]
fn registration_generates_private_unique_pin_and_enrollment() {
    let mut f = Fixture::new();
    let e = f.create();
    let (id, pin) = f.register(e, 1);
    let (_, pin2) = f.register(e, 2);
    assert_eq!(pin.len(), 20);
    assert!(pin.chars().all(|c| c.is_ascii_digit()));
    assert_ne!(pin, pin2);
    let hash: String = f
        .conn
        .query_row(
            "SELECT pin_hash FROM voter_pin_credentials WHERE user_id=?1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(hash, pin);
    assert_eq!(voters::list(&f.conn, &f.admin, e).unwrap().len(), 2);
    assert!(f.auth.pin_login(&f.conn, &pin).is_ok());
    assert!(f.auth.pin_login(&f.conn, "bad-pin").is_err());
    let logs = election::audit_log(&f.conn, &f.admin, e)
        .unwrap()
        .join("\n");
    assert!(logs.contains("voter_registered"));
    assert!(!logs.contains(&pin));
    assert!(!logs.contains(&hash));
}

#[test]
fn duplicate_and_invalid_registration_leave_no_partial_rows() {
    let mut f = Fixture::new();
    let e = f.create();
    f.register(e, 1);
    assert!(voters::register(&mut f.conn, &f.auth, &f.admin, e, &input(1)).is_err());
    let mut bad = input(2);
    bad.dob = "2020-02-30".into();
    assert!(voters::register(&mut f.conn, &f.auth, &f.admin, e, &bad).is_err());
    assert_eq!(count(&f.conn, "users"), 3);
    assert_eq!(count(&f.conn, "voter_pin_credentials"), 1);
}

#[test]
fn delivery_failure_rolls_back_registration() {
    let mut f = Fixture::new();
    let e = f.create();
    fs::write(&f.root, "not a directory").unwrap();
    assert!(voters::register(&mut f.conn, &f.auth, &f.admin, e, &input(1)).is_err());
    assert_eq!(count(&f.conn, "users"), 2);
    assert_eq!(count(&f.conn, "election_voters"), 0);
    assert_eq!(count(&f.conn, "voter_pin_credentials"), 0);
    fs::remove_file(&f.root).unwrap();
}

#[test]
fn role_checks_and_cross_admin_ownership_are_enforced_in_services() {
    let mut f = Fixture::new();
    let e = f.create();
    assert!(election::create(&mut f.conn, &f.official, "Forbidden").is_err());
    assert!(election::start(&mut f.conn, &f.admin, e).is_err());
    assert!(election::results(&f.conn, &f.admin, e).is_err());
    assert!(election::party_results(&f.conn, &f.admin, e).is_err());
    assert!(election::audit_log(&f.conn, &f.official, e).is_err());
    voters::provision(
        &mut f.conn,
        &f.auth,
        "other@example.test",
        "+15550000009",
        "Other",
        "password1234",
        Role::Admin,
    )
    .unwrap();
    let other = Session::for_test(3, Role::Admin);
    assert!(election::rename(&mut f.conn, &other, e, "Stolen").is_err());
    assert!(election::positions(&f.conn, &other, e).is_err());
    assert!(voters::register(&mut f.conn, &f.auth, &other, e, &input(1)).is_err());
}

#[test]
fn position_candidate_crud_and_linking_persist() {
    let mut f = Fixture::new();
    let e = f.create();
    election::add_position(&mut f.conn, &f.admin, e, "Treasurer").unwrap();
    let p = election::positions(&f.conn, &f.admin, e).unwrap();
    let last = p.last().unwrap().id;
    election::rename_position(&mut f.conn, &f.admin, e, last, "Finance Secretary").unwrap();
    election::add_candidate(&mut f.conn, &f.admin, e, last, "Third", "Green").unwrap();
    let p = election::positions(&f.conn, &f.admin, e).unwrap();
    let candidate = p.last().unwrap().candidates.last().unwrap().id;
    election::link_candidate(&mut f.conn, &f.admin, e, p[0].id, candidate).unwrap();
    election::update_candidate(&mut f.conn, &f.admin, e, candidate, "Updated", "Purple").unwrap();
    let p = election::positions(&f.conn, &f.admin, e).unwrap();
    assert!(p[0].candidates.iter().any(|c| c.name == "Updated"));
    election::unlink_candidate(&mut f.conn, &f.admin, e, p[0].id, candidate).unwrap();
    election::delete_position(&mut f.conn, &f.admin, e, last).unwrap();
    assert_eq!(election::positions(&f.conn, &f.admin, e).unwrap().len(), 3);
    assert!(election::delete_position(&mut f.conn, &f.admin, e, p[0].id).is_err());
    assert!(
        election::unlink_candidate(&mut f.conn, &f.admin, e, p[0].id, p[0].candidates[0].id)
            .is_err()
    );
}

#[test]
fn voter_update_enroll_and_remove_preserve_pin() {
    let mut f = Fixture::new();
    let e = f.create();
    let (id, pin) = f.register(e, 1);
    let e2 = f.create();
    voters::enroll(&mut f.conn, &f.admin, e2, "NID1").unwrap();
    let mut v = input(1);
    v.full_name = "Corrected Name".into();
    voters::update(&mut f.conn, &f.admin, e, id, &v).unwrap();
    assert_eq!(
        voters::list(&f.conn, &f.admin, e).unwrap()[0].full_name,
        "Corrected Name"
    );
    v.phone = "+15559999999".into();
    assert!(voters::update(&mut f.conn, &f.admin, e, id, &v).is_err());
    voters::remove(&mut f.conn, &f.admin, e, id).unwrap();
    assert!(voters::list(&f.conn, &f.admin, e).unwrap().is_empty());
    assert!(f.auth.pin_login(&f.conn, &pin).is_ok());
    assert_eq!(count(&f.conn, "voter_pin_credentials"), 1);
}

#[test]
fn lifecycle_tally_party_totals_and_announcement() {
    let mut f = Fixture::new();
    let e = f.create();
    let (v, _) = f.register(e, 1);
    let (v2, _) = f.register(e, 2);
    let s = Session::for_test(v, Role::Voter);
    let s2 = Session::for_test(v2, Role::Voter);
    let c = choices(&f.conn, &f.admin, e, 0);
    assert!(election::cast(&mut f.conn, &s, e, &c).is_err());
    assert!(election::tally(&mut f.conn, &f.official, e).is_err());
    election::start(&mut f.conn, &f.official, e).unwrap();
    election::cast(&mut f.conn, &s, e, &c).unwrap();
    election::cast(&mut f.conn, &s2, e, &c).unwrap();
    assert!(election::cast(&mut f.conn, &s, e, &c).is_err());
    election::close(&mut f.conn, &f.official, e).unwrap();
    assert!(election::cast(&mut f.conn, &s, e, &c).is_err());
    election::tally(&mut f.conn, &f.official, e).unwrap();
    assert!(election::tally(&mut f.conn, &f.official, e).is_err());
    let results = election::results(&f.conn, &f.official, e).unwrap();
    assert_eq!(results.len(), 6);
    assert_eq!(results.iter().filter(|r| r.votes == 2).count(), 3);
    assert_eq!(
        f.conn
            .query_row("SELECT sum(votes) FROM party_results", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        6
    );
    election::announce(&mut f.conn, &f.official, e).unwrap();
    assert!(election::get(&f.conn, &f.official, e).unwrap().announced);
    let times: (String, String, String) = f
        .conn
        .query_row(
            "SELECT started_at,closed_at,tallied_at FROM elections WHERE election_id=?1",
            [e],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(!times.0.is_empty() && !times.1.is_empty() && !times.2.is_empty());
}

#[test]
fn ballots_are_atomic_immutable_and_do_not_link_to_identity() {
    let mut f = Fixture::new();
    let e = f.create();
    let (v, _) = f.register(e, 1);
    let s = Session::for_test(v, Role::Voter);
    let c = choices(&f.conn, &f.admin, e, 0);
    election::start(&mut f.conn, &f.official, e).unwrap();
    assert!(election::cast(&mut f.conn, &s, e, &c[..2]).is_err());
    assert!(election::cast(&mut f.conn, &s, e, &[c[0], c[0], c[2]]).is_err());
    f.conn.execute_batch("CREATE TRIGGER test_fail BEFORE INSERT ON ballot_choices BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert!(election::cast(&mut f.conn, &s, e, &c).is_err());
    assert_eq!(count(&f.conn, "ballots"), 0);
    assert_eq!(
        f.conn
            .query_row(
                "SELECT has_voted FROM election_voters WHERE user_id=?1",
                [v],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    f.conn.execute_batch("DROP TRIGGER test_fail;").unwrap();
    election::cast(&mut f.conn, &s, e, &c).unwrap();
    assert!(f
        .conn
        .execute("UPDATE ballot_choices SET candidate_id=2", [])
        .is_err());
    assert!(f.conn.execute("DELETE FROM ballot_choices", []).is_err());
    assert!(f
        .conn
        .execute("UPDATE election_voters SET has_voted=0", [])
        .is_err());
    assert!(f.conn.execute("DELETE FROM audit_events", []).is_err());
    for table in ["ballots", "ballot_choices"] {
        let mut q = f
            .conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let cols = q
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(!cols.iter().any(|c| c.contains("user") || c.contains("pin")));
    }
}

#[test]
fn open_elections_are_frozen_and_foreign_keys_reject_other_elections() {
    let mut f = Fixture::new();
    let e = f.create();
    let e2 = f.create();
    let c2 = choices(&f.conn, &f.admin, e2, 0);
    let (v, _) = f.register(e, 1);
    let s = Session::for_test(v, Role::Voter);
    election::start(&mut f.conn, &f.official, e).unwrap();
    assert!(election::add_position(&mut f.conn, &f.admin, e, "Late").is_err());
    assert!(f
        .conn
        .execute(
            "UPDATE election_positions SET name='Changed' WHERE election_id=?1",
            [e]
        )
        .is_err());
    assert!(election::cast(&mut f.conn, &s, e, &c2).is_err());
    f.conn
        .execute("INSERT INTO ballots VALUES ('test',?1)", [e])
        .unwrap();
    assert!(f
        .conn
        .execute(
            "INSERT INTO ballot_choices VALUES (?1,'test',?2,?3)",
            params![e, c2[0].0, c2[0].1]
        )
        .is_err());
}

#[test]
fn failed_password_and_otp_attempts_lock_and_log() {
    let f = Fixture::new();
    for _ in 0..5 {
        assert!(f
            .auth
            .password_login(&f.conn, "admin@example.test", "wrong", Role::Admin)
            .is_err());
    }
    assert!(f
        .auth
        .password_login(&f.conn, "admin@example.test", "password1234", Role::Admin)
        .is_err());
    f.conn.execute("DELETE FROM auth_attempts", []).unwrap();
    let mut pending = Some(
        f.auth
            .password_login(&f.conn, "admin@example.test", "password1234", Role::Admin)
            .unwrap(),
    );
    for _ in 0..3 {
        assert!(f
            .auth
            .complete_otp(&f.conn, &mut pending, "not-six-digits")
            .is_err());
    }
    assert!(pending.is_none());
    assert!(f
        .auth
        .password_login(&f.conn, "admin@example.test", "password1234", Role::Admin)
        .is_err());
    for (event, severity, expected) in [
        ("password_failed", 3, 5),
        ("otp_failed", 3, 3),
        ("authentication_locked", 3, 2),
        ("authentication_blocked", 3, 1),
    ] {
        let n:i64=f.conn.query_row("SELECT count(*) FROM audit_events WHERE event_type=?1 AND actor_user_id=1 AND severity=?2",params![event,severity],|r|r.get(0)).unwrap();
        assert_eq!(n, expected, "{event}");
    }
    let anonymous:i64=f.conn.query_row("SELECT count(*) FROM audit_events WHERE event_type='authentication_blocked' AND actor_user_id IS NULL AND severity=3",[],|r|r.get(0)).unwrap();
    assert_eq!(anonymous, 1); // Password cooldown is checked before account lookup.
}

#[test]
fn otp_completes_once_and_wrong_role_cannot_log_in() {
    let f = Fixture::new();
    assert!(f
        .auth
        .password_login(
            &f.conn,
            "admin@example.test",
            "password1234",
            Role::DistrictOfficial
        )
        .is_err());
    let mut pending = Some(
        f.auth
            .password_login(&f.conn, "admin@example.test", "password1234", Role::Admin)
            .unwrap(),
    );
    let code = message(&f.root, "+15550000001", "Login OTP: ");
    let s = f.auth.complete_otp(&f.conn, &mut pending, &code).unwrap();
    assert_eq!(s.user_id(), 1);
    assert_eq!(s.role(), Role::Admin);
    assert!(f.auth.complete_otp(&f.conn, &mut pending, &code).is_err());
}

#[test]
fn reopen_persists_election_edits_and_records() {
    let mut f = Fixture::new();
    let path = std::env::temp_dir().join(format!("voting-{}.db", Uuid::new_v4()));
    let mut disk = database::open(&path).unwrap();
    voters::provision(
        &mut disk,
        &f.auth,
        "admin@example.test",
        "+15550000001",
        "Admin",
        "password1234",
        Role::Admin,
    )
    .unwrap();
    let e = election::create(&mut disk, &f.admin, "Persistent").unwrap();
    election::add_position(&mut disk, &f.admin, e, "Fourth").unwrap();
    drop(disk);
    f.conn = database::open(&path).unwrap();
    assert_eq!(election::positions(&f.conn, &f.admin, e).unwrap().len(), 4);
    assert_eq!(
        election::list(&f.conn, &f.admin).unwrap()[0].name,
        "Persistent"
    );
    drop(f);
    fs::remove_file(path).unwrap();
}

#[test]
fn legacy_account_schema_is_preserved() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,phone_number TEXT NOT NULL,role TEXT NOT NULL,full_name TEXT NOT NULL); INSERT INTO users VALUES(1,'old@example.test','1234567','admin','Old Admin'); CREATE TABLE voter_pins(user_id INTEGER PRIMARY KEY,voter_pin TEXT NOT NULL); INSERT INTO voter_pins VALUES(1,'legacy');").unwrap();
    database::initialize(&mut conn).unwrap();
    assert_eq!(count(&conn, "users"), 1);
    assert_eq!(count(&conn, "voter_pins"), 1);
    assert_eq!(count(&conn, "voter_pin_credentials"), 0);
}

#[test]
fn cancelled_elections_disappear_without_deleting_audit() {
    let mut f = Fixture::new();
    let e = f.create();
    election::delete(&mut f.conn, &f.admin, e).unwrap();
    assert!(election::list(&f.conn, &f.admin).unwrap().is_empty());
    assert!(election::audit_log(&f.conn, &f.admin, e)
        .unwrap()
        .iter()
        .any(|l| l.contains("cancelled")));
}

#[test]
fn concurrent_duplicate_submissions_commit_only_one_ballot() {
    let f = Fixture::new();
    let path = std::env::temp_dir().join(format!("voting-race-{}.db", Uuid::new_v4()));
    let mut conn = database::open(&path).unwrap();
    voters::provision(
        &mut conn,
        &f.auth,
        "admin@example.test",
        "+15550000001",
        "Admin",
        "password1234",
        Role::Admin,
    )
    .unwrap();
    voters::provision(
        &mut conn,
        &f.auth,
        "official@example.test",
        "+15550000002",
        "Official",
        "password1234",
        Role::DistrictOfficial,
    )
    .unwrap();
    let e = election::create(&mut conn, &f.admin, "Race test").unwrap();
    let v = voters::register(&mut conn, &f.auth, &f.admin, e, &input(9)).unwrap();
    let c = choices(&conn, &f.admin, e, 0);
    election::start(&mut conn, &f.official, e).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let c = c.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut db = Connection::open(path).unwrap();
                db.busy_timeout(Duration::from_secs(5)).unwrap();
                db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
                barrier.wait();
                election::cast(&mut db, &Session::for_test(v, Role::Voter), e, &c).is_ok()
            })
        })
        .collect();
    let successes = workers
        .into_iter()
        .filter(|w| w.thread().id() != std::thread::current().id())
        .map(|w| w.join().unwrap() as usize)
        .sum::<usize>();
    assert_eq!(successes, 1);
    assert_eq!(count(&conn, "ballots"), 1);
    assert_eq!(count(&conn, "ballot_choices"), 3);
    drop(conn);
    let conn = database::open(&path).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT has_voted FROM election_voters WHERE user_id=?1",
            [v],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    drop(conn);
    fs::remove_file(path).unwrap();
}

#[test]
fn pin_attempt_limit_and_deactivated_user_session() {
    let mut f = Fixture::new();
    let e = f.create();
    let (v, pin) = f.register(e, 1);
    for _ in 0..10 {
        assert!(f.auth.pin_login(&f.conn, "invalid").is_err());
    }
    assert!(f.auth.pin_login(&f.conn, &pin).is_ok());
    f.conn
        .execute("UPDATE users SET active=0 WHERE id=?1", [v])
        .unwrap();
    assert!(election::list(&f.conn, &Session::for_test(v, Role::Voter)).is_err());
}

#[test]
fn security_failures_have_counts_and_private_email_notifications() {
    let f = Fixture::new();
    for _ in 0..5 {
        let _ = f
            .auth
            .password_login(&f.conn, "admin@example.test", "wrong-password", Role::Admin);
    }
    let count: i64 = f
        .conn
        .query_row(
            "SELECT count(*) FROM security_events WHERE user_id=1 AND event_type='password_failed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 5);
    let max: i64 = f
        .conn
        .query_row(
            "SELECT max(attempts) FROM security_events WHERE event_type='password_failed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(max, 5);
    f.auth.flush_notifications(&f.conn).unwrap();
    let admin = std::fs::read_to_string(f.root.join("emails/admin@example.test.txt")).unwrap();
    let system = std::fs::read_to_string(f.root.join("emails/systemadmin@gmail.com.txt")).unwrap();
    assert!(admin.contains("authentication_locked"));
    assert!(system.contains("password_failed"));
    assert!(!admin.contains("wrong-password"));
    assert!(!f.root.join("emails/official@example.test.txt").exists());
    let pending: i64 = f
        .conn
        .query_row(
            "SELECT count(*) FROM email_outbox WHERE delivered=0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0);
}

#[test]
fn expired_mutation_does_not_commit() {
    let mut f = Fixture::new();
    crate::security::set_deadline(crate::security::now_ms().saturating_sub(1));
    let result = election::create(&mut f.conn, &f.admin, "Too late");
    crate::security::clear_deadline();
    assert!(result.is_err());
    assert_eq!(count(&f.conn, "elections"), 0);
}

#[test]
fn email_delivery_failure_keeps_outbox_for_retry() {
    let f = Fixture::new();
    std::fs::create_dir_all(&f.root).unwrap();
    std::fs::write(f.root.join("emails"), "blocks directory creation").unwrap();
    crate::security::event(&f.conn, Some(1), "password_failed", None, 1).unwrap();
    assert!(f.auth.flush_emails(&f.conn).is_err());
    let pending: i64 = f
        .conn
        .query_row(
            "SELECT count(*) FROM email_outbox WHERE delivered=0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(pending > 0);
    std::fs::remove_file(f.root.join("emails")).unwrap();
    f.auth.flush_emails(&f.conn).unwrap();
    let remaining: i64 = f
        .conn
        .query_row(
            "SELECT count(*) FROM email_outbox WHERE delivered=0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0);
}

#[test]
fn audit_failure_rolls_back_election_edit() {
    let mut f = Fixture::new();
    let e = f.create();
    let before = election::get(&f.conn, &f.admin, e).unwrap().name;
    let events = count(&f.conn, "audit_events");
    f.conn
        .execute_batch(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events
         WHEN NEW.event_type='election_renamed'
         BEGIN SELECT RAISE(ABORT,'test audit failure'); END;",
        )
        .unwrap();
    assert!(election::rename(&mut f.conn, &f.admin, e, "Must roll back").is_err());
    assert_eq!(election::get(&f.conn, &f.admin, e).unwrap().name, before);
    assert_eq!(count(&f.conn, "audit_events"), events);
    f.conn.execute_batch("DROP TRIGGER fail_audit;").unwrap();
    election::rename(&mut f.conn, &f.admin, e, "Saved with audit").unwrap();
    assert_eq!(
        election::get(&f.conn, &f.admin, e).unwrap().name,
        "Saved with audit"
    );
    assert_eq!(count(&f.conn, "audit_events"), events + 1);
}

#[test]
fn inbox_uses_phone_filename_and_rejects_paths() {
    let f = Fixture::new();
    f.auth.deliver("+15550000001", "Login OTP: 123456").unwrap();
    assert_eq!(
        fs::read_to_string(f.root.join("+15550000001.txt")).unwrap(),
        "Login OTP: 123456\n"
    );
    f.auth.deliver("engineer", "Setup OTP: 654321").unwrap();
    assert!(f.root.join("engineer.txt").exists());
    for invalid in ["../escape", "/tmp/escape", "..\\escape", "", "123/4567890"] {
        assert!(f.auth.deliver(invalid, "must not write").is_err());
    }
}

#[test]
fn lifecycle_rejections_and_private_atomic_vote_receipt() {
    let mut f = Fixture::new();
    let e = f.create();
    let (v, _) = f.register(e, 1);
    assert!(election::close(&mut f.conn, &f.official, e).is_err());
    election::start(&mut f.conn, &f.official, e).unwrap();
    assert!(election::start(&mut f.conn, &f.official, e).is_err());
    assert!(election::tally(&mut f.conn, &f.official, e).is_err());
    let c = choices(&f.conn, &f.official, e, 0);
    let voter = Session::for_test(v, Role::Voter);
    let receipts = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row(
            "SELECT count(*) FROM notification_outbox WHERE message='thank you for your vote!'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert!(election::cast(&mut f.conn, &voter, e, &c[..1]).is_err());
    assert_eq!(receipts(&f.conn), 0);
    let events = count(&f.conn, "audit_events");
    election::cast(&mut f.conn, &voter, e, &c).unwrap();
    assert_eq!(count(&f.conn, "audit_events"), events);
    assert_eq!(receipts(&f.conn), 1);
    assert_eq!(
        election::cast(&mut f.conn, &voter, e, &c)
            .unwrap_err()
            .to_string(),
        "you already voted bruh"
    );
    assert_eq!(count(&f.conn, "audit_events"), events);
    assert_eq!(receipts(&f.conn), 1);
    election::close(&mut f.conn, &f.official, e).unwrap();
    assert!(election::start(&mut f.conn, &f.official, e).is_err());
    assert!(election::close(&mut f.conn, &f.official, e).is_err());
    election::tally(&mut f.conn, &f.official, e).unwrap();
    assert!(election::start(&mut f.conn, &f.official, e).is_err());
}

#[test]
fn final_results_and_timestamps_survive_repeated_tally_and_sql_tampering() {
    let mut f = Fixture::new();
    let e = f.create();
    let (v, _) = f.register(e, 1);
    let c = choices(&f.conn, &f.admin, e, 0);
    election::start(&mut f.conn, &f.official, e).unwrap();
    election::cast(&mut f.conn, &Session::for_test(v, Role::Voter), e, &c).unwrap();
    election::close(&mut f.conn, &f.official, e).unwrap();
    election::tally(&mut f.conn, &f.official, e).unwrap();
    election::announce(&mut f.conn, &f.official, e).unwrap();
    let snapshot = |conn: &Connection| -> (String, String, i64) {
        conn.query_row("SELECT tallied_at,announced_at,(SELECT sum(votes) FROM candidate_results) FROM elections WHERE election_id=?1", [e], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
    };
    let before = snapshot(&f.conn);
    for _ in 0..3 {
        assert!(election::tally(&mut f.conn, &f.official, e).is_err());
        assert!(election::announce(&mut f.conn, &f.official, e).is_err());
    }
    for sql in [
        "UPDATE candidate_results SET votes=999",
        "DELETE FROM candidate_results",
        "UPDATE party_results SET votes=999",
        "DELETE FROM party_results",
        "UPDATE elections SET tallied_at='forged'",
        "UPDATE elections SET announced_at=NULL",
        "INSERT OR REPLACE INTO candidate_results SELECT * FROM candidate_results",
    ] {
        assert!(f.conn.execute(sql, []).is_err(), "{sql}");
    }
    assert_eq!(snapshot(&f.conn), before);
    for (event, expected, severity) in [
        ("election_tallied", 1, 0),
        ("results_announced", 1, 0),
        ("tally_rejected", 3, 2),
        ("announcement_rejected", 3, 2),
    ] {
        let n: i64 = f.conn.query_row("SELECT count(*) FROM audit_events WHERE event_type=?1 AND severity=?2 AND actor_user_id=?3 AND election_id=?4", params![event,severity,f.official.user_id(),e], |r| r.get(0)).unwrap();
        assert_eq!(n, expected, "{event}");
    }
}

#[test]
fn tally_audit_failure_rolls_back_totals_and_timestamp() {
    let mut f = Fixture::new();
    let e = f.create();
    election::start(&mut f.conn, &f.official, e).unwrap();
    election::close(&mut f.conn, &f.official, e).unwrap();
    f.conn.execute_batch("CREATE TRIGGER fail_tally BEFORE INSERT ON audit_events WHEN NEW.event_type='election_tallied' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    assert!(election::tally(&mut f.conn, &f.official, e).is_err());
    assert_eq!(count(&f.conn, "candidate_results"), 0);
    assert_eq!(count(&f.conn, "party_results"), 0);
    assert_eq!(
        election::get(&f.conn, &f.official, e).unwrap().status,
        "closed"
    );
    f.conn.execute_batch("DROP TRIGGER fail_tally").unwrap();
    election::tally(&mut f.conn, &f.official, e).unwrap();
}

#[test]
fn voter_events_are_aggregate_only_and_identity_inserts_are_blocked() {
    let mut f = Fixture::new();
    let e = f.create();
    let (v, pin) = f.register(e, 1);
    let audit_before = count(&f.conn, "audit_events");
    let security_before = count(&f.conn, "security_events");
    for event in [
        "pin_failed",
        "otp_failed",
        "otp_expired",
        "authentication_locked",
        "authentication_blocked",
        "client_error",
        "authorization_denied",
        "request_rejected",
        "request_timeout",
    ] {
        crate::security::event(&f.conn, Some(v), event, None, 1).unwrap();
        let n: i64 = f
            .conn
            .query_row(
                "SELECT total FROM voter_security_counts WHERE event_type=?1",
                [event],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "{event}");
    }
    crate::security::event(&f.conn, None, "pin_failed", Some("pin:anonymous-test"), 1).unwrap();
    let mut pending = Some(f.auth.pin_login(&f.conn, &pin).unwrap());
    let otp = message(&f.root, &input(1).phone, "Login OTP: ");
    f.auth.complete_otp(&f.conn, &mut pending, &otp).unwrap();
    assert_eq!(count(&f.conn, "audit_events"), audit_before);
    assert_eq!(count(&f.conn, "security_events"), security_before);
    assert!(super::audit(&f.conn, Some(e), Some(v), None, "client_error", 3).is_err());
    assert!(f.conn.execute("INSERT INTO audit_events(actor_user_id,event_type,severity) VALUES (?1,'client_error',3)",[v]).is_err());
    assert!(f
        .conn
        .execute(
            "INSERT INTO security_events(user_id,event_type,attempts) VALUES (?1,'otp_failed',1)",
            [v]
        )
        .is_err());
    assert!(f.conn.execute("INSERT INTO security_events(event_type,scope,attempts) VALUES ('pin_failed','pin:forged',1)",[]).is_err());
}

#[test]
fn receipt_confirmation_is_owned_private_and_audited_for_both_answers() {
    let mut f = Fixture::new();
    let e = f.create();
    let (v, _) = f.register(e, 1);
    for received in [true, false] {
        voters::pin_receipt(&f.conn, &f.admin, e, v, received).unwrap();
    }
    assert!(voters::pin_receipt(&f.conn, &f.official, e, v, true).is_err());
    assert!(voters::pin_receipt(&f.conn, &f.admin, e, v + 999, true).is_err());
    let n:i64 = f.conn.query_row("SELECT count(*) FROM audit_events WHERE event_type LIKE 'pin_receipt_%' AND actor_user_id=1 AND subject_user_id IS NULL",[],|r|r.get(0)).unwrap();
    assert_eq!(n, 2);
    election::delete(&mut f.conn, &f.admin, e).unwrap();
    assert_eq!(election::audit_list(&f.conn, &f.admin).unwrap()[0].id, e);
    assert!(election::audit_list(&f.conn, &f.official).is_err());
}

#[test]
fn incident_audits_are_owner_scoped_and_append_only() {
    let mut f = Fixture::new();
    let e = f.create();
    election::flag_incident(&f.conn, &f.admin, e).unwrap();
    let log = election::audit_log(&f.conn, &f.admin, e)
        .unwrap()
        .join("\n");
    assert!(log.contains("unidentified_change_reported") && log.contains("level 2"));
    assert!(election::flag_incident(&f.conn, &f.official, e).is_err());
    assert!(election::audit_log(&f.conn, &Session::for_test(999, Role::Admin), e).is_err());
    for sql in [
        "UPDATE audit_events SET severity=0",
        "DELETE FROM audit_events",
        "UPDATE security_events SET attempts=0",
        "DELETE FROM security_events",
    ] {
        // Ensure the security table has a row, so its trigger is exercised.
        crate::security::event(&f.conn, Some(1), "password_failed", None, 1).unwrap();
        assert!(f.conn.execute(sql, []).is_err(), "{sql}");
    }
}
