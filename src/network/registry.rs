//! Fictional read-only statewide registry, isolated behind an authenticated TLS service.
use super::*;

#[derive(Debug)]
enum Rejection {
    Missing,
    Mismatch,
    Underage,
    Unavailable,
}
impl Rejection {
    fn event(&self) -> &'static str {
        match self {
            Self::Missing => "voter_identifier_not_found",
            Self::Mismatch => "voter_registry_mismatch",
            Self::Underage => "voter_not_eligible_underage",
            Self::Unavailable => "voter_registry_unavailable",
        }
    }
}
impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "This user does not have a state-wide identifier to take part in this election.",
            Self::Mismatch => "Name, DOB and phone must match the statewide voter ID record. See demo/voter_ids.txt.",
            Self::Underage => "Voter is not eligible to vote: must be at least 18 years old.",
            Self::Unavailable => "Statewide registry unavailable; registration is blocked.",
        })
    }
}
impl std::error::Error for Rejection {}

pub(super) struct Registry {
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
}
impl Registry {
    pub(super) fn verify(&self, id: &str, name: &str, dob: &str, phone: &str) -> AppResult<()> {
        let reply = tls::exchange(
            self.address,
            self.config.clone(),
            &Request {
                deadline_ms: crate::security::now_ms() + 5_000,
                role: Role::Admin,
                token: None,
                operation: "registry.verify".into(),
                args: serde_json::json!([id, name, dob, phone]),
            },
        )
        .map_err(|_| Rejection::Unavailable)?;
        match reply.value.as_str().filter(|_| reply.error.is_none()) {
            Some("valid") => Ok(()),
            Some("missing") => Err(Rejection::Missing.into()),
            Some("mismatch") => Err(Rejection::Mismatch.into()),
            Some("underage") => Err(Rejection::Underage.into()),
            _ => Err(Rejection::Unavailable.into()),
        }
    }
    pub(super) fn registration(
        &self,
        conn: &Connection,
        session: &auth::login::Session,
        election: i64,
        input: &VoterInput,
    ) -> AppResult<VoterInput> {
        services::voters::enrollment_allowed(conn, session, election)?;
        let input = crate::validation::voter_fields(input)?;
        let result = if crate::validation::voter(&input).is_err() {
            Err(Rejection::Underage.into())
        } else {
            self.verify(&input.nid, &input.full_name, &input.dob, &input.phone)
        };
        if let Err(error) = result {
            let kind = error
                .downcast_ref::<Rejection>()
                .map_or("voter_registry_unavailable", Rejection::event);
            services::audit(conn, Some(election), Some(session.user_id()), None, kind, 2)?;
            return Err(error);
        }
        Ok(input)
    }
}
fn registry_database() -> AppResult<Connection> {
    #[cfg(not(test))]
    let conn = Connection::open_with_flags(
        std::env::var("VOTING_REGISTRY_DB")
            .unwrap_or_else(|_| "demo/statewide_voters.sqlite".into()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    #[cfg(test)]
    let conn = {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(include_str!("../../demo/registry.sql"))?;
        let add = |id: &str, name: &str, dob: &str, phone: &str| {
            conn.execute(
                "INSERT INTO government_voters VALUES (?1,?2,?3,?4)",
                rusqlite::params![id, name, dob, phone],
            )
        };
        add("TLS-VOTER", "Network Voter", "2000-01-02", "+15550000003")?;
        add("UI-NID", "Voter UI", "2001-02-03", "+15550000999")?;
        for n in 0..100 {
            let v = crate::test_support::input(n);
            add(&v.nid, &v.full_name, &v.dob, &v.phone)?;
        }
        conn
    };
    conn.execute_batch("PRAGMA query_only=ON;")?;
    Ok(conn)
}
pub(super) fn start(stop: Arc<AtomicBool>) -> AppResult<(Registry, thread::JoinHandle<()>)> {
    let conn = registry_database()?;
    let db = Arc::new(Mutex::new(conn));
    let certs = tls::Certificates::generate()?;
    let client_cert = certs.gateways[0].cert.clone();
    let config = tls::client_config(&certs.ca, Some(&certs.gateways[0]))?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let worker = server::listen(
        listener,
        certs.server_config(true)?,
        stop,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        move |req, peer| {
            let result: AppResult<Value> = (|| {
                if peer.as_ref() != Some(&client_cert) || req.operation != "registry.verify" {
                    return Err("Registry access denied.".into());
                }
                let (id, name, dob, phone): (String, String, String, String) =
                    serde_json::from_value(req.args)?;
                let db = db.lock().map_err(|_| "Registry unavailable")?;
                use rusqlite::OptionalExtension;
                let row: Option<(String, String, String)> = db.query_row(
                    "SELECT full_name,dob,phone_number FROM government_voters WHERE voter_id=?1",
                    [id.trim().to_uppercase()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
                let status = match row {
                    None => "missing",
                    Some((stored_name, stored_dob, stored_phone)) => {
                        let birth = chrono::NaiveDate::parse_from_str(&stored_dob, "%Y-%m-%d")?;
                        let today = chrono::Utc::now()
                            .with_timezone(&chrono_tz::America::New_York)
                            .date_naive();
                        if crate::validation::adult_on(birth, today).is_err() {
                            "underage"
                        } else if !stored_name.eq_ignore_ascii_case(name.trim())
                            || stored_dob != dob
                            || stored_phone != phone
                        {
                            "mismatch"
                        } else {
                            "valid"
                        }
                    }
                };
                Ok(Value::String(status.into()))
            })();
            match result {
                Ok(value) => Response { value, error: None },
                Err(e) => Response {
                    value: Value::Null,
                    error: Some(e.to_string()),
                },
            }
        },
    )?;
    Ok((Registry { address, config }, worker))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shipped_registry_matches_documented_records_and_is_read_only() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/statewide_voters.sqlite");
        let conn =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        for line in include_str!("../../demo/voter_ids.txt")
            .lines()
            .filter(|line| line.contains('|') && !line.starts_with('#'))
        {
            let row: Vec<_> = line.split('|').collect();
            let found: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM government_voters WHERE voter_id=?1 AND full_name=?2 AND dob=?3 AND phone_number=?4)", rusqlite::params![row[0],row[1],row[2],row[3]], |r|r.get(0)).unwrap();
            assert!(found);
        }
        assert!(conn.execute("DELETE FROM government_voters", []).is_err());
    }
    #[test]
    fn registry_tls_fails_closed_and_requires_client_certificate() {
        let stop = Arc::new(AtomicBool::new(false));
        let (registry, worker) = start(stop.clone()).unwrap();
        assert!(registry
            .verify("DEMO-NY-001", "Afia Demo", "2000-01-02", "+15551234567")
            .is_ok());
        assert!(registry
            .verify("DEMO-NY-001", "Someone Else", "2000-01-02", "+15551234567")
            .is_err());
        let untrusted = tls::Certificates::generate().unwrap();
        let reply = tls::exchange(
            registry.address,
            tls::client_config(&untrusted.ca, None).unwrap(),
            &Request {
                deadline_ms: 0,
                role: Role::Admin,
                token: None,
                operation: "registry.verify".into(),
                args: serde_json::json!(["DEMO-NY-001", "Afia Demo", "2000-01-02"]),
            },
        );
        assert!(reply.is_err());
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        let mut f = crate::test_support::Fixture::new();
        let e = f.create();
        assert!(registry
            .registration(&f.conn, &f.admin, e, &crate::test_support::input(1))
            .is_err());
        let warnings:i64=f.conn.query_row("SELECT count(*) FROM audit_events WHERE event_type='voter_registry_unavailable' AND severity=2 AND subject_user_id IS NULL",[],|r|r.get(0)).unwrap();
        assert_eq!(warnings, 1);

        assert!(registry
            .verify("DEMO-NY-001", "Afia Demo", "2000-01-02", "+15551234567")
            .is_err());
    }
}
