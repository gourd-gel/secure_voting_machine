//! These tests use actual TCP sockets and both TLS hops, not mocked transports.
use super::*;
use std::{
    fs,
    io::{Read, Write},
};
struct Fixture {
    network: Network,
    root: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("tls-voting-{}", Uuid::new_v4()));
        let mut conn = Connection::open_in_memory().unwrap();
        crate::database::initialize(&mut conn).unwrap();
        let auth = auth::login::Auth::for_test(root.clone());
        services::voters::provision(
            &mut conn,
            &auth,
            "admin@example.test",
            "+15550000001",
            "Admin",
            "password1234",
            Role::Admin,
        )
        .unwrap();
        services::voters::provision(
            &mut conn,
            &auth,
            "do@example.test",
            "+15550000002",
            "Official",
            "password1234",
            Role::DistrictOfficial,
        )
        .unwrap();
        let network = Network::start(
            conn,
            auth,
            tls::Certificates::generate().unwrap(),
            None,
            false,
        )
        .unwrap();
        Self { network, root }
    }
    fn message(&self, phone: &str, prefix: &str) -> String {
        fs::read_to_string(auth::login::mailbox_path(&self.root, phone).unwrap())
            .unwrap()
            .lines()
            .filter_map(|s| s.strip_prefix(prefix))
            .next_back()
            .unwrap()
            .to_owned()
    }
    fn login(&self, role: Role) -> Session {
        let (email, phone) = if role == Role::Admin {
            ("admin@example.test", "+15550000001")
        } else {
            ("do@example.test", "+15550000002")
        };
        let mut pending = Some(
            ClientAuth
                .password_login(&self.network.client, email, "password1234", role)
                .unwrap(),
        );
        let code = self.message(phone, "Login OTP: ");
        ClientAuth
            .complete_otp(&self.network.client, &mut pending, &code)
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn real_tls_full_election_and_role_privacy() {
    let f = Fixture::new();
    let mut api = f.network.client.clone();
    let admin = f.login(Role::Admin);
    let official = f.login(Role::DistrictOfficial);
    let e = client::election::create(&mut api, &admin, "TLS Election").unwrap();
    client::voters::register(
        &mut api,
        &ClientAuth,
        &admin,
        e,
        &VoterInput {
            full_name: "Network Voter".into(),
            email: "v@example.test".into(),
            phone: "+15550000003".into(),
            dob: "2000-01-02".into(),
            nid: "TLS-VOTER".into(),
        },
    )
    .unwrap();
    let pin = f.message("+15550000003", "Voting PIN: ");
    let mut pending = Some(ClientAuth.pin_login(&api, &pin).unwrap());
    let code = f.message("+15550000003", "Login OTP: ");
    let voter = ClientAuth.complete_otp(&api, &mut pending, &code).unwrap();
    let errors_before = f.network.count("error_reports");
    api.request::<Value>(
        Role::Voter,
        Some(voter.token.clone()),
        "error",
        json!(["voter-secret", "forged\nlog"]),
    )
    .unwrap();
    assert_eq!(f.network.count("error_reports"), errors_before);
    {
        let state = f.network.state.lock().unwrap();
        let n: i64 = state
            .conn
            .query_row(
                "SELECT total FROM voter_security_counts WHERE event_type='client_error'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    assert!(client::election::start(&mut api, &admin, e).is_err());
    client::election::start(&mut api, &official, e).unwrap();
    let positions = client::election::positions(&api, &voter, e).unwrap();
    let choices: Vec<_> = positions
        .iter()
        .map(|p| (p.id, p.candidates[0].id))
        .collect();
    client::election::cast(&mut api, &voter, e, &choices).unwrap();
    assert!(client::election::cast(&mut api, &voter, e, &choices).is_err());
    assert!(client::election::results(&api, &admin, e).is_err());
    assert!(client::voters::list(&api, &voter, e).is_err());
    client::election::close(&mut api, &official, e).unwrap();
    client::election::tally(&mut api, &official, e).unwrap();
    client::election::announce(&mut api, &official, e).unwrap();
    assert_eq!(
        client::election::results(&api, &official, e)
            .unwrap()
            .iter()
            .map(|r| r.votes)
            .sum::<i64>(),
        3
    );
    let log = client::election::audit_log(&api, &admin, e)
        .unwrap()
        .join("\n");
    assert!(!log.contains("voter_participated"));
    assert!(!log.contains(&pin));
    assert!(!log.contains("Hamberger"));
    assert_eq!(f.network.count("ballot_choices"), 3);
    api.logout(&admin).unwrap();
    assert!(client::election::list(&api, &admin).is_err());
}
#[test]
fn tls_rejects_untrusted_ca_wrong_hostname_plaintext_and_missing_client_certificate() {
    let f = Fixture::new();
    let api = &f.network.client;
    let request = Request {
        deadline_ms: crate::security::now_ms() + 10_000,
        role: Role::Admin,
        token: None,
        operation: "election.list".into(),
        args: Value::Null,
    };
    let wrong = tls::Certificates::generate().unwrap();
    assert!(tls::exchange(
        api.addresses[0],
        tls::client_config(&wrong.ca, None).unwrap(),
        &request
    )
    .is_err());
    assert!(tls::exchange_named(
        api.addresses[0],
        api.config.clone(),
        &request,
        "attacker.invalid"
    )
    .is_err());
    assert!(tls::exchange(f.network.db_address, api.config.clone(), &request).is_err());
    let mut plain = tls::socket(api.addresses[0]).unwrap();
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut bytes = [0; 128];
    let result = plain.read(&mut bytes);
    assert!(result.is_err() || result.unwrap() == 0 || bytes[0] == 21); // TLS alert, never application JSON.
}
#[test]
fn session_and_challenge_cannot_be_forged_replayed_or_used_on_another_gateway() {
    let f = Fixture::new();
    let api = &f.network.client;
    let mut pending = Some(
        ClientAuth
            .password_login(api, "admin@example.test", "password1234", Role::Admin)
            .unwrap(),
    );
    let challenge = pending.as_ref().unwrap().token.clone();
    let code = f.message("+15550000001", "Login OTP: ");
    let admin = ClientAuth.complete_otp(api, &mut pending, &code).unwrap();
    assert!(api
        .request::<Session>(Role::Admin, Some(challenge), "otp", json!([code]))
        .is_err());
    assert!(api
        .request::<Vec<Election>>(
            Role::Admin,
            Some("forged-session".into()),
            "election.list",
            Value::Null
        )
        .is_err());
    assert!(api
        .request::<Vec<Election>>(
            Role::DistrictOfficial,
            Some(admin.token.clone()),
            "election.list",
            Value::Null
        )
        .is_err());
    let request = Request {
        deadline_ms: crate::security::now_ms() + 10_000,
        role: Role::Voter,
        token: Some(admin.token.clone()),
        operation: "election.list".into(),
        args: Value::Null,
    };
    assert!(
        tls::exchange(api.addresses[0], api.config.clone(), &request)
            .unwrap()
            .error
            .is_some()
    );
    // Session metadata is display-only. The server ignores a client-edited user ID.
    let mut forged = admin.clone();
    forged.user_id = 9999;
    assert!(client::election::list(api, &forged).is_ok());
    f.network
        .state
        .lock()
        .unwrap()
        .sessions
        .get_mut(&admin.token)
        .unwrap()
        .expires = Instant::now();
    assert!(client::election::list(api, &admin).is_err());
}
#[test]
fn otp_expiration_retry_limit_and_setup_rejection_over_tls() {
    let f = Fixture::new();
    let api = &f.network.client;
    let mut pending = Some(
        ClientAuth
            .password_login(api, "admin@example.test", "password1234", Role::Admin)
            .unwrap(),
    );
    let code = f.message("+15550000001", "Login OTP: ");
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..3 {
        assert!(ClientAuth.complete_otp(api, &mut pending, wrong).is_err());
    }
    assert!(ClientAuth.complete_otp(api, &mut pending, &code).is_err());
    let mut pending = Some(
        ClientAuth
            .password_login(
                api,
                "do@example.test",
                "password1234",
                Role::DistrictOfficial,
            )
            .unwrap(),
    );
    let code = f.message("+15550000002", "Login OTP: ");
    f.network
        .state
        .lock()
        .unwrap()
        .pending
        .get_mut(&pending.as_ref().unwrap().token)
        .unwrap()
        .expires = Instant::now();
    assert!(ClientAuth.complete_otp(api, &mut pending, &code).is_err());
    assert!(api
        .request::<()>(
            Role::Admin,
            None,
            "provision",
            json!([
                "bad@example.test",
                "+15550000005",
                "Bad",
                "password1234",
                Role::Admin
            ])
        )
        .is_err());
}
#[test]
fn framing_rejects_oversized_messages_before_allocating_payload() {
    let bytes = (1024u32 * 1024 + 1).to_be_bytes();
    assert!(tls::read_frame::<Request>(&mut &bytes[..]).is_err());
}

#[test]
fn internal_certificate_role_binding_and_transport_incident_log() {
    let root = std::env::temp_dir().join(format!("tls-identity-{}", Uuid::new_v4()));
    let mut conn = Connection::open_in_memory().unwrap();
    crate::database::initialize(&mut conn).unwrap();
    let certs = tls::Certificates::generate().unwrap();
    let admin_config = tls::client_config(&certs.ca, Some(&certs.gateways[0])).unwrap();
    let net = Network::start(
        conn,
        auth::login::Auth::for_test(root.clone()),
        certs,
        None,
        false,
    )
    .unwrap();
    let request = Request {
        deadline_ms: crate::security::now_ms() + 10_000,
        role: Role::DistrictOfficial,
        token: None,
        operation: "election.list".into(),
        args: Value::Null,
    };
    let response = tls::exchange(net.db_address, admin_config, &request).unwrap();
    assert_eq!(response.error.as_deref(), Some("Wrong role gateway."));
    for _ in 0..11 {
        let mut socket = tls::socket(net.client.addresses[0]).unwrap();
        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut byte = [0];
        let _ = socket.read(&mut byte);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let count:i64=net.state.lock().unwrap().conn.query_row("SELECT COUNT(*) FROM audit_events WHERE event_type='tls_or_protocol_flood' AND severity=2",[],|r|r.get(0)).unwrap();
        if count > 0 {
            break;
        }
        assert!(Instant::now() < deadline, "TLS flood was not recorded");
        thread::sleep(Duration::from_millis(20));
    }
    drop(net);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn signup_responses_close_tls_cleanly_on_both_hops() {
    use rustls::pki_types::ServerName;
    let root = std::env::temp_dir().join(format!("tls-close-{}", Uuid::new_v4()));
    let mut conn = Connection::open_in_memory().unwrap();
    crate::database::initialize(&mut conn).unwrap();
    let certs = tls::Certificates::generate().unwrap();
    let internal = tls::client_config(&certs.ca, Some(&certs.gateways[0])).unwrap();
    let net = Network::start(
        conn,
        auth::login::Auth::for_test(root.clone()),
        certs,
        None,
        true,
    )
    .unwrap();
    for (i, address, config) in [
        (0, net.client.addresses[0], net.client.config.clone()),
        (1, net.db_address, internal),
    ] {
        let connection =
            rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut stream = rustls::StreamOwned::new(connection, tls::socket(address).unwrap());
        let role = if i == 0 {
            Role::Admin
        } else {
            Role::DistrictOfficial
        };
        let request = Request {
            deadline_ms: crate::security::now_ms() + 10_000,
            role: Role::Admin,
            token: net.client.setup_token.clone(),
            operation: "provision".into(),
            args: json!([
                format!("staff{i}@example.test"),
                format!("+1555000000{i}"),
                "Staff",
                "password1234",
                role
            ]),
        };
        tls::write_frame(&mut stream, &request).unwrap();
        let reply: Response = tls::read_frame(&mut stream).unwrap();
        assert!(reply.error.is_none(), "{:?}", reply.error);
        let mut byte = [0];
        assert_eq!(
            stream
                .read(&mut byte)
                .expect("server must send close_notify after signup response"),
            0
        );
        stream.conn.send_close_notify();
        let _ = stream.flush();
    }
    assert_eq!(net.count("user_credentials"), 2);
    drop(net);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn incomplete_frames_are_rejected_even_when_the_peer_closes() {
    let bytes = [0, 0, 0, 8, b'{', b'}'];
    let error = tls::read_frame::<Value>(&mut &bytes[..]).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn client_rejects_response_after_ten_second_deadline() {
    // Reproduce slow debug-build password hashing without burning CPU in bcrypt.
    // Eleven seconds exceeds both the old idle (5s) and whole-request (10s) limits.
    let certs = tls::Certificates::generate().unwrap();
    let server_config = certs.server_config(false).unwrap();
    let client_config = tls::client_config(&certs.ca, None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        tls::configure(&socket).unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(server_config).unwrap(),
            tls::DeadlineSocket::new(socket),
        );
        let _: Request = tls::read_frame(&mut stream).unwrap();
        stream.sock.begin_response();
        let mut byte = [0];
        assert_eq!(
            stream
                .read(&mut byte)
                .expect("client must send close_notify"),
            0
        );
        thread::sleep(Duration::from_secs(11));
        let _ = tls::write_frame(
            &mut stream,
            &Response {
                value: json!("late"),
                error: None,
            },
        );
    });
    let request = Request {
        deadline_ms: crate::security::now_ms() + 10_000,
        role: Role::Admin,
        token: None,
        operation: "test".into(),
        args: Value::Null,
    };
    let result = tls::exchange(address, client_config, &request);
    server.join().unwrap();
    assert!(result.is_err());
}

#[test]
fn configured_worker_waits_for_data_on_an_inherited_nonblocking_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    // Model BSD/macOS inheritance explicitly so Linux exercises the same case.
    server.set_nonblocking(true).unwrap();
    tls::configure(&server).unwrap();
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        client.write_all(b"x").unwrap();
    });
    let mut byte = [0];
    let result = server.read_exact(&mut byte);
    writer.join().unwrap();
    result.expect("configured TLS worker must wait instead of returning WouldBlock");
    assert_eq!(byte, *b"x");
}

#[test]
fn direct_endpoints_reject_bad_fields_and_cross_role_reads() {
    let f = Fixture::new();
    let admin = f.login(Role::Admin);
    let official = f.login(Role::DistrictOfficial);
    let client = &f.network.client;
    let e = client::election::create(&mut client.clone(), &admin, "Privacy test").unwrap();
    let request = |session: &Session, op: &str, args: Value| -> AppResult<Value> {
        client.request(session.role, Some(session.token.clone()), op, args)
    };
    assert!(request(&official, "voters.list", json!([e])).is_err());
    assert!(request(&official, "election.audit_log", json!([e])).is_err());
    assert!(request(&admin, "election.results", json!([e])).is_err());
    assert!(request(&admin, "ballots.list", json!([e])).is_err());
    assert!(request(&admin, "election.rename", json!([e, ""])).is_err());
    assert!(request(&admin, "election.rename", json!([e, "x".repeat(201)])).is_err());
    assert!(request(&admin, "election.rename", json!({"bad":"shape"})).is_err());
    assert!(request(
        &admin,
        "voters.register",
        json!([e,{"full_name":"V","dob":"2001-02-29","nid":"N","phone":"1234567","email":""}])
    )
    .is_err());
    request(
        &admin,
        "error",
        json!(["secret-in-screen", "secret-in-body\nforged audit event"]),
    )
    .unwrap();
    let state = f.network.state.lock().unwrap();
    let saved: String = state
        .conn
        .query_row(
            "SELECT screen||message FROM error_reports ORDER BY error_id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!saved.contains("secret"));
    assert!(!saved.contains("forged"));
    drop(state);
    assert_eq!(f.network.count("election_voters"), 0);
    assert_eq!(f.network.count("elections"), 1);
}

#[test]
fn expired_wire_request_cannot_create_election() {
    let f = Fixture::new();
    let admin = f.login(Role::Admin);
    let mut stream = rustls::StreamOwned::new(
        rustls::ClientConnection::new(
            f.network.client.config.clone(),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap(),
        tls::socket(f.network.client.addresses[0]).unwrap(),
    );
    let request = Request {
        deadline_ms: crate::security::now_ms().saturating_sub(1),
        role: Role::Admin,
        token: Some(admin.token),
        operation: "election.create".into(),
        args: json!(["Expired"]),
    };
    tls::write_frame(&mut stream, &request).unwrap();
    let response: Response = tls::read_frame(&mut stream).unwrap();
    assert!(response.error.is_some());
    assert_eq!(f.network.count("elections"), 0);
}

#[test]
fn server_watchdog_closes_stalled_handler_and_counts_timeout() {
    let certs = tls::Certificates::generate().unwrap();
    let config = tls::client_config(&certs.ca, None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let timeouts = Arc::new(AtomicUsize::new(0));
    let worker = server::listen(
        listener,
        certs.server_config(false).unwrap(),
        stop.clone(),
        Arc::new(AtomicUsize::new(0)),
        timeouts.clone(),
        |_, _| {
            thread::sleep(Duration::from_secs(11));
            Response {
                value: Value::Null,
                error: None,
            }
        },
    )
    .unwrap();
    let mut socket = tls::socket(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(12)))
        .unwrap();
    let connection = rustls::ClientConnection::new(
        config,
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut stream = rustls::StreamOwned::new(connection, &mut socket);
    let start = Instant::now();
    tls::write_frame(
        &mut stream,
        &Request {
            deadline_ms: crate::security::now_ms() + 10_000,
            role: Role::Admin,
            token: None,
            operation: "test".into(),
            args: Value::Null,
        },
    )
    .unwrap();
    let result: AppResult<Response> = tls::read_frame(&mut stream);
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(11));
    stop.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    assert_eq!(timeouts.load(Ordering::Relaxed), 1);
}

#[test]
fn registry_rejects_unknown_mismatched_and_underage_without_writes() {
    let f = Fixture::new();
    let mut api = f.network.client.clone();
    let admin = f.login(Role::Admin);
    let e = client::election::create(&mut api, &admin, "Eligibility").unwrap();
    let mut input = VoterInput {
        full_name: "Afia Demo".into(),
        dob: "2000-01-02".into(),
        nid: "DEMO-NY-001".into(),
        phone: "+15551234567".into(),
        email: "".into(),
    };
    for (id, dob) in [
        ("NO-SUCH-ID", "2000-01-02"),
        ("DEMO-NY-001", "2000-01-03"),
        ("DEMO-NY-001", "2020-01-02"),
    ] {
        input.nid = id.into();
        input.dob = dob.into();
        assert!(client::voters::register(&mut api, &ClientAuth, &admin, e, &input).is_err());
        assert_eq!(f.network.count("voter_pin_credentials"), 0);
        assert_eq!(f.network.count("election_voters"), 0);
    }
    input.nid = "DEMO-NY-001".into();
    input.dob = "2000-01-02".into();
    client::voters::register(&mut api, &ClientAuth, &admin, e, &input).unwrap();
    assert_eq!(f.network.count("voter_pin_credentials"), 1);
}

#[test]
fn registry_phone_forgery_minor_and_injection_attempts_have_private_audits() {
    let f = Fixture::new();
    let mut api = f.network.client.clone();
    let admin = f.login(Role::Admin);
    let e = client::election::create(&mut api, &admin, "Registry attacks").unwrap();
    for (nid, name, dob, phone, event) in [
        (
            "' OR 1=1 --",
            "Afia Demo",
            "2000-01-02",
            "+15551234567",
            "voter_identifier_not_found",
        ),
        (
            "DEMO-NY-001",
            "Afia Demo",
            "2000-01-02",
            "+15559999999",
            "voter_registry_mismatch",
        ),
        (
            "DEMO-NY-MINOR",
            "Young Demo",
            "2000-01-02",
            "+15551234569",
            "voter_not_eligible_underage",
        ),
        (
            "DEMO-NY-001",
            "Afia Demo",
            "2020-01-02",
            "+15551234567",
            "voter_not_eligible_underage",
        ),
    ] {
        let input = VoterInput {
            nid: nid.into(),
            full_name: name.into(),
            dob: dob.into(),
            phone: phone.into(),
            email: "".into(),
        };
        assert!(client::voters::register(&mut api, &ClientAuth, &admin, e, &input).is_err());
        assert_eq!(f.network.count("voter_pin_credentials"), 0);
        let state = f.network.state.lock().unwrap();
        let count:i64=state.conn.query_row("SELECT count(*) FROM audit_events WHERE event_type=?1 AND actor_user_id=1 AND subject_user_id IS NULL AND election_id=?2 AND severity=2",rusqlite::params![event,e],|r|r.get(0)).unwrap();
        assert!(count > 0, "{event}");
    }
    assert!(!f.root.join("+15559999999.txt").exists());
    let input = VoterInput {
        nid: "DEMO-NY-001".into(),
        full_name: "Afia Demo".into(),
        dob: "2000-01-02".into(),
        phone: "+15551234567".into(),
        email: "".into(),
    };
    let voter = client::voters::register(&mut api, &ClientAuth, &admin, e, &input).unwrap();
    for received in [false, true] {
        client::voters::pin_receipt(&api, &admin, e, voter, received).unwrap();
    }
    let audit = client::election::audit_log(&api, &admin, e)
        .unwrap()
        .join("\n");
    for secret in [&input.nid, &input.full_name, &input.phone, &input.dob] {
        assert!(!audit.contains(secret));
    }
}

#[test]
fn unauthenticated_voter_failures_do_not_make_individual_request_logs() {
    let f = Fixture::new();
    let before = f.network.count("audit_events");
    assert!(ClientAuth
        .pin_login(&f.network.client, "00000000000000000000")
        .is_err());
    assert_eq!(f.network.count("audit_events"), before);
    let state = f.network.state.lock().unwrap();
    for event in ["pin_failed", "request_rejected"] {
        let count: i64 = state
            .conn
            .query_row(
                "SELECT total FROM voter_security_counts WHERE event_type=?1",
                [event],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
