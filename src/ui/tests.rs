//! UI events and rendering tested against live TLS endpoints.
use super::*;
use crate::{
    auth::login::{Auth, Session},
    database,
    services::{election, voters},
    test_support::*,
};
use ratatui::{backend::TestBackend, Terminal};
use rusqlite::Connection;
fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
fn fill(app: &mut App, values: &[&str]) {
    for (f, value) in app.form.as_mut().unwrap().fields.iter_mut().zip(values) {
        f.value = (*value).into();
    }
    app.handle_key(key(KeyCode::Enter));
}
fn render(app: &mut App, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app)).unwrap();
    let b = t.backend().buffer();
    let mut out = String::new();
    for y in 0..h {
        for x in 0..w {
            out.push_str(b[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

#[test]
fn ui_login_goes_to_menu_then_create_and_edit_load_database() {
    let f = Fixture::new();
    let root = f.root.clone();
    // Build independent ownership of the connection; no default credentials in App.
    let mut conn = Connection::open_in_memory().unwrap();
    database::initialize(&mut conn).unwrap();
    let auth = Auth::for_test(root.clone());
    voters::provision(
        &mut conn,
        &auth,
        "admin@example.test",
        "+15550000001",
        "Admin",
        "password1234",
        Role::Admin,
    )
    .unwrap();
    let mut app = App::new(conn, auth, false);
    app.handle_key(key(KeyCode::Enter));
    fill(&mut app, &["admin@example.test", "password1234"]);
    assert_eq!(app.screen, Screen::Otp);
    assert!(app.session.is_none());
    let otp = message(&root, "+15550000001", "Login OTP: ");
    fill(&mut app, &[&otp]);
    assert_eq!(app.screen, Screen::AdminHome);
    assert!(app.positions.is_empty());
    assert_eq!(app.network.as_ref().unwrap().count("elections"), 0);
    let screen = render(&mut app, 100, 30);
    assert!(screen.contains("Create new election"));
    assert!(screen.contains("View audit log"));
    assert!(!screen.contains("Hamberger"));
    app.handle_key(key(KeyCode::Enter));
    fill(&mut app, &["UI Election"]);
    assert_eq!(app.screen, Screen::Editor);
    assert_eq!(app.positions.len(), 3);
    app.handle_key(key(KeyCode::Char('p')));
    fill(&mut app, &["UI Position"]);
    assert_eq!(app.positions.len(), 4);
    app.handle_key(key(KeyCode::Char('e')));
    fill(&mut app, &["Renamed President"]);
    assert_eq!(app.positions[0].name, "Renamed President");
    app.handle_key(key(KeyCode::Esc));
    app.selected = 1;
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.positions[0].name, "Renamed President");
    app.handle_key(key(KeyCode::Esc));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.session.is_none());
}

#[test]
fn ui_r_registers_voter_n_does_nothing_and_masks_password() {
    let mut f = Fixture::new();
    let e = f.create();
    let root = f.root.clone();
    let conn = std::mem::replace(&mut f.conn, Connection::open_in_memory().unwrap());
    let mut app = App::new(conn, Auth::for_test(root), false);
    app.session = Some(app.network.as_ref().unwrap().test_session(1, Role::Admin));
    app.election =
        Some(network::client::election::get(&app.conn, app.session.as_ref().unwrap(), e).unwrap());
    app.screen = Screen::Voters;
    app.handle_key(key(KeyCode::Char('n')));
    assert!(app.form.is_none());
    app.handle_key(key(KeyCode::Char('r')));
    fill(
        &mut app,
        &[
            "Voter UI",
            "2001-02-03",
            "UI-NID",
            "+15550000999",
            "ui@example.test",
        ],
    );
    assert!(
        matches!(
            app.form.as_ref().map(|f| f.purpose),
            Some(FormPurpose::PinReceipt(_))
        ),
        "{}",
        app.notice
    );
    fill(&mut app, &["yes"]);
    assert!(app.form.is_none());
    assert_eq!(app.voters.len(), 1);
    assert_eq!(
        app.network.as_ref().unwrap().count("voter_pin_credentials"),
        1
    );
    let pin = message(&f.root, "+15550000999", "Voting PIN: ");
    assert!(!render(&mut app, 100, 30).contains(&pin));
    app.logout();
    app.handle_key(key(KeyCode::Enter));
    app.form.as_mut().unwrap().fields[1].value = "super-secret".into();
    assert!(!render(&mut app, 100, 30).contains("super-secret"));
    assert!(render(&mut app, 30, 8).contains("resize"));
}

#[test]
fn ui_voter_casts_once_and_district_announces_tie() {
    let mut f = Fixture::new();
    let e = f.create();
    let (v, pin) = f.register(e, 1);
    let (v2, _) = f.register(e, 2);
    election::start(&mut f.conn, &f.official, e).unwrap();
    let c = choices(&f.conn, &f.official, e, 1);
    election::cast(&mut f.conn, &Session::for_test(v2, Role::Voter), e, &c).unwrap();
    let conn = std::mem::replace(&mut f.conn, Connection::open_in_memory().unwrap());
    let mut app = App::new(conn, Auth::for_test(f.root.clone()), false);
    app.selected = 2;
    app.handle_key(key(KeyCode::Enter));
    fill(&mut app, &[&pin]);
    let otp = message(&f.root, &input(1).phone, "Login OTP: ");
    fill(&mut app, &[&otp]);
    assert_eq!(app.session.as_ref().unwrap().user_id(), v);
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Vote);
    for row in [0, 2, 4] {
        app.ballot_cursor.row = row;
        app.handle_key(key(KeyCode::Char(' ')));
    }
    app.handle_key(key(KeyCode::Char('s')));
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Main);
    assert!(app.session.is_none());
    assert!(app.elections.is_empty());
    assert!(
        std::fs::read_to_string(auth::login::mailbox_path(&f.root, &input(1).phone).unwrap())
            .unwrap()
            .contains("thank you for your vote!")
    );
    assert_eq!(app.network.as_ref().unwrap().count("ballot_choices"), 6);
    app.logout();
    app.session = Some(
        app.network
            .as_ref()
            .unwrap()
            .test_session(2, Role::DistrictOfficial),
    );
    app.load_elections(SelectionPurpose::District).unwrap();
    app.handle_key(key(KeyCode::Enter));
    for command in ['f', 't', 'a'] {
        app.handle_key(key(KeyCode::Char(command)));
        app.handle_key(key(KeyCode::Enter));
    }
    assert_eq!(app.screen, Screen::Results);
    assert!(app.lines.iter().any(|l| l.contains("Tie:")));
    assert!(render(&mut app, 100, 30).contains("Party totals"));
}

#[test]
fn ui_failed_write_does_not_create_a_local_placeholder() {
    let mut f = Fixture::new();
    let e = f.create();
    let conn = std::mem::replace(&mut f.conn, Connection::open_in_memory().unwrap());
    let mut app = App::new(conn, Auth::for_test(f.root.clone()), false);
    app.session = Some(app.network.as_ref().unwrap().test_session(1, Role::Admin));
    app.election =
        Some(network::client::election::get(&app.conn, app.session.as_ref().unwrap(), e).unwrap());
    app.reload_election().unwrap();
    app.screen = Screen::Editor;
    app.handle_key(key(KeyCode::Char('p')));
    fill(&mut app, &["President"]);
    assert!(app.form.is_some());
    assert_eq!(app.positions.len(), 3);
    assert_eq!(app.network.as_ref().unwrap().count("election_positions"), 3);
}

#[test]
fn ui_empty_results_and_role_switch_do_not_leak_previous_session() {
    let mut f = Fixture::new();
    let e = f.create();
    election::start(&mut f.conn, &f.official, e).unwrap();
    election::close(&mut f.conn, &f.official, e).unwrap();
    election::tally(&mut f.conn, &f.official, e).unwrap();
    let conn = std::mem::replace(&mut f.conn, Connection::open_in_memory().unwrap());
    let mut app = App::new(conn, Auth::for_test(f.root.clone()), false);
    app.session = Some(
        app.network
            .as_ref()
            .unwrap()
            .test_session(2, Role::DistrictOfficial),
    );
    app.load_elections(SelectionPurpose::District).unwrap();
    app.select_election().unwrap();
    app.show_results().unwrap();
    assert_eq!(
        app.lines
            .iter()
            .filter(|l| l.contains("No winner: no votes cast"))
            .count(),
        3
    );
    app.logout();
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Login);
    assert!(app.session.is_none());
    assert!(app.positions.is_empty());
    assert!(app.lines.is_empty());
}

#[test]
fn staff_signup_creates_both_roles_without_granting_a_login_session() {
    let f = Fixture::new();
    let mut conn = Connection::open_in_memory().unwrap();
    database::initialize(&mut conn).unwrap();
    let server = Network::start(
        conn,
        Auth::for_test(f.root.clone()),
        network::tls::Certificates::generate().unwrap(),
        None,
        true,
    )
    .unwrap();
    let mut app = App::signup(server.client.clone()).unwrap();
    assert_eq!(app.screen, Screen::Setup);
    assert!(render(&mut app, 100, 30).contains("Administrator"));
    fill(
        &mut app,
        &[
            "new-admin@example.test",
            "password1234",
            "New Admin",
            "+15550000101",
        ],
    );
    assert!(app.form.is_none(), "{}", app.notice);
    assert!(app.session.is_none());
    assert_eq!(server.count("user_credentials"), 1);
    app.selected = 3;
    app.handle_key(key(KeyCode::Enter));
    app.form.as_mut().unwrap().focus = 4;
    app.handle_key(key(KeyCode::Right));
    assert!(render(&mut app, 100, 30).contains("District Official"));
    fill(
        &mut app,
        &[
            "new-do@example.test",
            "password1234",
            "New Official",
            "+15550000102",
        ],
    );
    assert!(app.form.is_none(), "{}", app.notice);
    assert!(app.session.is_none());
    assert_eq!(server.count("user_credentials"), 2);
    // Verify both stored roles using the real password endpoint; OTP is still required.
    assert!(app
        .auth
        .password_login(
            &app.conn,
            "new-admin@example.test",
            "password1234",
            Role::Admin
        )
        .is_ok());
    assert!(app
        .auth
        .password_login(
            &app.conn,
            "new-do@example.test",
            "password1234",
            Role::DistrictOfficial
        )
        .is_ok());
    assert!(app
        .auth
        .password_login(
            &app.conn,
            "new-do@example.test",
            "password1234",
            Role::Admin
        )
        .is_err());
    app.selected = 3;
    app.handle_key(key(KeyCode::Enter));
    fill(
        &mut app,
        &[
            "new-admin@example.test",
            "password1234",
            "Duplicate",
            "+15550000103",
        ],
    );
    assert!(app.form.is_some());
    assert_eq!(server.count("user_credentials"), 2);
}

#[test]
fn invalid_signup_stays_in_form_without_database_write() {
    let f = Fixture::new();
    let root = f.root.clone();
    let mut conn = Connection::open_in_memory().unwrap();
    database::initialize(&mut conn).unwrap();
    let mut app = App::new(conn, Auth::for_test(root), true);
    app.selected = 3;
    app.handle_key(key(KeyCode::Enter));
    fill(
        &mut app,
        &["not-email", "password1234", "Name", "++12345678", "admin"],
    );
    assert!(app.form.is_some());
    assert_eq!(app.network.as_ref().unwrap().count("users"), 0);
    assert!(!render(&mut app, 100, 30).contains("password1234"));
}
