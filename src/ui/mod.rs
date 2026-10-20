//! UI state and navigation helpers; persistence is accessed through the TLS client.
mod draw;
mod events;
mod forms;
#[cfg(test)]
mod tests;
use crate::network::client::{election, voters};
#[cfg(test)]
use crate::{
    auth,
    network::{self, Network},
};
use crate::{
    models::{Election, Position, Role, Voter, VoterInput},
    network::{ApiClient, ClientAuth, PendingLogin, Session},
    services::AppResult,
};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use draw::draw;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Clear, List, ListState, Paragraph, Wrap},
    DefaultTerminal, Frame,
};
use std::{io, time::Duration};
const ACTIVE: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const HIGHLIGHT: Style = Style::new().fg(Color::Black).bg(Color::Cyan);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Screen {
    Main,
    Login,
    Otp,
    AdminHome,
    Elections,
    Editor,
    Voters,
    Audit,
    District,
    Vote,
    Results,
    Setup,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectionPurpose {
    Edit,
    Register,
    Audit,
    District,
    Vote,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BallotColumn {
    Position,
    Candidate,
    Party,
}
#[derive(Clone, Copy, Debug)]
struct BallotCursor {
    row: usize,
    column: BallotColumn,
}
#[derive(Clone, Copy)]
enum FormPurpose {
    Login(Role),
    Otp,
    NewElection,
    RenameElection,
    AddPosition,
    AddCandidate(i64),
    EditPosition(i64),
    EditCandidate(i64),
    LinkCandidate(i64),
    RegisterVoter,
    PinReceipt(i64),
    UpdateVoter(i64),
    Enroll,
    Setup,
}
struct Field {
    label: &'static str,
    value: String,
    secret: bool,
}
struct Form {
    purpose: FormPurpose,
    title: String,
    fields: Vec<Field>,
    focus: usize,
}
#[derive(Clone, Copy)]
enum Action {
    DeleteElection,
    DeletePosition(i64),
    UnlinkCandidate(i64, i64),
    RemoveVoter(i64),
    Start,
    Close,
    Tally,
    Announce,
    Submit,
}
struct Confirmation {
    message: String,
    action: Action,
}

pub(crate) struct App {
    conn: ApiClient,
    auth: ClientAuth,
    #[cfg(test)]
    network: Option<Network>,
    session: Option<Session>,
    pending: Option<PendingLogin>,
    screen: Screen,
    quit: bool,
    setup_mode: bool,
    selected: usize,
    selection_purpose: SelectionPurpose,
    elections: Vec<Election>,
    election: Option<Election>,
    positions: Vec<Position>,
    voters: Vec<Voter>,
    ballot_cursor: BallotCursor,
    ballot_scroll: usize,
    voting_choices: Vec<Option<i64>>,
    lines: Vec<String>,
    scroll: usize,
    form: Option<Form>,
    confirmation: Option<Confirmation>,
    notice: String,
}
impl App {
    /// Staff registration is an explicit local setup capability, never public signup.
    pub(crate) fn signup(conn: ApiClient) -> AppResult<Self> {
        let mut app = Self::remote(conn, true);
        app.selected = 3;
        app.handle_screen(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))?;
        Ok(app)
    }

    /// Initialize TUI state around an API client without a direct database connection.
    pub(crate) fn remote(conn: ApiClient, setup_mode: bool) -> Self {
        Self {
            conn,
            auth: ClientAuth,
            #[cfg(test)]
            network: None,
            session: None,
            pending: None,
            screen: Screen::Main,
            quit: false,
            setup_mode,
            selected: 0,
            selection_purpose: SelectionPurpose::Edit,
            elections: vec![],
            election: None,
            positions: vec![],
            voters: vec![],
            ballot_cursor: BallotCursor {
                row: 0,
                column: BallotColumn::Position,
            },
            ballot_scroll: 0,
            voting_choices: vec![],
            lines: vec![],
            scroll: 0,
            form: None,
            confirmation: None,
            notice: "Choose your role to sign in.".into(),
        }
    }
    #[cfg(test)]
    fn new(conn: rusqlite::Connection, auth: auth::login::Auth, setup_mode: bool) -> Self {
        let network = Network::start(
            conn,
            auth,
            network::tls::Certificates::generate().unwrap(),
            None,
            setup_mode,
        )
        .unwrap();
        let mut app = Self::remote(network.client.clone(), setup_mode);
        app.network = Some(network);
        app
    }
    /// Require an authenticated session before protected UI actions.
    fn session(&self) -> AppResult<&Session> {
        self.session.as_ref().ok_or_else(|| "Please log in.".into())
    }
    /// Require a selected election and return its database ID.
    fn election_id(&self) -> AppResult<i64> {
        self.election
            .as_ref()
            .map(|e| e.id)
            .ok_or_else(|| "Choose an election.".into())
    }
    /// Set the user-visible notice.
    fn info(&mut self, message: impl Into<String>) {
        self.notice = message.into();
    }
    /// Build editable fields and open the requested form.
    fn form(
        &mut self,
        purpose: FormPurpose,
        title: &str,
        fields: Vec<(&'static str, String, bool)>,
    ) {
        self.form = Some(Form {
            purpose,
            title: title.into(),
            fields: fields
                .into_iter()
                .map(|(label, value, secret)| Field {
                    label,
                    value,
                    secret,
                })
                .collect(),
            focus: 0,
        });
        self.notice.clear();
    }
    /// Ask for confirmation before a destructive or final action.
    fn confirm(&mut self, message: &str, action: Action) {
        self.confirmation = Some(Confirmation {
            message: message.into(),
            action,
        });
    }
    /// Clear local session, pending authentication and role-specific screen data.
    fn logout(&mut self) {
        if let Some(session) = &self.session {
            let _ = self.conn.logout(session);
        }
        self.session = None;
        self.pending = None;
        self.election = None;
        self.positions.clear();
        self.voters.clear();
        self.voting_choices.clear();
        self.elections.clear();
        self.lines.clear();
        self.form = None;
        self.confirmation = None;
        self.screen = Screen::Main;
        self.selected = 0;
        self.notice = "Signed out. all best (all the best)!".into();
    }
    /// Reload selected election configuration from the backend after changes.
    fn reload_election(&mut self) -> AppResult<()> {
        let id = self.election_id()?;
        let e = election::get(&self.conn, self.session()?, id)?;
        let positions = election::positions(&self.conn, self.session()?, id)?;
        self.election = Some(e);
        self.positions = positions;
        self.ballot_cursor.row = self
            .ballot_cursor
            .row
            .min(self.rows().len().saturating_sub(1));
        Ok(())
    }
    /// Fetch allowed elections and open the appropriate selection screen.
    fn load_elections(&mut self, purpose: SelectionPurpose) -> AppResult<()> {
        self.elections = if matches!(purpose, SelectionPurpose::Audit) {
            election::audit_list(&self.conn, self.session()?)?
        } else {
            election::list(&self.conn, self.session()?)?
        };
        self.selection_purpose = purpose;
        self.selected = 0;
        self.screen = Screen::Elections;
        self.notice = if self.elections.is_empty() {
            "No eligible elections found.".into()
        } else {
            "Select an election and press Enter.".into()
        };
        Ok(())
    }
    /// Load the chosen election for editing, administration or voting.
    fn select_election(&mut self) -> AppResult<()> {
        let e = self
            .elections
            .get(self.selected)
            .cloned()
            .ok_or("No election selected.")?;
        self.election = Some(e);
        self.ballot_cursor.row = 0;
        self.ballot_scroll = 0;
        self.scroll = 0;
        self.reload_election()?;
        match self.selection_purpose {
            SelectionPurpose::Edit => self.screen = Screen::Editor,
            SelectionPurpose::Register => {
                self.load_voters()?;
                self.screen = Screen::Voters;
            }
            SelectionPurpose::Audit => {
                self.load_audit()?;
                self.screen = Screen::Audit;
            }
            SelectionPurpose::District => self.screen = Screen::District,
            SelectionPurpose::Vote => {
                self.voting_choices = vec![None; self.positions.len()];
                self.screen = Screen::Vote;
            }
        }
        self.notice = "Election loaded from database.".into();
        Ok(())
    }
    /// Fetch the authorized enrollment/participation view.
    fn load_voters(&mut self) -> AppResult<()> {
        self.voters = voters::list(&self.conn, self.session()?, self.election_id()?)?;
        self.selected = self.selected.min(self.voters.len().saturating_sub(1));
        Ok(())
    }
    /// Fetch the authorized election audit view.
    fn load_audit(&mut self) -> AppResult<()> {
        self.lines = election::audit_log(&self.conn, self.session()?, self.election_id()?)?;
        self.scroll = 0;
        Ok(())
    }
    /// Flatten positions and candidates into editor rows.
    fn rows(&self) -> Vec<(usize, Option<usize>)> {
        ballot_rows(&self.positions)
    }
    /// Resolve the selected editor row to position and optional candidate indices.
    fn current(&self) -> Option<(usize, Option<usize>)> {
        self.rows().get(self.ballot_cursor.row).copied()
    }
}

/// Build the row-to-position/candidate index mapping used by the editor.
fn ballot_rows(positions: &[Position]) -> Vec<(usize, Option<usize>)> {
    let mut rows = Vec::new();
    for (p, position) in positions.iter().enumerate() {
        if position.candidates.is_empty() {
            rows.push((p, None));
        } else {
            rows.extend((0..position.candidates.len()).map(|c| (p, Some(c))));
        }
    }
    rows
}
/// Drive the terminal draw/input loop and restore terminal state on exit.
pub(crate) fn run(mut terminal: DefaultTerminal, mut app: App) -> io::Result<()> {
    while !app.quit {
        terminal.draw(|f| draw(f, &mut app))?;
        if event::poll(Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
    }
    Ok(())
}
