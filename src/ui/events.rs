//! Keyboard actions for the role menus and election screens.
use super::*;
impl App {
    /// Route a key to the active form/screen and display operation errors.
    pub(super) fn handle_key(&mut self, key: KeyEvent) {
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        let result = if self.form.is_some() {
            self.handle_form(key)
        } else if self.confirmation.is_some() {
            self.handle_confirmation(key)
        } else {
            self.handle_screen(key)
        };
        if let Err(error) = result {
            // Store the failure category and message, never the submitted form.
            let message = error.to_string();
            let logged = self.conn.report_error(
                self.session.as_ref(),
                &format!("{:?}", self.screen),
                &message,
            );
            self.info(if logged.is_err() {
                format!("{message} (error log unavailable)")
            } else {
                message
            });
        }
    }
    /// Route screen-level selection, login and navigation actions.
    pub(super) fn handle_screen(&mut self, key: KeyEvent) -> AppResult<()> {
        match self.screen {
            Screen::Main => match key.code {
                KeyCode::Up => self.selected = self.selected.saturating_sub(1),
                KeyCode::Down => {
                    self.selected = (self.selected + 1).min(if self.setup_mode { 3 } else { 2 })
                }
                KeyCode::Esc | KeyCode::Char('q' | 'Q') => self.quit = true,
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if self.selected == 3 && self.setup_mode {
                        self.screen = Screen::Setup;
                        self.form(
                            FormPurpose::Setup,
                            "Sign up admin / district official",
                            vec![
                                ("Email", String::new(), false),
                                ("Password", String::new(), true),
                                ("Full name", String::new(), false),
                                ("Phone", String::new(), false),
                                ("Role: Left/Right", "admin".into(), false),
                            ],
                        );
                    } else {
                        let role =
                            [Role::Admin, Role::DistrictOfficial, Role::Voter][self.selected];
                        self.screen = Screen::Login;
                        let fields = if role == Role::Voter {
                            vec![("PIN", String::new(), true)]
                        } else {
                            vec![
                                ("Email", String::new(), false),
                                ("Password", String::new(), true),
                            ]
                        };
                        self.form(
                            FormPurpose::Login(role),
                            &format!("{} login", role.label()),
                            fields,
                        );
                    }
                }
                _ => {}
            },
            Screen::AdminHome => match key.code {
                KeyCode::Up => self.selected = self.selected.saturating_sub(1),
                KeyCode::Down => self.selected = (self.selected + 1).min(3),
                KeyCode::Esc => self.logout(),
                KeyCode::Char('r' | 'R') => self.load_elections(SelectionPurpose::Register)?,
                KeyCode::Enter => match self.selected {
                    0 => self.form(
                        FormPurpose::NewElection,
                        "Create new election",
                        vec![("Election name", String::new(), false)],
                    ),
                    1 => self.load_elections(SelectionPurpose::Edit)?,
                    2 => self.load_elections(SelectionPurpose::Register)?,
                    _ => self.load_elections(SelectionPurpose::Audit)?,
                },
                _ => {}
            },
            Screen::Elections => match key.code {
                KeyCode::Up => self.selected = self.selected.saturating_sub(1),
                KeyCode::Down => {
                    self.selected = (self.selected + 1).min(self.elections.len().saturating_sub(1))
                }
                KeyCode::Enter => self.select_election()?,
                KeyCode::Char('r' | 'R') => self.load_elections(self.selection_purpose)?,
                KeyCode::Esc => {
                    if self.session()?.role() == Role::Admin {
                        self.screen = Screen::AdminHome;
                        self.selected = 0;
                    } else {
                        self.logout();
                    }
                }
                _ => {}
            },
            Screen::Editor => self.handle_admin(key)?,
            Screen::Voters => self.handle_voters(key)?,
            Screen::District => self.handle_district(key)?,
            Screen::Vote => self.handle_vote(key)?,
            Screen::Audit | Screen::Results => match key.code {
                KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
                KeyCode::Down => {
                    self.scroll = (self.scroll + 1).min(self.lines.len().saturating_sub(1))
                }
                KeyCode::Char('r' | 'R') if self.screen == Screen::Audit => self.load_audit()?,
                KeyCode::Char('f' | 'F') if self.screen == Screen::Audit => {
                    election::flag_incident(&self.conn, self.session()?, self.election_id()?)?;
                    self.load_audit()?;
                    self.notice = "Election concern logged as a level 2 incident.".into();
                }
                KeyCode::Esc => {
                    self.screen = if self.screen == Screen::Audit {
                        Screen::AdminHome
                    } else {
                        Screen::District
                    };
                    self.selected = 0;
                }
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }
    /// Handle election-editor navigation and position/candidate actions.
    pub(super) fn handle_admin(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::AdminHome;
                self.selected = 0;
            }
            KeyCode::Up => self.ballot_cursor.row = self.ballot_cursor.row.saturating_sub(1),
            KeyCode::Down => {
                self.ballot_cursor.row =
                    (self.ballot_cursor.row + 1).min(self.rows().len().saturating_sub(1))
            }
            KeyCode::Left => {
                self.ballot_cursor.column = match self.ballot_cursor.column {
                    BallotColumn::Party => BallotColumn::Candidate,
                    _ => BallotColumn::Position,
                }
            }
            KeyCode::Right => {
                self.ballot_cursor.column = match self.ballot_cursor.column {
                    BallotColumn::Position => BallotColumn::Candidate,
                    _ => BallotColumn::Party,
                }
            }
            KeyCode::Char('p' | 'P') => self.form(
                FormPurpose::AddPosition,
                "Add position",
                vec![("Position name", String::new(), false)],
            ),
            KeyCode::Char('c' | 'C') => {
                if let Some((p, _)) = self.current() {
                    self.form(
                        FormPurpose::AddCandidate(self.positions[p].id),
                        "Add candidate",
                        vec![
                            ("Full name", String::new(), false),
                            ("Political party", String::new(), false),
                        ],
                    );
                }
            }
            KeyCode::Char('l' | 'L') => {
                if let Some((p, _)) = self.current() {
                    self.form(
                        FormPurpose::LinkCandidate(self.positions[p].id),
                        "Link existing candidate to this position",
                        vec![("Candidate ID from this election", String::new(), false)],
                    );
                }
            }
            KeyCode::Char('e' | 'E') => {
                if let Some((p, c)) = self.current() {
                    if self.ballot_cursor.column == BallotColumn::Position {
                        self.form(
                            FormPurpose::EditPosition(self.positions[p].id),
                            "Edit position",
                            vec![("Position name", self.positions[p].name.clone(), false)],
                        );
                    } else if let Some(c) = c {
                        let c = &self.positions[p].candidates[c];
                        self.form(
                            FormPurpose::EditCandidate(c.id),
                            "Edit candidate (all linked positions)",
                            vec![
                                ("Full name", c.name.clone(), false),
                                ("Political party", c.party.clone(), false),
                            ],
                        );
                    }
                }
            }
            KeyCode::Char('d' | 'D') => {
                if let Some((p, c)) = self.current() {
                    if self.ballot_cursor.column == BallotColumn::Position {
                        self.confirm(
                            "Delete this draft position?",
                            Action::DeletePosition(self.positions[p].id),
                        );
                    } else if let Some(c) = c {
                        self.confirm(
                            "Remove this candidate from this position?",
                            Action::UnlinkCandidate(
                                self.positions[p].id,
                                self.positions[p].candidates[c].id,
                            ),
                        );
                    }
                }
            }
            KeyCode::F(2) => self.form(
                FormPurpose::RenameElection,
                "Rename election",
                vec![(
                    "Election name",
                    self.election.as_ref().unwrap().name.clone(),
                    false,
                )],
            ),
            KeyCode::Char('x' | 'X') => self.confirm(
                "Cancel this draft election? Its audit history is retained.",
                Action::DeleteElection,
            ),
            KeyCode::Char('r' | 'R') => {
                self.load_voters()?;
                self.screen = Screen::Voters;
                self.selected = 0;
            }
            _ => {}
        }
        Ok(())
    }
    /// Open a voter registration or edit form with the appropriate field values.
    pub(super) fn voter_form(&mut self, voter: Option<Voter>) {
        let (purpose, title, input) = match voter {
            Some(v) => (
                FormPurpose::UpdateVoter(v.id),
                "Edit voter (NID/phone remain fixed)",
                VoterInput {
                    full_name: v.full_name,
                    email: v.email,
                    phone: v.phone,
                    dob: v.dob,
                    nid: v.nid,
                },
            ),
            None => (
                FormPurpose::RegisterVoter,
                "Register a new voter",
                VoterInput {
                    full_name: String::new(),
                    email: String::new(),
                    phone: String::new(),
                    dob: String::new(),
                    nid: String::new(),
                },
            ),
        };
        self.form(
            purpose,
            title,
            vec![
                ("Full name", input.full_name, false),
                ("DOB YYYY-MM-DD", input.dob, false),
                ("Government voter ID (demo)", input.nid, false),
                ("Phone", input.phone, false),
                ("Email (optional)", input.email, false),
            ],
        );
    }
    /// Handle registration, enrollment, editing and removal selection.
    pub(super) fn handle_voters(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::AdminHome;
                self.selected = 0;
            }
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(self.voters.len().saturating_sub(1))
            }
            KeyCode::Char('r' | 'R') => self.voter_form(None),
            KeyCode::Char('e' | 'E') => {
                if let Some(v) = self.voters.get(self.selected).cloned() {
                    self.voter_form(Some(v));
                }
            }
            KeyCode::Char('i' | 'I') => self.form(
                FormPurpose::Enroll,
                "Enroll an existing voter",
                vec![("Government voter ID (demo)", String::new(), false)],
            ),
            KeyCode::Char('d' | 'D') => {
                if let Some(v) = self.voters.get(self.selected) {
                    self.confirm(
                        "Remove this voter's draft enrollment?",
                        Action::RemoveVoter(v.id),
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }
    /// Handle election lifecycle commands available to district officials.
    pub(super) fn handle_district(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc => self.load_elections(SelectionPurpose::District)?,
            KeyCode::Char('s' | 'S') => self.confirm(
                "Open voting for this election? Editing will be locked.",
                Action::Start,
            ),
            KeyCode::Char('f' | 'F') => {
                self.confirm("Close voting for this election?", Action::Close)
            }
            KeyCode::Char('t' | 'T') => self.confirm(
                "Calculate and store candidate and party totals?",
                Action::Tally,
            ),
            KeyCode::Char('a' | 'A') => {
                self.confirm("Announce the tallied results?", Action::Announce)
            }
            KeyCode::Char('r' | 'R') => self.show_results()?,
            _ => {}
        }
        Ok(())
    }
    /// Fetch and display anonymous candidate and party totals.
    pub(super) fn show_results(&mut self) -> AppResult<()> {
        let rows = election::results(&self.conn, self.session()?, self.election_id()?)?;
        if rows.is_empty() {
            return Err("Tally the closed election first.".into());
        }
        let mut lines = Vec::new();
        for p in &self.positions {
            let results: Vec<_> = rows.iter().filter(|r| r.position == p.name).collect();
            let max = results.iter().map(|r| r.votes).max().unwrap_or(0);
            let leaders: Vec<_> = results
                .iter()
                .filter(|r| r.votes == max)
                .map(|r| r.candidate.as_str())
                .collect();
            let outcome = if max == 0 {
                "No winner: no votes cast".into()
            } else if leaders.len() > 1 {
                format!("Tie: {} ({max} each)", leaders.join(", "))
            } else {
                format!("Winner: {} ({max})", leaders[0])
            };
            lines.push(format!("{} -- {}", p.name, outcome));
            for r in results {
                lines.push(format!(
                    "  {} | {} | {} votes",
                    r.candidate, r.party, r.votes
                ));
            }
        }
        lines.push("Party totals per position:".into());
        lines.extend(election::party_results(
            &self.conn,
            self.session()?,
            self.election_id()?,
        )?);
        self.lines = lines;
        self.scroll = 0;
        self.screen = Screen::Results;
        Ok(())
    }
    /// Update local ballot selections and request final submission confirmation.
    pub(super) fn handle_vote(&mut self, key: KeyEvent) -> AppResult<()> {
        match key.code {
            KeyCode::Esc => {
                self.voting_choices.clear();
                self.load_elections(SelectionPurpose::Vote)?;
            }
            KeyCode::Up => self.ballot_cursor.row = self.ballot_cursor.row.saturating_sub(1),
            KeyCode::Down => {
                self.ballot_cursor.row =
                    (self.ballot_cursor.row + 1).min(self.rows().len().saturating_sub(1))
            }
            KeyCode::Char(' ') => {
                if let Some((p, Some(c))) = self.current() {
                    self.voting_choices[p] = Some(self.positions[p].candidates[c].id);
                }
            }
            KeyCode::Char('s' | 'S') => {
                if self.voting_choices.iter().any(Option::is_none) {
                    return Err("Choose one candidate for every position.".into());
                }
                self.confirm(
                    "Submit all selections? Accepted votes cannot be changed.",
                    Action::Submit,
                );
            }
            _ => {}
        }
        Ok(())
    }
}
