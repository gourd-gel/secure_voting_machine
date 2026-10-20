//! Form input and confirmed mutations. State changes follow successful server writes.
use super::*;
impl App {
    /// Handle input/navigation/submission; preserve invalid forms and clear secret fields.
    pub(super) fn handle_form(&mut self, key: KeyEvent) -> AppResult<()> {
        let mut form = self.form.take().unwrap();
        match key.code {
            KeyCode::Esc => {
                if matches!(
                    form.purpose,
                    FormPurpose::Login(_) | FormPurpose::Otp | FormPurpose::Setup
                ) {
                    self.logout();
                }
                return Ok(());
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let step = if key.code == KeyCode::BackTab
                    || key.modifiers.contains(KeyModifiers::SHIFT)
                {
                    form.fields.len() - 1
                } else {
                    1
                };
                form.focus = (form.focus + step) % form.fields.len();
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                if matches!(form.purpose, FormPurpose::Setup) && form.focus == 4 =>
            {
                form.fields[4].value = if form.fields[4].value == "admin" {
                    "district_official"
                } else {
                    "admin"
                }
                .into();
            }
            KeyCode::Enter => {
                let result = self.submit_form(&form);
                if result.is_err() {
                    for f in &mut form.fields {
                        if f.secret {
                            f.value.clear();
                        }
                    }
                    if matches!(form.purpose, FormPurpose::Otp) && self.pending.is_none() {
                        self.logout();
                    } else {
                        self.form = Some(form);
                    }
                }
                return result;
            }
            KeyCode::Backspace => {
                if !(matches!(form.purpose, FormPurpose::Setup) && form.focus == 4) {
                    form.fields[form.focus].value.pop();
                }
            }
            KeyCode::Char(c)
                if !c.is_control()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && !(matches!(form.purpose, FormPurpose::Setup) && form.focus == 4)
                    && form.fields[form.focus].value.len() < 200 =>
            {
                form.fields[form.focus].value.push(c);
            }
            _ => {}
        }
        self.form = Some(form);
        Ok(())
    }
    /// Validate client fields and call the appropriate typed backend operation.
    pub(super) fn submit_form(&mut self, form: &Form) -> AppResult<()> {
        let v: Vec<&str> = form.fields.iter().map(|f| f.value.as_str()).collect();
        // Validate before sending; server validation remains mandatory.
        use crate::validation as check;
        match form.purpose {
            FormPurpose::Login(Role::Voter) => check::digits(v[0], 20, "PIN")?,
            FormPurpose::Login(_) => {
                check::email(v[0], false)?;
                check::password(v[1], false)?;
            }
            FormPurpose::Otp => check::digits(v[0], 6, "OTP")?,
            FormPurpose::Setup => {
                check::email(v[0], false)?;
                check::password(v[1], true)?;
                check::text(v[2], "Name")?;
                check::phone(v[3])?;
                if !matches!(v[4], "admin" | "district_official") {
                    return Err("Invalid staff role.".into());
                }
            }
            FormPurpose::RegisterVoter | FormPurpose::UpdateVoter(_) => {
                check::voter_fields(&VoterInput {
                    full_name: v[0].into(),
                    dob: v[1].into(),
                    nid: v[2].into(),
                    phone: v[3].into(),
                    email: v[4].into(),
                })?;
            }
            _ => {
                for value in &v {
                    check::text(value, "Field")?;
                }
            }
        }
        match form.purpose {
            FormPurpose::Login(role) => {
                self.pending = Some(if role == Role::Voter {
                    self.auth.pin_login(&self.conn, v[0])?
                } else {
                    self.auth.password_login(&self.conn, v[0], v[1], role)?
                });
                self.screen = Screen::Otp;
                self.form(
                    FormPurpose::Otp,
                    "OTP sent to your virtual SMS inbox",
                    vec![("Six-digit OTP", String::new(), true)],
                );
            }
            FormPurpose::Otp => {
                let session = self
                    .auth
                    .complete_otp(&self.conn, &mut self.pending, v[0])?;
                let role = session.role();
                self.session = Some(session);
                self.selected = 0;
                if role == Role::Admin {
                    self.elections = election::list(&self.conn, self.session()?)?;
                    self.screen = Screen::AdminHome;
                } else {
                    self.load_elections(if role == Role::Voter {
                        SelectionPurpose::Vote
                    } else {
                        SelectionPurpose::District
                    })?;
                }
                self.notice = "Login successful.".into();
            }
            FormPurpose::Setup => {
                if !self.setup_mode {
                    return Err("Engineer setup mode is disabled.".into());
                }
                let role = if v[4] == "admin" {
                    Role::Admin
                } else {
                    Role::DistrictOfficial
                };
                voters::provision(&mut self.conn, &self.auth, v[0], v[3], v[2], v[1], role)?;
                self.logout();
                self.notice = "Account created. Sign in using its role.".into();
            }
            _ => {
                let session = self.session.as_ref().ok_or("Please log in.")?;
                if matches!(form.purpose, FormPurpose::NewElection) {
                    let id = election::create(&mut self.conn, session, v[0])?;
                    self.election = Some(election::get(&self.conn, session, id)?);
                    self.reload_election()?;
                    self.ballot_cursor.row = 0;
                    self.screen = Screen::Editor;
                } else {
                    let id = self.election_id()?;
                    let session = self.session.as_ref().unwrap();
                    match form.purpose {
                        FormPurpose::RenameElection => {
                            election::rename(&mut self.conn, session, id, v[0])?
                        }
                        FormPurpose::AddPosition => {
                            election::add_position(&mut self.conn, session, id, v[0])?
                        }
                        FormPurpose::EditPosition(p) => {
                            election::rename_position(&mut self.conn, session, id, p, v[0])?
                        }
                        FormPurpose::AddCandidate(p) => {
                            election::add_candidate(&mut self.conn, session, id, p, v[0], v[1])?
                        }
                        FormPurpose::EditCandidate(c) => {
                            election::update_candidate(&mut self.conn, session, id, c, v[0], v[1])?
                        }
                        FormPurpose::LinkCandidate(p) => election::link_candidate(
                            &mut self.conn,
                            session,
                            id,
                            p,
                            v[0].trim()
                                .parse::<i64>()
                                .map_err(|_| "Enter a numeric candidate ID.")?,
                        )?,
                        FormPurpose::RegisterVoter | FormPurpose::UpdateVoter(_) => {
                            let input = VoterInput {
                                full_name: v[0].into(),
                                dob: v[1].into(),
                                nid: v[2].into(),
                                phone: v[3].into(),
                                email: v[4].into(),
                            };
                            if let FormPurpose::UpdateVoter(user) = form.purpose {
                                voters::update(&mut self.conn, session, id, user, &input)?;
                            } else {
                                let voter = voters::register(
                                    &mut self.conn,
                                    &self.auth,
                                    session,
                                    id,
                                    &input,
                                )?;
                                self.load_voters()?;
                                self.form(
                                    FormPurpose::PinReceipt(voter),
                                    "Did voter receive PIN?",
                                    vec![("yes / no", String::new(), false)],
                                );
                                self.notice =
                                    "PIN sent privately to the voter's phone-number text file."
                                        .into();
                                return Ok(());
                            }
                            self.load_voters()?;
                        }
                        FormPurpose::PinReceipt(voter) => {
                            let received = match v[0].trim().to_lowercase().as_str() {
                                "yes" => true,
                                "no" => false,
                                _ => return Err("Please enter yes or no.".into()),
                            };
                            voters::pin_receipt(&self.conn, session, id, voter, received)?;
                            self.notice = if received { "PIN receipt confirmed." } else { "PIN not received. Check the registered phone's inbox; registration remains saved." }.into();
                            return Ok(());
                        }
                        FormPurpose::Enroll => {
                            voters::enroll(&mut self.conn, session, id, v[0])?;
                            self.load_voters()?;
                        }
                        _ => {}
                    }
                    self.reload_election()?;
                }
                self.notice = if matches!(form.purpose, FormPurpose::RegisterVoter) {
                    "Voter registered. PIN delivered to their virtual SMS inbox.".into()
                } else {
                    "Saved to database.".into()
                };
            }
        }
        Ok(())
    }
    /// Execute a confirmed operation and refresh the affected UI state.
    pub(super) fn handle_confirmation(&mut self, key: KeyEvent) -> AppResult<()> {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('n' | 'N')) {
            self.confirmation = None;
            return Ok(());
        }
        if !matches!(key.code, KeyCode::Enter | KeyCode::Char('y' | 'Y')) {
            return Ok(());
        }
        let action = self.confirmation.take().unwrap().action;
        let id = self.election_id()?;
        let session = self.session.as_ref().ok_or("Please log in.")?;
        match action {
            Action::DeleteElection => election::delete(&mut self.conn, session, id)?,
            Action::DeletePosition(p) => election::delete_position(&mut self.conn, session, id, p)?,
            Action::UnlinkCandidate(p, c) => {
                election::unlink_candidate(&mut self.conn, session, id, p, c)?
            }
            Action::RemoveVoter(v) => voters::remove(&mut self.conn, session, id, v)?,
            Action::Start => election::start(&mut self.conn, session, id)?,
            Action::Close => election::close(&mut self.conn, session, id)?,
            Action::Tally => election::tally(&mut self.conn, session, id)?,
            Action::Announce => election::announce(&mut self.conn, session, id)?,
            Action::Submit => {
                let choices = self
                    .positions
                    .iter()
                    .zip(&self.voting_choices)
                    .map(|(p, c)| Ok((p.id, c.ok_or("Incomplete ballot")?)))
                    .collect::<AppResult<Vec<_>>>()?;
                election::cast(&mut self.conn, session, id, &choices)?;
                self.logout();
                self.notice =
                    "thank you for your vote! Signed out. Check your SMS text file.".into();
                return Ok(());
            }
        }
        if matches!(action, Action::DeleteElection) {
            self.election = None;
            self.positions.clear();
            self.screen = Screen::AdminHome;
            self.selected = 0;
        } else {
            self.reload_election()?;
            if matches!(action, Action::RemoveVoter(_)) {
                self.load_voters()?;
            }
        }
        if matches!(action, Action::Announce) {
            self.show_results()?;
        }
        self.notice = "Action saved to database.".into();
        Ok(())
    }
}
