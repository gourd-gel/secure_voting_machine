//! Database-side login challenges, session lifetime, and authenticated dispatch.
use super::*;
pub(super) struct LoginRecord {
    pub(super) login: Option<auth::login::PendingLogin>,
    pub(super) role: Role,
    pub(super) expires: Instant,
}
pub(super) struct SessionRecord {
    pub(super) session: auth::login::Session,
    pub(super) expires: Instant,
}
pub(super) struct State {
    pub(super) conn: Connection,
    pub(super) registry: registry::Registry,
    pub(super) auth: auth::login::Auth,
    pub(super) pending: HashMap<String, LoginRecord>,
    pub(super) sessions: HashMap<String, SessionRecord>,
    pub(super) setup_token: Option<String>,
}
impl State {
    /// Validate gateway role, authenticate challenges/sessions and dispatch authorized operations.
    pub(super) fn dispatch(&mut self, request: Request, peer_role: Role) -> AppResult<Value> {
        crate::security::check_deadline()?;
        if request.role != peer_role {
            return Err("Wrong role gateway.".into());
        }
        let now = Instant::now();
        self.pending.retain(|_, r| r.expires > now);
        self.sessions.retain(|_, r| r.expires > now);
        match request.operation.as_str() {
            "password" | "pin" => {
                if self.pending.len() >= 1024 {
                    return Err("Too many pending logins. Try later.".into());
                }
                let login = if request.operation == "pin" {
                    if peer_role != Role::Voter {
                        return Err("Use the voter gateway.".into());
                    }
                    let (pin,): (String,) = serde_json::from_value(request.args)?;
                    self.auth.pin_login(&self.conn, &pin)?
                } else {
                    let (email, password): (String, String) = serde_json::from_value(request.args)?;
                    self.auth
                        .password_login(&self.conn, &email, &password, peer_role)?
                };
                let token = Uuid::new_v4().to_string();
                self.pending.insert(
                    token.clone(),
                    LoginRecord {
                        login: Some(login),
                        role: peer_role,
                        expires: now + Duration::from_secs(300),
                    },
                );
                return Ok(serde_json::to_value(PendingLogin {
                    token,
                    role: peer_role,
                })?);
            }
            "otp" => {
                let token = request.token.ok_or("Missing login challenge.")?;
                let record = self
                    .pending
                    .get_mut(&token)
                    .ok_or("Login challenge expired or already used.")?;
                if record.role != peer_role {
                    return Err("Wrong role gateway.".into());
                }
                let (code,): (String,) = serde_json::from_value(request.args)?;
                let result = self.auth.complete_otp(&self.conn, &mut record.login, &code);
                if record.login.is_none() {
                    self.pending.remove(&token);
                }
                let session = result?;
                let token = Uuid::new_v4().to_string();
                let public = Session {
                    token: token.clone(),
                    user_id: session.user_id(),
                    role: session.role(),
                };
                if self.sessions.len() >= 4096 {
                    return Err("Session capacity reached. Try later.".into());
                }
                self.sessions.insert(
                    token,
                    SessionRecord {
                        session,
                        expires: now + Duration::from_secs(1800),
                    },
                );
                return Ok(serde_json::to_value(public)?);
            }
            "provision" => {
                if peer_role != Role::Admin
                    || self.setup_token.is_none()
                    || request.token != self.setup_token
                {
                    return Err("Engineer setup is disabled.".into());
                }
                let (email, phone, name, password, role): (String, String, String, String, Role) =
                    serde_json::from_value(request.args)?;
                services::voters::provision(
                    &mut self.conn,
                    &self.auth,
                    &email,
                    &phone,
                    &name,
                    &password,
                    role,
                )?;
                return Ok(Value::Null);
            }
            _ => {}
        }
        let token = request.token.ok_or("Log in first.")?;
        let record = self
            .sessions
            .remove(&token)
            .ok_or("Invalid or expired session; log in again.")?;
        // Always restore the session, even after a rejected action; logout is explicit.
        let result = (|| {
            if record.session.role() != peer_role {
                return Err("Wrong role gateway.".into());
            }
            services::require_role(&self.conn, &record.session, peer_role)?;
            match request.operation.as_str() {
                "logout" => Ok(Value::Null),
                "error" => {
                    let (_screen, _message): (String, String) =
                        serde_json::from_value(request.args)?;

                    if record.session.role() == Role::Voter {
                        // Aggregate only. No identity, session or screen.
                        crate::security::voter_metric(&self.conn, "client_error")?;
                    } else {
                        self.conn.execute(
                            "INSERT INTO error_reports(
                            actor_user_id,screen,message
                        ) VALUES (?1,?2,?3)",
                            rusqlite::params![
                                record.session.user_id(),
                                "terminal-client",
                                "Client reported an operation failure"
                            ],
                        )?;

                        services::audit(
                            &self.conn,
                            None,
                            Some(record.session.user_id()),
                            None,
                            "client_error",
                            3,
                        )?;
                    }

                    Ok(Value::Null)
                }
                _ => {
                    dispatch::service_call(self, &record.session, &request.operation, request.args)
                }
            }
        })();
        if request.operation != "logout" {
            self.sessions.insert(token, record);
        }
        result
    }
}
