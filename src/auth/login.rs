//! Authentication, bounded retries, and a local virtual-SMS delivery adapter.
//! A Session is issued only after both credential and OTP verification.
use crate::{
    models::Role,
    services::{audit, AppResult},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use chrono_tz::America::New_York;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub struct Session {
    user_id: i64,
    role: Role,
}
impl Session {
    /// Return the authenticated user ID.
    pub fn user_id(&self) -> i64 {
        self.user_id
    }
    /// Return the authenticated role.
    pub fn role(&self) -> Role {
        self.role
    }
    #[cfg(test)]
    pub(crate) fn for_test(user_id: i64, role: Role) -> Self {
        Self { user_id, role }
    }
}

pub struct PendingLogin {
    user_id: i64,
    role: Role,
    code_hash: String,
    expires: i64,
    attempts: u8,
}

pub struct Auth {
    pepper: String,
    mailbox: PathBuf,
    cost: u32,
}
impl Auth {
    /// Load and validate the password pepper; configure normal bcrypt cost.
    pub fn from_env(mailbox: PathBuf) -> AppResult<Self> {
        dotenvy::dotenv().ok();
        let pepper = std::env::var("APP_PEPPER")
            .map_err(|_| "Set APP_PEPPER before starting the application.")?;
        if pepper.len() < 16 || pepper.len() > 40 {
            return Err("APP_PEPPER must be 16-40 bytes; preserve it between runs.".into());
        }
        Ok(Self {
            pepper,
            mailbox,
            cost: DEFAULT_COST,
        })
    }
    #[cfg(test)]
    pub(crate) fn for_test(mailbox: PathBuf) -> Self {
        Self {
            pepper: "isolated-test-pepper-123".into(),
            mailbox,
            cost: 4,
        }
    }
    /// Combine the password with the pepper, rejecting bcrypt input overflow.
    fn password_input(&self, password: &str) -> AppResult<String> {
        crate::validation::password(password, false)?;
        let input = format!("{password}{}", self.pepper);
        if input.len() > 72 {
            return Err("Password and pepper together must be at most 72 bytes.".into());
        }
        Ok(input)
    }
    /// Hash a signup password using bcrypt and the configured pepper.
    pub(crate) fn password_hash(&self, password: &str) -> AppResult<String> {
        if password.len() < 10 {
            return Err("Use a password of at least 10 characters.".into());
        }
        Ok(hash(self.password_input(password)?, self.cost)?)
    }
    /// Create a keyed digest for lookup/rate-limit scopes without storing the raw secret.
    pub(crate) fn lookup(&self, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.pepper.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(value.as_bytes());
        format!("{:x}", mac.finalize().into_bytes())
    }
    /// Generate a random decimal PIN and return its lookup digest and bcrypt verifier.
    pub(crate) fn new_pin(&self) -> AppResult<(String, String, String)> {
        // UUIDv4 supplies OS randomness. The 20 decimal digits are never a user ID.
        let pin = format!(
            "{:020}",
            Uuid::new_v4().as_u128() % 100_000_000_000_000_000_000u128
        );
        let lookup = self.lookup(&pin);
        let hashed = hash(self.password_input(&pin)?, self.cost)?;
        Ok((pin, lookup, hashed))
    }
    /// Verify staff credentials and retry limits; issue an OTP challenge on success.
    pub fn password_login(
        &self,
        conn: &Connection,
        email: &str,
        password: &str,
        role: Role,
    ) -> AppResult<PendingLogin> {
        if role == Role::Voter {
            return Err("Voters sign in with their PIN.".into());
        }
        crate::validation::email(email, false)?;
        let scope = format!("password:{}", self.lookup(&email.trim().to_lowercase()));
        check_limit(conn, &scope)?;
        let record: Option<(i64, String)> = conn
            .query_row(
                "SELECT u.id,c.password_hash FROM users u JOIN user_credentials c ON c.user_id=u.id
             WHERE lower(u.email)=lower(?1) AND u.role=?2 AND u.active=1",
                params![email.trim(), role.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let user = record.as_ref().map(|(id, _)| *id);
        crate::security::event(conn, user, "password_attempt", Some(&scope), 0)?;
        if let Some((id, stored)) = record {
            if verify(self.password_input(password)?, &stored)? {
                crate::security::check_deadline()?;
                reset_limit(conn, &scope)?;
                crate::security::event(conn, Some(id), "password_verified", Some(&scope), 0)?;
                return self.issue_otp(conn, id, role);
            }
        }
        failed(conn, &scope, 5, "password_failed", user)?;
        Err("Invalid credentials or role.".into())
    }
    /// Verify a voter PIN and its scoped retry limit; issue an OTP challenge.
    pub fn pin_login(&self, conn: &Connection, pin: &str) -> AppResult<PendingLogin> {
        // This is a single-machine limiter, not an IP-based network control.
        let scope = format!("pin:{}", self.lookup(pin.trim()));
        check_limit(conn, &scope)?;
        let record: Option<(i64, String)> = conn
            .query_row(
                "SELECT u.id,p.pin_hash FROM voter_pin_credentials p JOIN users u ON u.id=p.user_id
             WHERE p.lookup_hash=?1 AND u.role='voter' AND u.active=1",
                [self.lookup(pin.trim())],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let user = record.as_ref().map(|(id, _)| *id);
        if let Some((id, stored)) = record {
            if verify(self.password_input(pin.trim())?, &stored)? {
                reset_limit(conn, &scope)?;
                return self.issue_otp(conn, id, Role::Voter);
            }
        }
        failed(conn, &scope, 10, "pin_failed", user)?;
        Err("Invalid PIN.".into())
    }
    /// Deliver an expiring virtual OTP and return the pending verification state.
    fn issue_otp(&self, conn: &Connection, id: i64, role: Role) -> AppResult<PendingLogin> {
        crate::security::check_deadline()?;
        check_limit(conn, &format!("otp:{id}"))?;
        let (phone, name): (String, String) = conn.query_row(
            "SELECT phone_number, full_name FROM users WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let code = format!("{:06}", Uuid::new_v4().as_u128() % 1_000_000);
        let sent = Utc::now();
        let expires = (sent + Duration::minutes(5)).timestamp();
        self.deliver(&phone, &otp_message(&name, &phone, "Login", &code, sent))?;
        Ok(PendingLogin {
            user_id: id,
            role,
            code_hash: self.lookup(&code),
            expires,
            attempts: 0,
        })
    }
    /// Consume a valid OTP once and issue a session; count failures and expire challenges.
    pub fn complete_otp(
        &self,
        conn: &Connection,
        pending: &mut Option<PendingLogin>,
        code: &str,
    ) -> AppResult<Session> {
        let mut login = pending.take().ok_or("Start login again.")?;
        crate::security::event(
            conn,
            Some(login.user_id),
            "otp_attempt",
            None,
            i64::from(login.attempts) + 1,
        )?;
        if now() >= login.expires {
            if login.role == Role::Voter {
                crate::security::voter_metric(conn, "otp_expired")?;
            } else {
                audit(conn, None, Some(login.user_id), None, "otp_expired", 3)?;
            }

            return Err("OTP expired; log in again.".into());
        }
        let scope = format!("otp:{}", login.user_id);
        check_limit(conn, &scope)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.pepper.as_bytes()).expect("valid HMAC key");
        mac.update(code.trim().as_bytes());
        // HMAC strings are not secrets; compare fixed-length digests without early exit.
        let actual = format!("{:x}", mac.finalize().into_bytes());
        let equal = actual
            .as_bytes()
            .iter()
            .zip(login.code_hash.as_bytes())
            .fold(0u8, |v, (a, b)| v | (a ^ b))
            == 0;
        if !equal {
            login.attempts += 1;
            failed(conn, &scope, 3, "otp_failed", Some(login.user_id))?;
            if login.attempts < 3 {
                *pending = Some(login);
            }
            return Err("Invalid OTP; three failures require a cooldown and a new login.".into());
        }
        reset_limit(conn, &scope)?;

        if login.role != Role::Voter {
            audit(conn, None, Some(login.user_id), None, "login_succeeded", 0)?;

            tracing::info!(
                target: "security",
                event_type = "staff_login_succeeded",
                actor_user_id = login.user_id,
                role = login.role.as_str(),
                "Staff authenticated"
            );
        }
        Ok(Session {
            user_id: login.user_id,
            role: login.role,
        })
    }
    /// Retry queued alerts after UI actions. A crash may duplicate an alert,
    /// but it cannot erase the underlying committed audit event.
    pub fn flush_notifications(&self, conn: &Connection) -> AppResult<()> {
        let mut stmt = conn.prepare(
            "SELECT notification_id,phone,message FROM notification_outbox WHERE delivered=0 ORDER BY notification_id LIMIT 100"
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let messages = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, phone, message) in messages {
            self.deliver(&phone, &message)?;
            conn.execute(
                "UPDATE notification_outbox SET delivered=1 WHERE notification_id=?1",
                [id],
            )?;
        }
        self.flush_emails(conn)?;
        Ok(())
    }

    /// Local engineer approval before enabling privileged staff provisioning.
    pub fn approve_setup(&self, conn: &Connection) -> AppResult<()> {
        check_limit(conn, "engineer-setup")?;
        let code = format!("{:06}", Uuid::new_v4().as_u128() % 1_000_000);
        let sent = Utc::now();
        let expires = (sent + Duration::minutes(5)).timestamp();
        self.deliver(
            "engineer",
            &otp_message("Engineer", "engineer", "Setup", &code, sent),
        )?;
        println!("Engineer approval required. Read --inbox engineer in another terminal, then enter Setup OTP:");
        for _ in 0..3 {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if now() < expires && input.trim() == code {
                reset_limit(conn, "engineer-setup")?;
                audit(conn, None, None, None, "engineer_setup_approved", 0)?;
                return Ok(());
            }
            failed(conn, "engineer-setup", 3, "engineer_setup_failed", None)?;
            self.flush_notifications(conn)?;
            println!("Incorrect or expired setup OTP.");
        }
        Err("Setup locked for five minutes.".into())
    }

    /// Append email-style alerts. Failed delivery leaves the durable outbox pending.
    pub fn flush_emails(&self, conn: &Connection) -> AppResult<()> {
        let root = self.mailbox.join("emails");
        fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        let mut q=conn.prepare("SELECT o.id,o.recipient,a.event_id,a.event_type,a.occurred_at,a.severity FROM email_outbox o JOIN audit_events a ON a.event_id=o.event_id WHERE o.delivered=0 ORDER BY o.id LIMIT 100")?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, email, event, kind, time, severity) in rows {
            let email = crate::validation::email(&email, false)?;
            let mut options = fs::OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(root.join(format!("{email}.txt")))?;
            writeln!(file,"To: {email}\nSubject: Voting system event — {kind}\nEvent ID: {event}\nTimestamp (UTC): {time}\nSeverity: {severity}\nMessage: {kind}\nDetails: See the authorized audit view; credentials and ballot contents are excluded.\n---")?;
            file.sync_all()?;
            conn.execute("UPDATE email_outbox SET delivered=1 WHERE id=?1", [id])?;
        }
        Ok(())
    }

    /// Virtual SMS is a same-host teaching simulation, not independent MFA.
    /// Credentials are never included in the election audit log or admin screen.
    pub(crate) fn deliver(&self, phone: &str, message: &str) -> AppResult<()> {
        fs::create_dir_all(&self.mailbox)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.mailbox, fs::Permissions::from_mode(0o700))?;
        }
        let path = mailbox_path(&self.mailbox, phone)?;
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        writeln!(file, "{message}")?;
        file.sync_all()?;
        Ok(())
    }
}
/// Use the validated phone number as the inbox filename; reject path characters.
pub fn mailbox_path(root: &Path, phone: &str) -> AppResult<PathBuf> {
    let phone = phone.trim();
    let name = if phone == "engineer" {
        phone.to_owned()
    } else {
        crate::validation::phone(phone)?
    };
    Ok(root.join(format!("{name}.txt")))
}
/// Return Unix seconds for persisted authentication expiry timestamps.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
/// Reject authentication while its scope is in cooldown; clear expired cooldowns.
fn check_limit(conn: &Connection, scope: &str) -> AppResult<()> {
    let user = if scope.starts_with("otp:") {
        scope
            .strip_prefix("otp:")
            .and_then(|s| s.parse::<i64>().ok())
    } else {
        None
    };
    let until: Option<i64> = conn
        .query_row(
            "SELECT blocked_until FROM auth_attempts WHERE scope=?1",
            [scope],
            |r| r.get(0),
        )
        .optional()?;
    if until.is_some_and(|t| t > now()) {
        crate::security::event(conn, user, "authentication_blocked", Some(scope), 0)?;
        return Err("Too many failed attempts. Try again in 5 minutes.".into());
    }
    if until.is_some_and(|t| t > 0) {
        reset_limit(conn, scope)?;
    }
    Ok(())
}
/// Clear the successful or expired authentication retry counter.
fn reset_limit(conn: &Connection, scope: &str) -> AppResult<()> {
    conn.execute("DELETE FROM auth_attempts WHERE scope=?1", [scope])?;
    Ok(())
}
/// Increment a bounded retry record, apply cooldown and log sanitized failure/lockout events.
fn failed(
    conn: &Connection,
    scope: &str,
    threshold: i64,
    event: &str,
    user: Option<i64>,
) -> AppResult<()> {
    // Bound attacker-controlled unknown-identity records. Existing accounts still
    // retain their counters; old expired counters can be discarded safely.
    conn.execute(
        "DELETE FROM auth_attempts WHERE blocked_until>0 AND blocked_until<=?1",
        [now()],
    )?;
    let full:bool=conn.query_row("SELECT count(*)>=4096 AND NOT EXISTS(SELECT 1 FROM auth_attempts WHERE scope=?1) FROM auth_attempts",[scope],|r|r.get(0))?;
    if full {
        return Err("Authentication capacity reached; try later.".into());
    }
    conn.execute(
        "INSERT INTO auth_attempts(scope,failures,blocked_until) VALUES (?1,1,0)
        ON CONFLICT(scope) DO UPDATE SET failures=failures+1",
        [scope],
    )?;
    conn.execute(
        "UPDATE auth_attempts SET blocked_until=?2 WHERE scope=?1 AND failures>=?3",
        params![scope, now() + 300, threshold],
    )?;
    let count: i64 = conn.query_row(
        "SELECT failures FROM auth_attempts WHERE scope=?1",
        [scope],
        |r| r.get(0),
    )?;
    crate::security::event(conn, user, event, Some(scope), count)?;
    if count >= threshold {
        crate::security::event(conn, user, "authentication_locked", Some(scope), count)?;
    }
    Ok(())
}

/// Render a virtual text with New York time; keep the existing code line for readers/tests.
fn otp_message(name: &str, phone: &str, purpose: &str, code: &str, sent: DateTime<Utc>) -> String {
    let sent = sent.with_timezone(&New_York);
    let expires = sent + Duration::minutes(5);
    let display_time = "%Y-%m-%d %I:%M:%S %p %Z (UTC%:z)";
    // Legacy names must not inject extra message headers or terminal controls.
    let name: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!(
        "From: Secure Voting Machine — {purpose} Verification\n\
         To: {name} <{phone}>\n\
         Sent: {}\n\n\
         Hi, {name}! Please find your OTP verification code below.\n\
         {purpose} OTP: {code}\n\
         This code expires in 5 minutes at {}.\n\
         Use it once and keep it private. If you did not request it, do not share it.\n\
         ---\n",
        sent.format(display_time),
        expires.format(display_time),
    )
}

#[cfg(test)]
mod message_tests {
    use super::*;

    #[test]
    fn otp_text_names_recipient_and_formats_est_and_edt() {
        for (date, zone, hour) in [
            ("2026-01-15T18:00:00Z", "EST (UTC-05:00)", "01"),
            ("2026-07-15T18:00:00Z", "EDT (UTC-04:00)", "02"),
        ] {
            let sent = DateTime::parse_from_rfc3339(date)
                .unwrap()
                .with_timezone(&Utc);
            let text = otp_message("Afia", "+15550000001", "Login", "123456", sent);
            assert!(text.contains("From: Secure Voting Machine — Login Verification"));
            assert!(text.contains("To: Afia <+15550000001>"));
            assert!(text.contains("Hi, Afia!"));
            assert!(text.contains("Login OTP: 123456\n"));
            assert!(text.contains(&format!("{hour}:00:00 PM {zone}")));
            assert!(text.contains(&format!("{hour}:05:00 PM {zone}")));
        }
    }

    #[test]
    fn expiry_is_five_minutes_even_when_clocks_fall_back() {
        let sent = DateTime::parse_from_rfc3339("2026-11-01T05:58:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let text = otp_message("Engineer", "engineer", "Setup", "654321", sent);
        assert!(text.contains("01:58:00 AM EDT (UTC-04:00)"));
        assert!(text.contains("01:03:00 AM EST (UTC-05:00)"));
        assert!(text.contains("Setup OTP: 654321\n"));
    }
}
