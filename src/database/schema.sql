CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, email TEXT COLLATE NOCASE UNIQUE,
 phone_number TEXT NOT NULL CHECK(length(trim(phone_number))>0),
 role TEXT NOT NULL CHECK(role IN ('admin','district_official','voter')),
 full_name TEXT NOT NULL CHECK(length(trim(full_name))>0),
 dob TEXT, nid TEXT, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 CHECK(role='voter' OR (email IS NOT NULL AND length(trim(email))>0))
);
CREATE TABLE IF NOT EXISTS user_credentials (
 user_id INTEGER PRIMARY KEY REFERENCES users(id), password_hash TEXT NOT NULL
);
-- Separate name avoids silently accepting legacy, predictable PIN records.
CREATE TABLE IF NOT EXISTS voter_pin_credentials (
 user_id INTEGER PRIMARY KEY REFERENCES users(id),
 lookup_hash TEXT NOT NULL UNIQUE, pin_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS elections (
 election_id INTEGER PRIMARY KEY, name TEXT NOT NULL CHECK(length(trim(name))>0),
 status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','open','closed','tallied','cancelled')),
 created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 opened_by INTEGER REFERENCES users(id), started_at TEXT, opened_at TEXT,
 closed_by INTEGER REFERENCES users(id), closed_at TEXT,
 tallied_by INTEGER REFERENCES users(id), tallied_at TEXT,
 announced_by INTEGER REFERENCES users(id), announced_at TEXT,
 CHECK(status NOT IN ('open','closed','tallied') OR (opened_by IS NOT NULL AND started_at IS NOT NULL)),
 CHECK(status NOT IN ('closed','tallied') OR (closed_by IS NOT NULL AND closed_at IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS election_positions (
 position_id INTEGER PRIMARY KEY, election_id INTEGER NOT NULL REFERENCES elections(election_id),
 name TEXT NOT NULL COLLATE NOCASE CHECK(length(trim(name))>0), display_order INTEGER NOT NULL,
 UNIQUE(election_id,name), UNIQUE(election_id,position_id)
);
CREATE TABLE IF NOT EXISTS candidates (
 candidate_id INTEGER PRIMARY KEY, election_id INTEGER NOT NULL REFERENCES elections(election_id),
 full_name TEXT NOT NULL CHECK(length(trim(full_name))>0),
 political_party TEXT NOT NULL CHECK(length(trim(political_party))>0),
 UNIQUE(election_id,candidate_id)
);
CREATE TABLE IF NOT EXISTS position_candidates (
 election_id INTEGER NOT NULL, position_id INTEGER NOT NULL, candidate_id INTEGER NOT NULL,
 PRIMARY KEY(election_id,position_id,candidate_id),
 FOREIGN KEY(election_id,position_id) REFERENCES election_positions(election_id,position_id),
 FOREIGN KEY(election_id,candidate_id) REFERENCES candidates(election_id,candidate_id)
);
CREATE TABLE IF NOT EXISTS election_voters (
 election_id INTEGER NOT NULL REFERENCES elections(election_id), user_id INTEGER NOT NULL REFERENCES users(id),
 has_voted INTEGER NOT NULL DEFAULT 0 CHECK(has_voted IN (0,1)),
 PRIMARY KEY(election_id,user_id)
);
CREATE TABLE IF NOT EXISTS ballots (
 ballot_id TEXT PRIMARY KEY NOT NULL, election_id INTEGER NOT NULL REFERENCES elections(election_id),
 UNIQUE(election_id,ballot_id)
);
CREATE TABLE IF NOT EXISTS ballot_choices (
 election_id INTEGER NOT NULL, ballot_id TEXT NOT NULL, position_id INTEGER NOT NULL, candidate_id INTEGER NOT NULL,
 PRIMARY KEY(ballot_id,position_id),
 FOREIGN KEY(election_id,ballot_id) REFERENCES ballots(election_id,ballot_id),
 FOREIGN KEY(election_id,position_id,candidate_id) REFERENCES position_candidates(election_id,position_id,candidate_id)
);
CREATE TABLE IF NOT EXISTS candidate_results (
 election_id INTEGER NOT NULL, position_id INTEGER NOT NULL, candidate_id INTEGER NOT NULL,
 votes INTEGER NOT NULL CHECK(votes>=0), PRIMARY KEY(election_id,position_id,candidate_id),
 FOREIGN KEY(election_id,position_id,candidate_id) REFERENCES position_candidates(election_id,position_id,candidate_id)
);
CREATE TABLE IF NOT EXISTS party_results (
 election_id INTEGER NOT NULL, position_id INTEGER NOT NULL, party TEXT NOT NULL,
 votes INTEGER NOT NULL CHECK(votes>=0), PRIMARY KEY(election_id,position_id,party),
 FOREIGN KEY(election_id,position_id) REFERENCES election_positions(election_id,position_id)
);
CREATE TABLE IF NOT EXISTS audit_events (
 event_id INTEGER PRIMARY KEY, election_id INTEGER REFERENCES elections(election_id),
 actor_user_id INTEGER REFERENCES users(id), subject_user_id INTEGER REFERENCES users(id),
 event_type TEXT NOT NULL, occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 severity INTEGER NOT NULL DEFAULT 0 CHECK(severity BETWEEN 0 AND 3)
);
CREATE TABLE IF NOT EXISTS auth_attempts (
 scope TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ballot_choices_tally ON ballot_choices(election_id,position_id,candidate_id);
CREATE INDEX IF NOT EXISTS audit_election ON audit_events(election_id,event_id);
CREATE TRIGGER IF NOT EXISTS ballot_choices_no_update BEFORE UPDATE ON ballot_choices BEGIN SELECT RAISE(ABORT,'Accepted votes cannot be changed'); END;
CREATE TRIGGER IF NOT EXISTS ballot_choices_no_delete BEFORE DELETE ON ballot_choices BEGIN SELECT RAISE(ABORT,'Accepted votes cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS ballots_no_update BEFORE UPDATE ON ballots BEGIN SELECT RAISE(ABORT,'Accepted ballots cannot be changed'); END;
CREATE TRIGGER IF NOT EXISTS ballots_no_delete BEFORE DELETE ON ballots BEGIN SELECT RAISE(ABORT,'Accepted ballots cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS participation_no_reset BEFORE UPDATE OF has_voted ON election_voters WHEN OLD.has_voted=1 AND NEW.has_voted<>1 BEGIN SELECT RAISE(ABORT,'Participation cannot be reset'); END;
CREATE TRIGGER IF NOT EXISTS participation_no_delete BEFORE DELETE ON election_voters WHEN OLD.has_voted=1 BEGIN SELECT RAISE(ABORT,'Participation cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'Audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'Audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS election_creator_role BEFORE INSERT ON elections BEGIN
 SELECT RAISE(ABORT,'Administrator required') WHERE NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.created_by AND role='admin' AND active=1);
END;
CREATE TRIGGER IF NOT EXISTS election_open_role BEFORE UPDATE OF opened_by ON elections WHEN NEW.opened_by IS NOT NULL BEGIN
 SELECT RAISE(ABORT,'District Official required') WHERE NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.opened_by AND role='district_official' AND active=1);
END;
CREATE TRIGGER IF NOT EXISTS election_close_role BEFORE UPDATE OF closed_by ON elections WHEN NEW.closed_by IS NOT NULL BEGIN
 SELECT RAISE(ABORT,'District Official required') WHERE NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.closed_by AND role='district_official' AND active=1);
END;

CREATE TRIGGER IF NOT EXISTS freeze_election_positions_insert BEFORE INSERT ON election_positions
WHEN COALESCE((SELECT status FROM elections WHERE election_id=NEW.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS freeze_election_positions_update BEFORE UPDATE ON election_positions
WHEN COALESCE((SELECT status FROM elections WHERE election_id=OLD.election_id),'missing')<>'draft' OR COALESCE((SELECT status FROM elections WHERE election_id=NEW.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS freeze_election_positions_delete BEFORE DELETE ON election_positions
WHEN COALESCE((SELECT status FROM elections WHERE election_id=OLD.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS freeze_candidates_insert BEFORE INSERT ON candidates
WHEN COALESCE((SELECT status FROM elections WHERE election_id=NEW.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS freeze_candidates_update BEFORE UPDATE ON candidates
WHEN COALESCE((SELECT status FROM elections WHERE election_id=OLD.election_id),'missing')<>'draft' OR COALESCE((SELECT status FROM elections WHERE election_id=NEW.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS freeze_candidates_delete BEFORE DELETE ON candidates
WHEN COALESCE((SELECT status FROM elections WHERE election_id=OLD.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS freeze_position_candidates_insert BEFORE INSERT ON position_candidates
WHEN COALESCE((SELECT status FROM elections WHERE election_id=NEW.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS freeze_position_candidates_update BEFORE UPDATE ON position_candidates
WHEN COALESCE((SELECT status FROM elections WHERE election_id=OLD.election_id),'missing')<>'draft' OR COALESCE((SELECT status FROM elections WHERE election_id=NEW.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS freeze_position_candidates_delete BEFORE DELETE ON position_candidates
WHEN COALESCE((SELECT status FROM elections WHERE election_id=OLD.election_id),'missing')<>'draft'
BEGIN SELECT RAISE(ABORT,'Election configuration is frozen outside draft state'); END;

CREATE TRIGGER IF NOT EXISTS validate_election_transition BEFORE UPDATE OF status ON elections
WHEN NOT (OLD.status=NEW.status OR (OLD.status='draft' AND NEW.status IN ('open','cancelled')) OR
 (OLD.status='open' AND NEW.status='closed') OR (OLD.status='closed' AND NEW.status='tallied'))
BEGIN SELECT RAISE(ABORT,'Invalid election lifecycle transition'); END;
CREATE TRIGGER IF NOT EXISTS election_start_as_draft BEFORE INSERT ON elections WHEN NEW.status<>'draft'
BEGIN SELECT RAISE(ABORT,'New election must be a draft'); END;
CREATE TRIGGER IF NOT EXISTS election_owner_immutable BEFORE UPDATE OF created_by ON elections WHEN NEW.created_by<>OLD.created_by
BEGIN SELECT RAISE(ABORT,'Election owner cannot change'); END;
CREATE TRIGGER IF NOT EXISTS election_minimums BEFORE UPDATE OF status ON elections WHEN NEW.status='open'
BEGIN
 SELECT RAISE(ABORT,'At least three positions required') WHERE (SELECT count(*) FROM election_positions WHERE election_id=NEW.election_id)<3;
 SELECT RAISE(ABORT,'At least two candidates per position required') WHERE EXISTS(
 SELECT 1 FROM election_positions p WHERE p.election_id=NEW.election_id AND (SELECT count(*) FROM position_candidates pc WHERE pc.position_id=p.position_id)<2);
END;
CREATE TRIGGER IF NOT EXISTS ballot_insert_open BEFORE INSERT ON ballots
WHEN COALESCE((SELECT status FROM elections WHERE election_id=NEW.election_id),'missing')<>'open'
BEGIN SELECT RAISE(ABORT,'Voting requires an open election'); END;
CREATE TRIGGER IF NOT EXISTS choice_insert_open BEFORE INSERT ON ballot_choices
WHEN COALESCE((SELECT status FROM elections WHERE election_id=NEW.election_id),'missing')<>'open'
BEGIN SELECT RAISE(ABORT,'Voting requires an open election'); END;
CREATE TRIGGER IF NOT EXISTS enroll_voter_role BEFORE INSERT ON election_voters
BEGIN SELECT RAISE(ABORT,'Voter role required') WHERE NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND role='voter' AND active=1); END;

-- Operational errors are kept separately from the admin participation view.
CREATE TABLE IF NOT EXISTS error_reports (
 error_id INTEGER PRIMARY KEY, actor_user_id INTEGER REFERENCES users(id),
 screen TEXT NOT NULL, message TEXT NOT NULL, occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Durable local alerts. PINs and OTPs never enter this queue.
CREATE TABLE IF NOT EXISTS notification_outbox (
 notification_id INTEGER PRIMARY KEY, phone TEXT NOT NULL, message TEXT NOT NULL,
 delivered INTEGER NOT NULL DEFAULT 0 CHECK(delivered IN (0,1))
);

DROP TRIGGER IF EXISTS notify_audit_event;
CREATE TABLE IF NOT EXISTS security_events (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), event_type TEXT NOT NULL,
 scope TEXT, attempts INTEGER NOT NULL DEFAULT 0, occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS email_outbox (
 id INTEGER PRIMARY KEY, recipient TEXT NOT NULL, event_id INTEGER NOT NULL REFERENCES audit_events(event_id),
 delivered INTEGER NOT NULL DEFAULT 0 CHECK(delivered IN (0,1)), UNIQUE(recipient,event_id)
);
CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO system_settings VALUES ('system_email','systemadmin@gmail.com');
CREATE TRIGGER IF NOT EXISTS security_no_update BEFORE UPDATE ON security_events BEGIN SELECT RAISE(ABORT,'Security events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS security_no_delete BEFORE DELETE ON security_events BEGIN SELECT RAISE(ABORT,'Security events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_forbid_voter_identity
BEFORE INSERT ON audit_events
WHEN
    NEW.event_type IN ('voter_participated', 'vote_rejected')
    OR EXISTS (
        SELECT 1
        FROM users
        WHERE role = 'voter'
          AND id IN (
              NEW.actor_user_id,
              NEW.subject_user_id
          )
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'Voter identity prohibited in audit log'
    );
END;
CREATE TRIGGER IF NOT EXISTS security_forbid_voter_identity
BEFORE INSERT ON security_events
WHEN
    NEW.scope LIKE 'pin:%'
    OR EXISTS (
        SELECT 1
        FROM users
        WHERE id = NEW.user_id
          AND role = 'voter'
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'Voter identity prohibited in security log'
    );
END;
CREATE TABLE IF NOT EXISTS voter_security_counts (
    day TEXT NOT NULL,
    event_type TEXT NOT NULL,
    total INTEGER NOT NULL DEFAULT 0
        CHECK(total >= 0),
    PRIMARY KEY(day, event_type)
);
CREATE TRIGGER notify_audit_event AFTER INSERT ON audit_events
BEGIN
 INSERT OR IGNORE INTO email_outbox(recipient,event_id)
 SELECT value,NEW.event_id FROM system_settings WHERE key='system_email' AND NEW.severity>0;
 INSERT OR IGNORE INTO email_outbox(recipient,event_id)
 SELECT u.email,NEW.event_id FROM users u WHERE u.active=1 AND u.role='admin' AND (
 u.id=(SELECT created_by FROM elections WHERE election_id=NEW.election_id) OR
 u.id=NEW.actor_user_id OR
 EXISTS(SELECT 1 FROM election_voters v JOIN elections e USING(election_id) WHERE v.user_id=NEW.actor_user_id AND e.created_by=u.id));
 -- DO receives only lifecycle/configuration notices; no participation/authentication feed.
 INSERT INTO notification_outbox(phone,message)
 SELECT phone_number,'Event: '||NEW.event_type||' | '||NEW.occurred_at FROM users
 WHERE active=1 AND role='district_official' AND NEW.event_type IN
 ('election_created','position_added','position_updated','position_deleted','candidate_added','candidate_updated','candidate_unlinked','candidate_linked','election_opened','election_closed','election_tallied','results_announced');
END;

-- Stored results and final timestamps cannot be rewritten by ordinary SQL updates.
CREATE TRIGGER IF NOT EXISTS election_final_tally BEFORE UPDATE OF tallied_at,tallied_by ON elections
WHEN OLD.tallied_at IS NOT NULL AND (NEW.tallied_at IS NOT OLD.tallied_at OR NEW.tallied_by IS NOT OLD.tallied_by)
BEGIN SELECT RAISE(ABORT,'Tally is final'); END;
CREATE TRIGGER IF NOT EXISTS election_final_announcement BEFORE UPDATE OF announced_at,announced_by ON elections
WHEN OLD.announced_at IS NOT NULL AND (NEW.announced_at IS NOT OLD.announced_at OR NEW.announced_by IS NOT OLD.announced_by)
BEGIN SELECT RAISE(ABORT,'Announcement is final'); END;
CREATE TRIGGER IF NOT EXISTS candidate_results_no_update BEFORE UPDATE ON candidate_results BEGIN SELECT RAISE(ABORT,'Results are immutable'); END;
CREATE TRIGGER IF NOT EXISTS candidate_results_no_delete BEFORE DELETE ON candidate_results BEGIN SELECT RAISE(ABORT,'Results are immutable'); END;
CREATE TRIGGER IF NOT EXISTS candidate_results_no_late_insert BEFORE INSERT ON candidate_results WHEN EXISTS(SELECT 1 FROM elections WHERE election_id=NEW.election_id AND (status!='closed' OR tallied_at IS NOT NULL OR announced_at IS NOT NULL)) BEGIN SELECT RAISE(ABORT,'Results require a first tally'); END;
CREATE TRIGGER IF NOT EXISTS party_results_no_update BEFORE UPDATE ON party_results BEGIN SELECT RAISE(ABORT,'Results are immutable'); END;
CREATE TRIGGER IF NOT EXISTS party_results_no_delete BEFORE DELETE ON party_results BEGIN SELECT RAISE(ABORT,'Results are immutable'); END;
CREATE TRIGGER IF NOT EXISTS party_results_no_late_insert BEFORE INSERT ON party_results WHEN EXISTS(SELECT 1 FROM elections WHERE election_id=NEW.election_id AND (status!='closed' OR tallied_at IS NOT NULL OR announced_at IS NOT NULL)) BEGIN SELECT RAISE(ABORT,'Results require a first tally'); END;
