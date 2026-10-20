# America’s Next Top Threat Model: STRIDE and implementation assurances

**Group 4 · Secure Systems Engineering · E-voting system v0.2.5**

This document connects our original implementation plan to the system we actually built. For each proposed protection, we explain what is implemented, what evidence supports it, and what still needs work. The goal is to make the security argument checkable—because “we added TLS” cannot do all the heavy lifting.

**Source:** *Group 4_ Implementation Details(1).pdf*, dated 13 October 2026, 13 pages. Page references below refer to that PDF. Implementation references refer to the v0.2.5 source release and its saved test transcripts. This is a documentation review of that tested release; no new application changes or test runs are claimed here.

**Status key:** **Implemented** means present in the reviewed code. **Tested** means the cited regression or terminal journey exercises the stated behavior. **Changed** means we deliberately implemented a different approach from the proposal. **Partial / Not implemented** identifies a remaining gap. Passing our tests supports the specific checks; it is not proof that every possible attack is blocked.

## 1. Objective, architecture and trust boundaries

The PDF’s objective is a completely software-based voting demonstration, without requiring physical phones or paper ballots (pp. 1–2). We meet that objective with a Rust terminal UI, SQLite, virtual text-message/email inboxes, and real TLS connections over loopback. The TUI is the CLI-facing interface; there is no web frontend.

| Boundary | What crosses it | Protection and assumption |
| --- | --- | --- |
| User → terminal client | Credentials, OTPs, registration fields, ballot selections | Secret-field masking and format checks. The backend repeats validation and authorization; a modified client is not trusted. |
| Terminal client → role gateway | Framed JSON requests over TCP | TLS server certificate/hostname validation. The client trusts the development CA. A role selection alone grants no access. |
| Role gateway → database service | Requests and server-issued session tokens | Mutual TLS with distinct admin, DO and voter gateway certificates. The certificate’s role must agree with the request/session. |
| Database service → registry service | Voter ID, name, DOB and phone verification | Separate registry trust root and exact authorized client-certificate check. Returns a verification outcome, not a downloadable voter directory. |
| Service → SQLite | Configuration, identity, enrollment, ballots, results and logs | Parameterized queries, transactions, foreign keys, uniqueness checks and triggers. Backend ownership/role/state checks remain necessary. |
| Service → local files | Virtual SMS/email, development keys and JSON traces | Restricted POSIX permissions and validated inbox filenames. These files remain accessible to the trusted OS account. |

The gateways, database service and registry are separated logically and communicate through actual network endpoints. In classroom mode they can share one process and host. TLS does not isolate ordinary Rust function calls or protect us from an administrator who controls that host.

### Assets: what we are protecting

The PDF’s §4.1 repeats the stakeholder table rather than listing assets (pp. 9–10). We retain those stakeholders below and make the assets explicit here.

| Asset | Required property |
| --- | --- |
| Election configuration: positions, candidate names/parties, ownership | Only the owning admin changes drafts; freeze configuration once voting opens. |
| Voter identity: ID, name, DOB, phone and optional email | Restrict access, reject duplicate IDs, validate against the demo registry, prevent ordinary phone redirection. |
| Password/PIN verifiers, OTP challenges, session tokens and pepper | Prevent disclosure and guessing; enforce expiry, retry limits and session-role binding. |
| Enrollment and participation flags | One accepted whole ballot per voter per election; no resetting accepted participation through supported operations. |
| Ballots and choices | Atomic submission, valid election/position/candidate relationships, immutability, no explicit voter-to-ballot identifier. |
| Candidate/party totals and final timestamps | First tally only; prevent ordinary rewriting after tally or announcement. |
| Audit/security records, anonymous counters, notification outboxes | Preserve evidence of permitted changes and rejected actions while limiting privacy leakage. |
| TLS certificates and private keys | Authenticate actual endpoints, protect traffic, keep private keys off ordinary clients. |
| Registry database and service | Read-only application access, canonical identity/age/phone checks, rejection when verification is unavailable. |
| Service availability, source code and deployment configuration | Bound resource consumption; protect engineer setup and deployment secrets. |

### Stakeholders and adversaries

All nine stakeholder categories from §§4.1–4.2 (pp. 9–11) are represented:

| Stakeholder | Goal and permitted capability | Security concern |
| --- | --- | --- |
| System engineers | Configure/deploy the system and approve privileged signup | Trusted access can bypass application protections; engineer inbox and host must remain private. |
| Election administrator | Create own elections, manage draft configuration, register/enroll voters and review own audit history | Compromised credentials or misuse of legitimate authority. |
| District official | Open/close elections, tally and display winners | Unauthorized lifecycle changes or repeated tally/announcement attempts. |
| Voter | Authenticate with PIN plus OTP and submit one complete ballot | Credential theft, duplicate submissions, privacy loss or accidental invalid input. |
| Candidates | Receive fair and accurate results; no privileged account by default | The implementation displays results through the DO interface, not a separate public candidate portal. |
| Developers/maintainers | Review, modify and test code; potentially access development databases | Source changes and privileged database access are outside normal voter/admin permissions. |
| External attacker | Guess credentials, submit malformed requests, inspect or disrupt traffic | Spoofing, endpoint misuse, injection and resource exhaustion. |
| Malicious insider | Abuse an existing account or accessible records | Cross-owner access, privilege misuse, collusion and data manipulation. |
| Competing candidate acting maliciously | Gain advantage through collusion or credential misuse | No special privileges, but may act through another compromised stakeholder. |

## 2. Complete proposal-to-implementation checklist

This section covers the PDF’s user journey, required functionality, additional monitoring feature and proposed mechanisms. Differences are written down instead of quietly treating the original plan as completed.

### Authentication and monitoring: §§2.0, 2.2 and 4.3

| PDF proposal | Current behavior and status |
| --- | --- |
| Welcome screen asks the user’s role and routes to the appropriate interface (p. 2) | **Implemented/tested.** Admin, DO and voter flows; successful authentication precedes protected actions. Backend checks prevent role-menu spoofing. |
| Engineers pre-register known admins/DOs; ordinary signup excluded (pp. 2–3) | **Changed/tested.** Local `--signup`/`--setup` exists, gated by an engineer OTP and setup capability. Ordinary remote client/server mode cannot provision staff. Signup does not create a logged-in session. |
| `better-auth` for staff authentication (p. 3) | **Changed.** Custom Rust authentication uses bcrypt password verification, a private pepper and server-held sessions. The proposed dependency is not used. |
| Five failed sign-ins trigger severity 3 (p. 3) | **Implemented/tested.** Five failed passwords for a normalized-email lookup scope cause a five-minute cooldown. This is account/scope-based, not a machine/IP ban. Failed/locked/blocked staff events are recorded. |
| OTP using proposed `topt-rs`, `socat`, `virtualsms-io`, or possibly Twilio (p. 3) | **Changed/tested.** Random six-digit OTP, five-minute validity, keyed verifier and local phone-named text inbox. No serial-port SIM service, TOTP provider or real SMS subscription is used. |
| Three wrong OTPs disable the individual and trigger severity 3 plus alerts (pp. 3–4) | **Implemented with changed reporting.** Three failures invalidate the challenge and impose a five-minute scope cooldown. Staff failures are individually audited; voter failures become anonymous daily counters. The whole system is not disabled. |
| Reusable login/PIN/OTP module functions (pp. 3–4) | **Implemented.** Authentication is centralized in `src/auth/login.rs`; network challenge/session handling lives in `src/network/state.rs`. |
| Voter PIN possibly generated using SHA3; PIN identifies a digital ballot (p. 4) | **Changed/tested.** Random 20-digit credential with a bcrypt verifier and keyed lookup. It is not derived from the voter ID and is not stored as the ballot identifier. |
| More than ten incorrect PIN entries trigger severity 3 and SMS/email alerts (p. 4) | **Changed/tested.** Ten failures at the same PIN lookup cause a five-minute cooldown. Failures/locks use anonymous counters rather than per-voter severity records or per-voter incident messages. |
| Log each failure, block offending IP/port after ten failures, severity 1 (p. 4) | **Partial.** Scoped cooldowns, listener limits and transport rejection aggregation exist. Automatic per-IP/port banning and level-1 escalation do not. A loopback-wide ban would block legitimate demo users too. |
| Robust independent logging such as `prometheus-client`, preserving logs during a breach (p. 3) | **Partial/changed.** SQLite audit/security records plus Jeremy’s JSON tracing, append-only triggers and queued notifications. No independent monitoring server, signed log archive or protection against the host/database owner. |
| TLS handshakes between ports; more than ten bad handshakes triggers severity 2 (p. 3) | **Implemented with qualification.** TLS on the actual network hops; more than ten accumulated rejected transports produces `tls_or_protocol_flood`, severity 2. The counter combines TLS/protocol/admission rejection; it is not a per-source, handshake-only classifier. |
| Monitor unforeseen downtime and report severity 1 (p. 4) | **Not implemented as proposed.** Request timeouts/watchdogs exist. No independent health monitor can report a fully dead process or host. |
| Detect failed login, OTP, suspected DoS and suspicious requests automatically (pp. 6–7) | **Implemented with privacy changes.** Staff/system records, transport aggregates, request deadlines and anonymous voter counters cover these classes. Failed requests are evidence of errors or attempts, not automatic proof of an attacker. |

### Role tasks and election behavior: §§2.0–2.1

| PDF proposal | Current behavior and status |
| --- | --- |
| Admin creates elections with ≥3 positions and ≥2 candidates each; full name and political party required (pp. 4, 6) | **Implemented/tested.** Creation seeds three positions/two candidates; editing/opening constraints preserve minimums. Candidate identity may be shared across positions. |
| Admin modifies positions and candidates; record changes and notify (pp. 5–6) | **Implemented/tested.** Owning-admin draft-only CRUD, transactional audit and queued lifecycle/configuration notifications. The merged candidate-edit handler was repaired and exercised through the terminal. |
| Register full name, DOB, phone and NID; check prior registration; issue unique PIN (pp. 5–6) | **Implemented/tested.** Normalized fields, unique identity, registry matching, age checks, PIN credential and enrollment. Failed database/ordinary delivery operations roll back registration; filesystem writes are not a distributed transaction. |
| Admin reviews lifecycle, voter information and timestamps (pp. 5–6) | **Implemented with privacy changes.** **Admin → View Audit Log** shows owned-election events, including cancelled elections, plus own account events. Identity/participation is in the authorized voter list; new audit rows do not contain voter actor/subject identity. |
| Include party votes and identity-linked vote submissions in admin audit (pp. 5–6) | **Deliberately changed.** No individual vote success/failure audit or party-choice feed for admins. The PDF’s own confidentiality requirement on p. 12 motivates this separation. |
| Admin and DO can flag unexplained changes as severity 2 (p. 4) | **Partial.** Owning admin can flag an incident from the audit screen. DO incident-flag/audit access is not implemented. |
| Unidentified/unauthorized changes should be severity 2 (pp. 4–5) | **Changed classification.** Manual concerns and finality rejections are severity 2. Generic rejected requests/authorization failures normally use severity 3, consistent with unsuccessful attempts; voter requests use aggregates. |
| DO starts an existing election (pp. 5–6) | **Implemented/tested.** Draft → open only; minimum configuration validated. Admins/voters cannot invoke the operation successfully. |
| DO ends an election (pp. 5–6) | **Implemented/tested.** Open → closed only. Closed/tallied elections cannot reopen. |
| DO tallies and evaluates each position’s winner (pp. 5–6) | **Implemented/tested.** Closed, never-tallied election only. Candidate and party totals per position include zero-vote candidates; ties/no-vote positions are displayed explicitly. |
| DO announces winners (pp. 5–6) | **Implemented/tested.** Announcement requires a tally and occurs once. Repeated attempts leave warnings without changing final timestamps/results. |
| Voter authenticates with PIN and OTP (pp. 4, 6) | **Implemented/tested.** PIN verification precedes OTP; challenge replay, expired OTPs and invalid sessions are rejected. |
| Voter casts one immutable vote per position in an open election (pp. 5–6) | **Implemented with a whole-ballot workflow.** Selections remain local until Submit. Exactly one choice per position commits atomically; accepted ballots cannot be edited. Partial/duplicate/concurrent submissions are checked. |
| Log every vote submission and make PIN single-use (pp. 6, 12) | **Changed.** PIN remains a reusable authentication credential. Enrollment permits one accepted ballot per election. No individual vote audit; denied voter requests can increment an anonymous category counter. |

### Original STRIDE mechanisms that need an explicit status

| PDF mechanism | Current status |
| --- | --- |
| National database API returns NIDs and registered phones (p. 11) | **Simulated/changed.** Bundled fictional SQLite registry includes ID, name, DOB and phone. Its authenticated endpoint returns verification status only. No real government integration or real-world identity proof. |
| Deliver PIN only after OTP authentication to the registry phone (p. 11) | **Partial.** PIN goes directly to the matched phone’s virtual inbox during registration; the admin then answers “Did voter receive PIN?” OTP is required at voter login, not before initial PIN issuance. Confirmation is an admin report, not device-possession proof. |
| TLS around every sensitive subsystem operation (p. 12) | **Implemented for exposed network boundaries.** In-process service functions do not perform their own TLS handshakes. Authorization, transactions and constraints protect operations after transport authentication. |
| Alert admins about privileged activity from unfamiliar ports (p. 12) | **Partial.** Recognized gateway certificates and role binding are enforced; rejected transports are monitored. There is no learned “usual port/device” profile or suspicious-location alert. |
| Trace all actions and prevent log tampering (p. 12) | **Partial/changed.** Structured administrative/security evidence and anonymous voter counts. Logging every voter action would damage privacy; local logs are not tamper-proof against a privileged OS/database owner. |
| Confidential data inaccessible to unauthorized parties; participation not linked to choices (p. 12) | **Implemented at supported application interfaces, with limits.** Restricted role endpoints and ballots without user IDs/PINs/timestamps remove the explicit join. Timing, transaction order, local inbox observation, collusion and very small elections remain risks. SQLite is not encrypted at rest. |
| Timeout, e.g. 20,000 ms, followed by HTTP 500 (pp. 12–13) | **Changed/tested.** Ten-second request budget, socket watchdog, database deadline checks and structured error responses. The protocol is framed JSON over TLS, not HTTP; there is no HTTP 500 status. |
| Notify existing admins, engineers and DO account holder about every privileged login (p. 13) | **Partial.** Staff login is audited/traced and OTP goes to the account’s inbox. Admin own-account events reach the admin email outbox; system email receives errors. There is no all-admin broadcast or separate successful-login alert to every DO/system engineer. |
| Engineer OTP for every privileged-account customization; detect bypass as severity 2 (p. 13) | **Partial.** Engineer OTP gates the local setup session/capability for provisioning. There is no ordinary staff-role customization endpoint, per-edit engineer challenge, or independent detector for direct database role changes. |

## 3. STRIDE analysis of the implemented system

### S — Spoofing: “Who are you?” needs a backend answer

An attacker may steal staff credentials, guess a voter PIN, forge a session, reuse an OTP, claim another gateway role, or register using someone else’s ID and a different phone.

**Our controls:** bcrypt plus pepper; random PINs and keyed lookup; OTP expiry and retry limits; server-issued, role-bound sessions with a 30-minute lifetime; TLS identity checks; mutual TLS on internal hops; canonical registry matching. The registry checks both the submitted age and stored DOB, so changing a minor’s entered DOB to an adult DOB does not pass.

**Evidence:** `otp_completes_once_and_wrong_role_cannot_log_in`, `session_and_challenge_cannot_be_forged_replayed_or_used_on_another_gateway`, `registry_phone_forgery_minor_and_injection_attempts_have_private_audits`, registry TLS tests and the real signup/login journey.

**Assurance boundary:** We reject the tested credential, replay, role and identity-mismatch attempts. Matching a fictional record does not prove the human’s identity or phone ownership. Same-host inboxes simulate a second step; they are not an independent authentication factor against the host owner.

### T — Tampering: a rejected request must not leave half a ballot

Threats include SQL-shaped input, editing live candidates, mixing candidates across elections, changing accepted choices, double voting, rewriting totals and repeated tallying after announcement.

**Our controls:** parameterized SQL, input validation, ownership and lifecycle checks, foreign keys, uniqueness constraints, atomic whole-ballot transactions and an irreversible participation flag. SQL triggers block ordinary ballot/result rewriting and final timestamp changes. Tally no longer deletes and recalculates existing results. A successful sensitive mutation and its audit record commit together through the shared transaction helper.

**Evidence:** candidate/position CRUD tests; `ballots_are_atomic_immutable_and_do_not_link_to_identity`; `concurrent_duplicate_submissions_commit_only_one_ballot`; `final_results_and_timestamps_survive_repeated_tally_and_sql_tampering`; `tally_audit_failure_rolls_back_totals_and_timestamp`; `audit_failure_rolls_back_election_edit`.

**Assurance boundary:** Supported operations and the tested direct SQL edits cannot silently rewrite accepted results. Someone who owns the database can remove triggers or replace the file. We do not implement an authorized recount, signed ballot protocol or independent result-verification system.

### R — Repudiation: receipts for changes, without receipts for everyone’s vote

A compromised account may change configuration and deny it, forge client error text, erase evidence or exploit a failed notification.

**Our controls:** timestamped SQLite audit records with event type, staff actor where known, election scope and severity; append-only triggers; fixed client-error messages; Jeremy’s rotating JSON traces; durable notification outboxes. Traces for committed administrative operations are emitted after commit. Failed email delivery leaves pending work for retry.

**Evidence:** `incident_audits_are_owner_scoped_and_append_only`, audit-rollback tests, forged-log input checks, email retry tests, and terminal inspection of lifecycle/rejection traces.

**Assurance boundary:** Attribution identifies the account, not necessarily the human operating it. SQLite is authoritative; JSON tracing is asynchronous and may lose queued events on a crash or under pressure. No digital signatures, remote witness or independently protected archive provides cryptographic non-repudiation. Existing historical logs are retained, not scrubbed.

### I — Information disclosure: the audit should not become a ballot lookup

Threats include admin access to choices, DO access to voter identity, credentials in logs, arbitrary error text leaking secrets, registry enumeration and direct access to local files.

**Our controls:** admin/DO/voter endpoint separation; owner-scoped admin reads; no general raw-ballot endpoint; ballots without explicit identity/PIN/session/timestamp fields; no individual vote audit. SQL/application guards reject new voter-identifying audit/security inserts. Voter failures use daily aggregate categories. Registry responses disclose only status. PINs stay off the admin form; trace fields exclude names, phones, credentials and choices. Database/inbox/key permissions restrict other OS accounts on POSIX systems.

**Evidence:** `real_tls_full_election_and_role_privacy`, `direct_endpoints_reject_bad_fields_and_cross_role_reads`, `voter_events_are_aggregate_only_and_identity_inserts_are_blocked`, `unauthenticated_voter_failures_do_not_make_individual_request_logs`, masked-field UI tests and JSON-log inspection in the terminal run.

**Assurance boundary:** Admins still see participation through their voter lists. Retry state, enrollment, outboxes and local files contain operational identity information. An observer with privileged access may correlate timing/order or infer a choice in a one-voter election. We do not claim cryptographic unlinkability or encrypted storage.

### D — Denial of service: timeout the request, not the entire election

Threats include repeated login attempts, random-PIN flooding, malformed/oversized messages, handshake floods, slow sockets and expensive work that holds a service busy.

**Our controls:** five-minute scoped cooldowns; a ten-second request budget; socket timeout/watchdog; SQLite interruption and pre-commit deadline checks; 1 MiB frame limit; 32 active workers and 64 admissions per second per listener; bounded retry/session storage; aggregated transport reporting instead of one database write per bad packet.

**Evidence:** password/OTP/PIN limit tests; oversized/truncated framing tests; `expired_wire_request_cannot_create_election`; `expired_mutation_does_not_commit`; `client_rejects_response_after_ten_second_deadline`; `server_watchdog_closes_stalled_handler_and_counts_timeout`; transport incident tests.

**Assurance boundary:** These reduce exposure; they do not provide volumetric DDoS protection, fair scheduling or a hard real-time guarantee. bcrypt and filesystem operations cannot always be interrupted immediately. A commit followed by a lost response leaves the client uncertain: refresh state before retrying. No independent outage monitor, automatic IP ban or complete disk-retention policy is implemented.

### E — Elevation of privilege: hidden buttons are not authorization

An attacker may switch the claimed role, call another role’s endpoint directly, use someone else’s election ID or try to provision a privileged account through an ordinary client.

**Our controls:** backend checks of active database role, session role, gateway-certificate role and election ownership; explicit endpoint allowlist; privileged setup restricted to engineer-approved local mode. Admin cannot tally, DO cannot inspect the voter list/audit, and voter cannot configure elections.

**Evidence:** role/ownership service tests, forged-session/gateway tests, direct cross-role endpoint tests, setup rejection tests and engineer-OTP signup through the terminal.

**Assurance boundary:** An authorized DO can perform the DO’s legitimate operations; there is no two-person approval rule. A stolen fully authenticated account has its normal powers until expiry/logout/deactivation. Trusted engineers and direct database writers can change the deployment outside application controls.

## 4. Logging, incident levels and notification routing

The PDF’s legend (p. 13) defines **1 = outage**, **2 = harmful/unexpected incident**, **3 = unsuccessful attempt**. We preserve the numeric scheme and use **0** for normal informational activity. The numbers are project categories, not a conventional ascending severity scale.

| Event class | Actual recording | Alert / limitation |
| --- | --- | --- |
| Election creation, edits, cancellation, opening, closing, first tally and announcement | SQLite audit, severity 0; committed-operation JSON trace | Owning-admin email notifications; allowlisted lifecycle/configuration events also go to DO virtual SMS. |
| Voter registration | Admin/election audit, severity 0; no voter subject identity; JSON trace | PIN delivered separately to the matched phone inbox. |
| Missing registry ID / mismatch / underage / unavailable registry | `voter_identifier_not_found`, `voter_registry_mismatch`, `voter_not_eligible_underage`, `voter_registry_unavailable`, severity 2 | Owner/system error notification routes; no applicant name, ID, DOB or phone in the event. |
| PIN receipt response | `pin_receipt_confirmed` = 0; `pin_receipt_not_confirmed` = 2 | Administrator/election attribution only. “No” keeps registration saved; does not regenerate the PIN. |
| Repeated tally/announcement | `tally_rejected`, `announcement_rejected`, severity 2 | Stored counts and original timestamps remain unchanged. No recount is performed. |
| Admin flags unexplained change | `unidentified_change_reported`, severity 2 | Owner-scoped audit and queued notifications. DO flagging is unavailable. |
| Staff authentication | Normal attempts/verification/success at 0; failed/expired/locked/blocked events at 3 | Staff/system structured records. Some pre-account-lookup failures have no actor. No raw password/OTP in logs. |
| Staff/system request errors and authorization denial | Fixed event categories, generally severity 3 | Sanitized logs; supplied exception/body text is not trusted evidence. |
| TLS/protocol rejection | Aggregate transport event at 3; accumulated count over ten produces flood event at 2 | System routing. This does not establish who attacked or prove an attack occurred. |
| Request timeout | Staff/system `request_timeout`, generally severity 3; voter request failures aggregated | A timed-out request is not automatically a confirmed level-1 outage. |
| Voter PIN/OTP/authorization/client/request failures | `voter_security_counts`: UTC day, category, total | No individual timestamp/actor/session/election record and no per-voter error alert. Counts represent categories, not necessarily unique requests. |
| Successful vote | Ballot/enrollment transaction and private queued thank-you text | No individual success audit/trace linking the voter to submission. |
| Total process/host outage | No reliable external reporter | Level 1 remains a proposed category, not a fully implemented monitoring assurance. |

**Files and routing:** JSON traces are written to `logs/security.jsonl.YYYY-MM-DD`. Virtual SMS uses `virtual_sms/<phone>.txt`; engineer approval uses the fixed `engineer.txt` inbox. Email-style notifications use `virtual_sms/emails/<email>.txt`, with `systemadmin@gmail.com` as the configurable default system recipient. These are text files, not messages sent to mobile networks or Gmail.

The system email route receives severity >0 events. Admin routes are scoped to the account/owned election; we do not broadcast every incident to every admin. DO SMS notifications are restricted to an explicit lifecycle/configuration allowlist. Anonymous voter counters do not produce the PDF’s proposed individual SMS/email security alerts. Successful engineer provisioning is recorded in SQLite; not every SQLite event has an identical one-for-one JSON trace.

Notification delivery is retried during later activity. A crash after file output but before marking delivery can duplicate a notification. Ordinary failures retain pending outbox rows; a totally dead host cannot notify itself. Append-only triggers protect against ordinary SQL edits, not an owner who can drop them.

## 5. Additional protections introduced after the PDF

| Addition | Assurance supported by the implementation |
| --- | --- |
| Read-only statewide demo database | `demo/statewide_voters.sqlite` stores ID, name, DOB and phone. `VOTING_REGISTRY_DB` can select another database; missing/unreadable production registry prevents startup rather than accepting identities unchecked. |
| Canonical identity/phone matching | Redirecting the phone or changing the supplied identity fields fails verification. The application does not return the full registry. |
| Age eligibility | Real date validation; both entered and stored DOB must meet age 18. New York calendar date is used. Under the demo rule, February 29 birthdays reach the threshold on March 1 in non-leap years. This is an implementation rule, not a legal eligibility determination. |
| Valid-record guide | `demo/voter_ids.txt`, README includes matching DOB/phone records and a deliberately underage record. All identities are fictional. |
| PIN receipt question | Admin answers yes/no after private delivery; both outcomes have tested audit behavior without revealing the PIN or voter identity. |
| Final result protection | First tally only, no deleting/recalculating prior totals, immutable result rows and final timestamps, duplicate-announcement rejection. |
| Cancelled-election audit access | Cancellation hides a draft from ordinary selection but keeps it selectable in the owning admin’s audit view. |
| Atomic submission and private receipt | Whole ballot, participation flag and thank-you queue entry commit together; no receipt is queued for a rejected/rolled-back vote. UI signs out after success. |
| Jeremy’s tracing and voter privacy changes | Rotating JSON logging, safe selected fields, anonymous failure counts and SQL privacy guards are retained. Centered menus are retained too, although layout itself is not a security control. |
| Integration regression repair | Candidate edits update candidate name/party rather than running the misplaced enrollment/vote update. Service tests and real terminal CRUD cover the repair. |

## 6. Evidence: what we actually exercised

The saved v0.2.5 validation reports **58 Rust tests passed**, a successful fresh build, clean Clippy with warnings denied, formatting checks and a successful real CLI/TUI journey on Linux. Native macOS/Windows runs are not claimed. The accepted-socket blocking-mode fix has a portable regression test.

| Evidence file in the project | What it supports |
| --- | --- |
| `tests/latest-rust-run.txt` | Exact test names and 58-pass result. |
| `tests/latest-build-run.txt` | Fresh compilation of the release. |
| `tests/latest-clippy-run.txt` / `latest-format-run.txt` | Static checks and formatting; these do not establish security by themselves. |
| `tests/latest-terminal-run.txt` | Signup, admin CRUD, registration/PIN, audit view, voter flow, DO lifecycle, winner display and privacy checks. |
| `tests/terminal_smoke.py` | Reproducible keyboard-driven PTY test against a separate TLS server and disposable SQLite data. |
| `src/services/tests.rs` | Transactions, constraints, ownership, finality, receipt behavior, logging integrity and authentication cases. |
| `src/network/tests.rs` / `src/network/registry.rs` tests | Actual sockets/TLS, direct endpoint misuse, registry forgery, framing, session replay and deadline cases. |
| `src/ui/tests.rs` / validation tests | UI state, masked credentials, invalid forms, age boundaries and input rules. |

The terminal journey created an election, registered a voter, submitted a complete ballot, closed and tallied the election, and displayed **Winner: Red Burger**. It then returned from the results screen to the lifecycle controls, attempted two additional tallies and another announcement, required new rejection records, and verified unchanged results/timestamps. JSON traces were inspected for expected lifecycle/security events and the absence of the tested voter identity, PIN and candidate-choice values.

The local adversarial checks include forged/replayed sessions, wrong-role endpoints, invalid TLS peers, SQL-shaped IDs, phone substitution, a false adult DOB for a minor, malformed frames, slow requests, concurrent duplicate voting, direct result edits, forged error text and failed audit/delivery operations. These are targeted regression tests against our own temporary system. Calling this a comprehensive production penetration test would be a stretch.

## 7. Remaining PDF sections and project traceability

The PDF’s non-security sections are accounted for here so they do not disappear from the comparison.

| PDF section | Coverage / qualification |
| --- | --- |
| Title, executive summary and objective (pp. 1–2) | Group 4’s software-only e-voting project and its intended 19 October 2026 delivery scope are the context for this assessment. A planned deadline is not proof of implementation completion. |
| §2.3 Control Flow Diagram; §2.4 Functional Block Diagram (p. 7) | The PDF points to external Lucidchart documents rather than embedding the full diagrams. Those linked diagrams were not independently reviewed here. The trust-boundary table describes the inspected code, not a claim that either external diagram is current. |
| §3 Authentication task (p. 7) | Planned assignee: Afia Fahmida Rahman; date: 16 October 2026. Authentication/role routing is covered above. |
| §3 Admin task (pp. 7–8) | Planned assignee: Chinnonye Okafor; date: 17 October 2026. Create/register/customize functions are covered in the role checklist. |
| §3 DO task (p. 8) | Planned assignees: Chinnonye/Afia; date: 17 October 2026. Start/end/tally/announce are covered above. |
| §3 Voter task (p. 8) | Planned assignee: Afia; date: 17 October 2026. Login and immutable voting are covered above. |
| §3 Logging task (p. 8) | Planned assignee: Jeremy; date: 18 October 2026. Creation/start/end/tally/announcement, authentication/request/certificate failures and registration are mapped in the logging section. Individual voting logs were deliberately replaced by the privacy design. Certificate failures are transport categories, not a separate “PK verification” audit for every handshake. |
| §§4.1–4.2 Assets/stakeholders (pp. 9–11) | All nine stakeholder categories retained; separate asset inventory supplied because the PDF duplicates stakeholder content under assets. |
| §4.3 Six STRIDE categories (pp. 11–13) | Each attack family, proposed mechanism, implemented defense, evidence and remaining gap is addressed above. |
| §5.1 Incident legend (p. 13) | Original 1/2/3 meanings preserved and compared with actual severity usage; informational 0 explained. |

Task assignments above reproduce the original plan. They are not a claim about each person’s eventual contribution, authorship or completion date. Commit history, reviews and actual work should support those claims.

## 8. What we can responsibly assure

We can demonstrate that the tested release enforces role/ownership checks, verifies fictional registry records, protects accepted ballot/result state through the supported application path, records administrative changes and relevant rejections, and keeps individual voter identity/choices out of newly generated audit/tracing records. We can also demonstrate the specific negative cases listed in our tests.

We cannot assure real-world identity, independent MFA through same-host files, cryptographic ballot anonymity, tamper-proof logs against a privileged host owner, continuous availability, or complete implementation of every mechanism proposed in the PDF. Those are real boundaries, not fine print. Our next steps would be driven by the deployment threat model: independently protected credentials/inboxes, external monitoring and log retention, a genuine authorized registry integration, and reviewed procedures for recounts and privileged-account changes.

