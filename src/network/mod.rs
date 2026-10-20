//! Four loopback TLS listeners: three role gateways and one private database service.
//! Gateways use distinct mTLS identities. Database authorization uses server-held sessions.
pub mod client;
mod dispatch;
mod monitor;
mod protocol;
mod registry;
mod server;
mod state;
pub use client::{ApiClient, ClientAuth};
pub use protocol::{PendingLogin, Session};
use protocol::{Request, Response};
pub use server::Network;
#[cfg(test)]
use state::SessionRecord;
use state::State;
#[cfg(test)]
mod tests;
pub mod tls;
use crate::{
    auth,
    models::*,
    services::{self, AppResult},
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Map a role to its dedicated gateway address/certificate index.
fn role_index(role: Role) -> usize {
    match role {
        Role::Admin => 0,
        Role::DistrictOfficial => 1,
        Role::Voter => 2,
    }
}
const ROLES: [Role; 3] = [Role::Admin, Role::DistrictOfficial, Role::Voter];
