use itertools::Itertools;
use rocket::serde::{Deserialize, Serialize};
use tabled::settings::Style;
use tabled::{Table, Tabled};

use crate::types::{ServerState, UserRecord};
use crate::UserId;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub enum UserStatus {
    IDAcquired,
    CipherSubmitted,
    DecryptionShareSubmitted,
}
impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
#[serde(crate = "rocket::serde")]
pub struct RegisteredUser {
    pub id: UserId,
    pub name: String,
    pub status: UserStatus,
}

impl RegisteredUser {
    pub(crate) fn new(id: UserId, name: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
            status: UserStatus::IDAcquired,
        }
    }
}
impl From<&UserRecord> for RegisteredUser {
    fn from(user: &UserRecord) -> Self {
        use crate::types::UserStorage::*;
        let status = match user.storage {
            Empty => UserStatus::IDAcquired,
            CipherSks(_, _) => UserStatus::CipherSubmitted,
            DecryptionShare(_) => UserStatus::DecryptionShareSubmitted,
        };

        Self {
            id: user.id,
            name: user.name.to_string(),
            status,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Dashboard {
    status: ServerState,
    users: Vec<RegisteredUser>,
}
impl Dashboard {
    pub(crate) fn new(status: &ServerState, users: &[RegisteredUser]) -> Self {
        Self {
            status: status.clone(),
            users: users.to_vec(),
        }
    }

    pub fn get_names(&self) -> Vec<String> {
        self.users
            .iter()
            .map(|reg| reg.name.to_string())
            .collect_vec()
    }

    /// An API for client to check server state
    pub fn is_concluded(&self) -> bool {
        self.status == ServerState::ReadyForInputs
    }

    pub fn is_fhe_complete(&self) -> bool {
        self.status == ServerState::CompletedFhe
    }

    pub fn print_presentation(&self) {
        println!("🤖🧠 {}", self.status);
        let users = Table::new(&self.users)
            .with(Style::ascii_rounded())
            .to_string();
        println!("{}", users);
    }
}
