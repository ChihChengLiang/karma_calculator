use itertools::Itertools;
use phantom_zone::{
    evaluator::NonInteractiveMultiPartyCrs,
    keys::CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare, parameters::BoolParameters,
    SeededBatchedFheUint8,
};
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::Mutex;
use rocket::{Responder, State};
use std::collections::HashMap;
use std::fmt::Display;
use tabled::settings::Style;
use tabled::{Table, Tabled};
use thiserror::Error;

pub type Seed = [u8; 32];
pub type ServerKeyShare = CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare<
    Vec<Vec<u64>>,
    BoolParameters<u64>,
    NonInteractiveMultiPartyCrs<Seed>,
>;
pub type Cipher = SeededBatchedFheUint8<Vec<u64>, Seed>;
pub type DecryptionShare = Vec<u64>;
pub type ClientKey = phantom_zone::ClientKey;
pub type UserId = usize;
pub type FheUint8 = phantom_zone::FheUint8;

pub(crate) type MutexServerStatus = Mutex<ServerStatus>;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("Wrong server state: expect {expect} but got {got}")]
    WrongServerState { expect: String, got: String },
    #[error("User #{user_id} is unregistered")]
    UnregisteredUser { user_id: usize },
    #[error("The ciphertext from user #{user_id} not found")]
    CipherNotFound { user_id: UserId },
    #[error("Decryption share of {output_id} from user {user_id} not found")]
    DecryptionShareNotFound { output_id: usize, user_id: UserId },
    /// Temporary here
    #[error("Output not ready")]
    OutputNotReady,
}

#[derive(Responder)]
pub(crate) enum ErrorResponse {
    #[response(status = 500, content_type = "json")]
    ServerError(String),
    #[response(status = 404, content_type = "json")]
    NotFoundError(String),
}

impl From<Error> for ErrorResponse {
    fn from(error: Error) -> Self {
        match error {
            Error::WrongServerState { .. } | Error::CipherNotFound { .. } => {
                ErrorResponse::ServerError(error.to_string())
            }
            Error::DecryptionShareNotFound { .. }
            | Error::UnregisteredUser { .. }
            | Error::OutputNotReady => ErrorResponse::NotFoundError(error.to_string()),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ServerStatus {
    /// Users are allowed to join the computation
    ReadyForJoining,
    /// The number of user is determined now.
    /// We can now accept ciphertexts, which depends on the number of users.
    ReadyForInputs,
    ReadyForRunning,
    RunningFhe {
        blocking_task: tokio::task::JoinHandle<Vec<FheUint8>>,
    },
    CompletedFhe,
}

impl ServerStatus {
    pub(crate) fn ensure(&self, expect: Self) -> Result<&Self, Error> {
        if self.to_string() == expect.to_string() {
            Ok(self)
        } else {
            Err(Error::WrongServerState {
                expect: expect.to_string(),
                got: self.to_string(),
            })
        }
    }
    pub(crate) fn transit(&mut self, next: Self) {
        *self = next;
    }
}

impl Display for ServerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[[ {:?} ]]", self)
    }
}

pub(crate) type MutexServerStorage = Mutex<ServerStorage>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct ServerStorage {
    pub(crate) seed: Seed,
    pub(crate) users: Vec<UserStorage>,
    pub(crate) fhe_outputs: Vec<FheUint8>,
}

impl ServerStorage {
    pub(crate) fn new(seed: Seed) -> Self {
        Self {
            seed,
            users: vec![],
            fhe_outputs: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(crate = "rocket::serde")]
pub(crate) enum UserStorage {
    #[default]
    Empty,
    CipherSks(Cipher, Box<ServerKeyShare>),
    DecryptionShare(Option<Vec<DecryptionShare>>),
}

impl UserStorage {
    pub(crate) fn get_cipher_sks(&self) -> Option<(&Cipher, &ServerKeyShare)> {
        match self {
            Self::CipherSks(cipher, sks) => Some((cipher, sks)),
            _ => None,
        }
    }

    pub(crate) fn get_mut_decryption_shares(
        &mut self,
    ) -> Option<&mut Option<Vec<DecryptionShare>>> {
        match self {
            Self::DecryptionShare(ds) => Some(ds),
            _ => None,
        }
    }
}

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
    pub id: usize,
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

// We're going to store all of the messages here. No need for a DB.
pub(crate) type UserList = Mutex<Vec<RegisteredUser>>;
pub(crate) type Users<'r> = &'r State<UserList>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Dashboard {
    status: String,
    users: Vec<RegisteredUser>,
}
impl Dashboard {
    pub(crate) fn new(status: &ServerStatus, users: &[RegisteredUser]) -> Self {
        Self {
            status: status.to_string(),
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
        self.status == ServerStatus::ReadyForInputs.to_string()
    }

    pub fn print_presentation(&self) {
        println!("🤖🧠 {}", self.status);
        let users = Table::new(&self.users)
            .with(Style::ascii_rounded())
            .to_string();
        println!("{}", users);
    }
}

/// FheUint8 index -> user_id -> decryption share
pub type DecryptionSharesMap = HashMap<(usize, UserId), DecryptionShare>;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct CipherSubmission {
    pub(crate) user_id: UserId,
    pub(crate) cipher_text: Cipher,
    pub(crate) sks: ServerKeyShare,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct DecryptionShareSubmission {
    pub(crate) user_id: UserId,
    /// The user sends decryption share Vec<u64> for each FheUint8.
    pub(crate) decryption_shares: Vec<DecryptionShare>,
}
