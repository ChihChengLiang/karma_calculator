use itertools::Itertools;
use phantom_zone::{
    evaluator::NonInteractiveMultiPartyCrs,
    keys::CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare, parameters::BoolParameters,
    SeededBatchedFheUint8,
};
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::Mutex;
use rocket::Responder;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use thiserror::Error;

use crate::dashboard::{Dashboard, RegisteredUser};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServerState {
    /// Users are allowed to join the computation
    ReadyForJoining,
    /// The number of user is determined now.
    /// We can now accept ciphertexts, which depends on the number of users.
    ReadyForInputs,
    ReadyForRunning,
    RunningFhe,
    CompletedFhe,
}

impl ServerState {
    fn ensure(&self, expect: Self) -> Result<&Self, Error> {
        if *self == expect {
            Ok(self)
        } else {
            Err(Error::WrongServerState {
                expect: expect.to_string(),
                got: self.to_string(),
            })
        }
    }
    fn transit(&mut self, next: Self) {
        *self = next;
    }
}

impl Display for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[[ {:?} ]]", self)
    }
}

pub(crate) type MutexServerStorage = Arc<Mutex<ServerStorage>>;

#[derive(Debug)]
pub(crate) struct ServerStorage {
    pub(crate) seed: Seed,
    pub(crate) state: ServerState,
    pub(crate) users: Vec<UserRecord>,
    pub(crate) fhe_outputs: Vec<FheUint8>,
}

impl ServerStorage {
    pub(crate) fn new(seed: Seed) -> Self {
        Self {
            seed,
            state: ServerState::ReadyForJoining,
            users: vec![],
            fhe_outputs: Default::default(),
        }
    }

    pub(crate) fn add_user(&mut self, name: &str) -> RegisteredUser {
        let user_id: usize = self.users.len();
        self.users.push(UserRecord {
            id: user_id,
            name: name.to_string(),
            storage: UserStorage::Empty,
        });
        RegisteredUser::new(user_id, name)
    }

    pub(crate) fn ensure(&self, state: ServerState) -> Result<(), Error> {
        self.state.ensure(state)?;
        Ok(())
    }

    pub(crate) fn transit(&mut self, state: ServerState) {
        self.state.transit(state)
    }

    pub(crate) fn get_user(&mut self, user_id: UserId) -> Result<&mut UserRecord, Error> {
        self.users
            .get_mut(user_id)
            .ok_or(Error::UnregisteredUser { user_id })
    }

    pub(crate) fn check_cipher_submission(&self) -> bool {
        self.users
            .iter()
            .all(|user| matches!(user.storage, UserStorage::CipherSks(..)))
    }

    pub(crate) fn get_ciphers_and_sks(
        &mut self,
    ) -> Result<(Vec<ServerKeyShare>, Vec<Cipher>), Error> {
        let mut server_key_shares = vec![];
        let mut ciphers = vec![];
        for (user_id, user) in self.users.iter_mut().enumerate() {
            if let Some((cipher, sks)) = user.storage.get_cipher_sks() {
                server_key_shares.push(sks.clone());
                ciphers.push(cipher.clone());
                user.storage = UserStorage::DecryptionShare(None);
            } else {
                return Err(Error::CipherNotFound { user_id });
            }
        }
        Ok((server_key_shares, ciphers))
    }

    pub(crate) fn get_dashboard(&self) -> Dashboard {
        Dashboard::new(&self.state, &self.users.iter().map_into().collect_vec())
    }
}

#[derive(Debug)]
pub(crate) struct UserRecord {
    pub(crate) id: UserId,
    pub(crate) name: String,
    pub(crate) storage: UserStorage,
}

#[derive(Debug, Clone)]
pub(crate) enum UserStorage {
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
