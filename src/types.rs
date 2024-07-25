use phantom_zone::{
    evaluator::NonInteractiveMultiPartyCrs,
    keys::CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare, parameters::BoolParameters,
    SeededBatchedFheUint8,
};
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::Mutex;
use rocket::State;
use std::collections::HashMap;
use tabled::Tabled;

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

pub type MutexServerStatus = Mutex<ServerStatus>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ServerResponse {
    pub ok: bool,
    pub msg: String,
}

impl ServerResponse {
    pub(crate) fn ok(msg: &str) -> Self {
        Self {
            ok: true,
            msg: msg.to_string(),
        }
    }
    pub(crate) fn err(msg: &str) -> Self {
        Self {
            ok: false,
            msg: msg.to_string(),
        }
    }
    pub(crate) fn ok_user(user_id: UserId) -> Self {
        Self::ok(&format!("{user_id}"))
    }

    pub(crate) fn err_unregistered_user(user_id: UserId) -> Self {
        Self::err(&format!("User {user_id} hasn't registered yet"))
    }

    pub(crate) fn err_unregistered_users(user_len: usize) -> Self {
        Self::err(&format!(
            "Some users haven't registered yet. Want {TOTAL_USERS}  Got {user_len}"
        ))
    }

    pub(crate) fn err_already_concluded(status: &ServerStatus) -> Self {
        Self::err(&format!(
            "Registration already concluded, status: {:?}",
            status
        ))
    }

    pub(crate) fn err_not_ready_for_run(status: &ServerStatus) -> Self {
        Self::err(&format!("Not ready for computation, status: {:?}", status))
    }
    pub(crate) fn err_run_in_progress() -> Self {
        Self::err("Fhe computation already running")
    }

    pub(crate) fn ok_run_already_end() -> Self {
        Self::ok("Fhe computation completed")
    }
    pub(crate) fn err_missing_submission(user_id: UserId) -> Self {
        Self::err(&format!("can't find cipher submission from user {user_id}"))
    }
    pub(crate) fn err_output_not_ready() -> Self {
        Self::err("FHE output not ready yet")
    }

    pub(crate) fn err_decryption_share_not_found(output_id: usize, user_id: UserId) -> Self {
        Self::err(&format!(
            "Decryption share of {output_id} from user {user_id} not found"
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub enum ServerStatus {
    /// Users are allowed to join the computation
    ReadyForJoining,
    /// The number of user is determined now.
    /// We can now accept ciphertexts, which depends on the number of users.
    ReadyForInputs,
    ReadyForRunning,
    RunningFhe,
    CompletedFhe,
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
    CipherSks(Cipher, ServerKeyShare),
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

/// FheUint8 index -> user_id -> decryption share
pub type DecryptionSharesMap = HashMap<(usize, UserId), DecryptionShare>;

// TODO: how should the user get this value before everyone registered?
pub const TOTAL_USERS: usize = 3;

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
