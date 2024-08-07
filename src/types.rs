use itertools::Itertools;
use phantom_zone::NonInteractiveSeededFheBools;
use phantom_zone::{
    evaluator::NonInteractiveMultiPartyCrs,
    keys::CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare, parameters::BoolParameters,
    Encryptor, FheBool, KeySwitchWithId, MultiPartyDecryptor, SampleExtractor,
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
/// number of users + total
pub type Score = PlainWord;
pub type Word = Vec<FheBool>;
/// Decryption share for a word from one user.
pub type DecryptionShare = Vec<u64>;
pub type ClientKey = phantom_zone::ClientKey;
pub type UserId = usize;

pub type PlainWord = u32;
type EncryptedWord = NonInteractiveSeededFheBools<Vec<u64>, Seed>;

/// Encrypted input words contributed from one user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInput {
    karma_sent: Vec<EncryptedWord>,
}

impl CircuitInput {
    pub fn from_plain(ck: &ClientKey, karma: &[PlainWord]) -> Self {
        let cipher = karma
            .iter()
            .map(|score| encrypt_plain(ck, *score))
            .collect_vec();
        Self { karma_sent: cipher }
    }

    /// Unpack ciphers
    ///
    /// 1. Decompression: A cipher is a matrix generated from a seed. The seed is sent through the network as a compression. By calling the `unseed` method we recovered the matrix here.
    /// 2. Key Switch: We reencrypt the cipher with the server key for the computation. We need to specify the original signer of the cipher.
    /// 3. Extract: A user's encrypted inputs are packed in a batched struct. We call `extract_all` method to convert it to unbatched word.
    pub(crate) fn unpack(&self, user_id: UserId) -> Vec<Word> {
        self.karma_sent
            .iter()
            .map(|word| {
                word.unseed::<Vec<Vec<u64>>>()
                    .key_switch(user_id)
                    .extract_all()
            })
            .collect_vec()
    }
}

fn encrypt_plain(ck: &ClientKey, plain: PlainWord) -> EncryptedWord {
    let plain = u64_to_binary::<32>(plain as u64);
    let cipher = ck.encrypt(plain.as_slice());
    return cipher;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitOutput {
    /// Computed karma balance of all users
    karma_balance: Vec<Word>,
}

impl CircuitOutput {
    pub(crate) fn new(karma_balance: Vec<Word>) -> Self {
        Self { karma_balance }
    }

    /// For each output word, a user generates its decryption share
    pub fn gen_decryption_shares(&self, ck: &ClientKey) -> Vec<DecryptionShare> {
        self.karma_balance
            .iter()
            .map(|word| gen_decryption_shares(ck, word))
            .collect_vec()
    }

    pub fn decrypt(&self, ck: &ClientKey, dss: &[Vec<DecryptionShare>]) -> Vec<PlainWord> {
        self.karma_balance
            .iter()
            .zip_eq(dss)
            .map(|(word, shares)| decrypt_word(ck, word, shares))
            .collect_vec()
    }

    /// Get number of outputs
    pub fn n(&self) -> usize {
        self.karma_balance.len()
    }
}

fn gen_decryption_shares(ck: &ClientKey, fhe_output: &Word) -> DecryptionShare {
    let dec_shares = fhe_output
        .iter()
        .map(|out_bit| ck.gen_decryption_share(out_bit))
        .collect_vec();
    dec_shares
}

fn decrypt_word(ck: &ClientKey, fhe_output: &Word, shares: &[DecryptionShare]) -> PlainWord {
    // A DecryptionShare is user i's contribution to word j.
    // To decrypt word j at bit position k. We need to extract the position k of user i's share.
    let decrypted_bits = fhe_output
        .iter()
        .enumerate()
        .map(|(bit_k, fhe_bit)| {
            let shares_for_bit_k = shares
                .iter()
                .map(|user_share| user_share[bit_k])
                .collect_vec();
            ck.aggregate_decryption_shares(fhe_bit, &shares_for_bit_k)
        })
        .collect_vec();
    recover(&decrypted_bits)
}

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
    pub(crate) fhe_outputs: Option<CircuitOutput>,
}

impl ServerStorage {
    pub(crate) fn new(seed: Seed) -> Self {
        Self {
            seed,
            state: ServerState::ReadyForJoining,
            users: vec![],
            fhe_outputs: None,
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
    ) -> Result<(Vec<ServerKeyShare>, Vec<CircuitInput>), Error> {
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
    CipherSks(CircuitInput, Box<ServerKeyShare>),
    DecryptionShare(Option<Vec<DecryptionShare>>),
}

impl UserStorage {
    pub(crate) fn get_cipher_sks(&self) -> Option<(&CircuitInput, &ServerKeyShare)> {
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
pub(crate) struct InputSubmission {
    pub(crate) user_id: UserId,
    pub(crate) ci: CircuitInput,
    pub(crate) sks: ServerKeyShare,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct DecryptionShareSubmission {
    pub(crate) user_id: UserId,
    /// The user sends decryption share Vec<u64> for each FheUint8.
    pub(crate) decryption_shares: Vec<DecryptionShare>,
}

pub fn u64_to_binary<const N: usize>(v: u64) -> [bool; N] {
    assert!((v as u128) < 2u128.pow(N as u32));
    let mut result = [false; N];
    for i in 0..N {
        if (v >> i) & 1 == 1 {
            result[i] = true;
        }
    }
    result
}

pub fn recover(bits: &[bool]) -> u32 {
    let mut out: u32 = 0;
    for (i, bit) in bits.iter().enumerate() {
        out &= (*bit as u32) << i;
    }
    out
}
