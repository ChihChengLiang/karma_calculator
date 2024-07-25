use phantom_zone::{set_common_reference_seed, set_parameter_set, FheUint8, ParameterSelector};
use tabled::Tabled;

use crate::circuit::{derive_server_key, evaluate_circuit};
use crate::{Cipher, DecryptionShare, Seed, ServerKeyShare, UserId};
use rand::{thread_rng, RngCore};
use std::borrow::Cow;
use std::collections::HashMap;

use rocket::tokio::sync::Mutex;
use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};

use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::serde::{Deserialize, Serialize};

type MutexServerStatus = Mutex<ServerStatus>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ServerResponse {
    pub ok: bool,
    pub msg: String,
}

impl ServerResponse {
    fn ok(msg: &str) -> Self {
        Self {
            ok: true,
            msg: msg.to_string(),
        }
    }
    fn err(msg: &str) -> Self {
        Self {
            ok: false,
            msg: msg.to_string(),
        }
    }
    fn ok_user(user_id: UserId) -> Self {
        Self::ok(&format!("{user_id}"))
    }

    fn err_unregistered_user(user_id: UserId) -> Self {
        Self::err(&format!("User {user_id} hasn't registered yet"))
    }

    fn err_unregistered_users(user_len: usize) -> Self {
        Self::err(&format!(
            "Some users haven't registered yet. Want {TOTAL_USERS}  Got {user_len}"
        ))
    }
    fn err_run_in_progress() -> Self {
        Self::err("Fhe computation already running")
    }

    fn ok_run_already_end() -> Self {
        Self::ok("Fhe computation completed")
    }
    fn err_missing_submission(user_id: UserId) -> Self {
        Self::err(&format!("can't find cipher submission from user {user_id}"))
    }
    fn err_output_not_ready() -> Self {
        Self::err("FHE output not ready yet")
    }

    fn err_decryption_share_not_found(output_id: usize, user_id: UserId) -> Self {
        Self::err(&format!(
            "Decryption share of {output_id} from user {user_id} not found"
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
enum ServerStatus {
    Waiting,
    RunningFhe,
    CompletedFhe,
}

type MutexServerStorage = Mutex<ServerStorage>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct ServerStorage {
    seed: Seed,
    users: Vec<UserStorage>,
    fhe_outputs: Vec<FheUint8>,
}

impl ServerStorage {
    fn new(seed: Seed) -> Self {
        Self {
            seed,
            users: vec![UserStorage::Empty, UserStorage::Empty, UserStorage::Empty],
            fhe_outputs: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(crate = "rocket::serde")]
enum UserStorage {
    #[default]
    Empty,
    CipherSks(Cipher, ServerKeyShare),
    DecryptionShare(Option<Vec<DecryptionShare>>),
}

impl UserStorage {
    fn get_cipher_sks(&self) -> Option<(&Cipher, &ServerKeyShare)> {
        match self {
            Self::CipherSks(cipher, sks) => Some((cipher, sks)),
            _ => None,
        }
    }

    fn get_mut_decryption_shares(&mut self) -> Option<&mut Option<Vec<DecryptionShare>>> {
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
    id: usize,
    pub name: String,
    status: UserStatus,
}

// We're going to store all of the messages here. No need for a DB.
type UserList = Mutex<Vec<RegisteredUser>>;
type Users<'r> = &'r State<UserList>;

/// FheUint8 index -> user_id -> decryption share
pub type DecryptionSharesMap = HashMap<(usize, UserId), DecryptionShare>;

// TODO: how should the user get this value before everyone registered?
pub const TOTAL_USERS: usize = 3;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct CipherSubmission {
    user_id: UserId,
    cipher_text: Cipher,
    sks: ServerKeyShare,
}

impl CipherSubmission {
    pub fn new(user_id: usize, cipher_text: Cipher, sks: ServerKeyShare) -> Self {
        Self {
            user_id,
            cipher_text,
            sks,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct DecryptionShareSubmission<'r> {
    user_id: UserId,
    /// The user sends decryption share Vec<u64> for each FheUint8.
    decryption_shares: Cow<'r, Vec<DecryptionShare>>,
}
impl<'r> DecryptionShareSubmission<'r> {
    pub fn new(user_id: usize, decryption_shares: &'r Vec<DecryptionShare>) -> Self {
        Self {
            user_id,
            decryption_shares: Cow::Borrowed(decryption_shares),
        }
    }
}

#[get("/param")]
async fn get_param(ss: &State<MutexServerStorage>) -> Json<Seed> {
    let ss = ss.lock().await;
    Json(ss.seed)
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct RegistrationOut {
    pub name: String,
    pub user_id: usize,
}

/// A user registers a name and get an ID
#[post("/register", data = "<name>")]
async fn register(name: &str, users: Users<'_>) -> Json<RegistrationOut> {
    let mut users = users.lock().await;
    let user_id = users.len();
    let user = RegisteredUser {
        id: user_id,
        name: name.to_string(),
        status: UserStatus::IDAcquired,
    };
    users.push(user);
    Json(RegistrationOut {
        name: name.to_string(),
        user_id,
    })
}

#[get("/users")]
async fn get_users(users: Users<'_>) -> Json<Vec<RegisteredUser>> {
    let users = users.lock().await;
    Json(users.to_vec())
}

/// The user submits the ciphertext
#[post("/submit", data = "<submission>", format = "msgpack")]
async fn submit(
    submission: MsgPack<CipherSubmission>,
    users: Users<'_>,
    ss: &State<MutexServerStorage>,
) -> Json<ServerResponse> {
    let user_id = submission.0.user_id;

    let mut users = users.lock().await;
    if users.len() <= user_id {
        return Json(ServerResponse::err_unregistered_user(user_id));
    }
    let mut ss = ss.lock().await;
    ss.users[user_id] = UserStorage::CipherSks(submission.0.cipher_text, submission.0.sks);

    users[user_id].status = UserStatus::CipherSubmitted;
    Json(ServerResponse::ok_user(user_id))
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(
    users: Users<'_>,
    ss: &State<MutexServerStorage>,
    status: &State<MutexServerStatus>,
) -> Json<ServerResponse> {
    let mut s = status.lock().await;
    match *s {
        ServerStatus::Waiting => {
            *s = ServerStatus::RunningFhe;
        }
        ServerStatus::RunningFhe => {
            return Json(ServerResponse::err_run_in_progress());
        }
        ServerStatus::CompletedFhe => {
            return Json(ServerResponse::ok_run_already_end());
        }
    }
    drop(s);
    let users = users.lock().await;
    println!("checking if we have all user submissions");
    if users.len() < TOTAL_USERS {
        *status.lock().await = ServerStatus::Waiting;
        return Json(ServerResponse::err_unregistered_users(users.len()));
    }
    println!("load server keys and ciphers");
    let mut ss = ss.lock().await;

    let mut server_key_shares = vec![];
    let mut ciphers = vec![];
    for (user_id, user) in users.iter().enumerate() {
        if let Some((cipher, sks)) = ss.users[user_id].get_cipher_sks() {
            server_key_shares.push(sks.clone());
            ciphers.push((cipher.clone(), user.to_owned()));
            ss.users[user_id] = UserStorage::DecryptionShare(None);
        } else {
            *status.lock().await = ServerStatus::Waiting;
            return Json(ServerResponse::err_missing_submission(user_id));
        }
    }
    // Long running, global variable change
    derive_server_key(&server_key_shares);

    // Long running
    ss.fhe_outputs = evaluate_circuit(&ciphers);

    *status.lock().await = ServerStatus::CompletedFhe;

    Json(ServerResponse::ok("FHE complete"))
}

#[get("/fhe_output")]
async fn get_fhe_output(
    ss: &State<MutexServerStorage>,
) -> Result<Json<Vec<FheUint8>>, Json<ServerResponse>> {
    let ss: tokio::sync::MutexGuard<ServerStorage> = ss.lock().await;
    if ss.fhe_outputs.is_empty() {
        Err(Json(ServerResponse::err_output_not_ready()))
    } else {
        Ok(Json(ss.fhe_outputs.clone()))
    }
}

/// The user submits the ciphertext
#[post("/submit_decryption_shares", data = "<submission>", format = "msgpack")]
async fn submit_decryption_shares(
    submission: MsgPack<DecryptionShareSubmission<'_>>,
    ss: &State<MutexServerStorage>,
    users: Users<'_>,
) -> Json<ServerResponse> {
    let user_id = submission.user_id;
    let mut ss = ss.lock().await;
    let decryption_shares = match ss.users[user_id].get_mut_decryption_shares() {
        Some(ds) => ds,
        None => return Json(ServerResponse::err_output_not_ready()),
    };
    *decryption_shares = Some(submission.decryption_shares.to_vec());

    let mut users = users.lock().await;

    users[user_id].status = UserStatus::DecryptionShareSubmitted;
    Json(ServerResponse::ok_user(user_id))
}

#[get("/decryption_share/<fhe_output_id>/<user_id>")]
async fn get_decryption_share(
    fhe_output_id: usize,
    user_id: UserId,
    ss: &State<MutexServerStorage>,
) -> Result<Json<DecryptionShare>, Json<ServerResponse>> {
    let mut ss = ss.lock().await;
    match ss.users[user_id].get_mut_decryption_shares() {
        None => Err(Json(ServerResponse::err_output_not_ready())),
        Some(decryption_shares_option) => match decryption_shares_option {
            Some(decryption_shares) => Ok(Json(decryption_shares[fhe_output_id].clone())),
            None => Err(Json(ServerResponse::err_decryption_share_not_found(
                fhe_output_id,
                user_id,
            ))),
        },
    }
}

pub fn setup(seed: &Seed) {
    set_parameter_set(ParameterSelector::NonInteractiveLTE4Party);
    set_common_reference_seed(*seed);
}

pub fn rocket() -> Rocket<Build> {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);

    setup(&seed);

    rocket::build()
        .manage(UserList::new(vec![]))
        .manage(MutexServerStorage::new(ServerStorage::new(seed)))
        .manage(MutexServerStatus::new(ServerStatus::Waiting))
        .mount(
            "/",
            routes![
                get_param,
                register,
                get_users,
                submit,
                run,
                get_fhe_output,
                submit_decryption_shares,
                get_decryption_share,
            ],
        )
}