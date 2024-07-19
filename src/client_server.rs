use itertools::Itertools;
use phantom_zone::{
    aggregate_server_key_shares, set_common_reference_seed, set_parameter_set, FheUint8,
    KeySwitchWithId, ParameterSelector, SampleExtractor,
};

use crate::{Cipher, DecryptionShare, ServerKeyShare, UserId};
use rand::{thread_rng, RngCore};
use std::borrow::Cow;
use std::collections::HashMap;

use rocket::tokio::sync::Mutex;
use rocket::State;
use rocket::{get, launch, post, routes};

use rocket::serde::json::{json, Json, Value};
use rocket::serde::msgpack::MsgPack;
use rocket::serde::{Deserialize, Serialize};

type MutexServerStatus = Mutex<ServerStatus>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ServerResponse {
    pub ok: bool,
    pub msg: String,
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
    seed: [u8; 32],
    users: Vec<UserStorage>,
    fhe_outputs: Vec<FheUint8>,
}

impl ServerStorage {
    fn new(seed: [u8; 32]) -> Self {
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
enum Registration {
    IDAcquired,
    CipherSubmitted,
    DecryptionShareSubmitted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct RegisteredUser {
    pub name: String,
    registration: Registration,
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
async fn get_param(ss: &State<MutexServerStorage>) -> Json<[u8; 32]> {
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
        name: name.to_string(),
        registration: Registration::IDAcquired,
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
        return Json(ServerResponse {
            ok: false,
            msg: format!("{user_id} hasn't registered yet"),
        });
    }
    let mut ss = ss.lock().await;
    ss.users[user_id] = UserStorage::CipherSks(submission.0.cipher_text, submission.0.sks);

    users[user_id].registration = Registration::CipherSubmitted;
    Json(ServerResponse {
        ok: true,
        msg: format!("{user_id}"),
    })
}

fn sum_fhe(a: &FheUint8, b: &FheUint8, c: &FheUint8, total: &FheUint8) -> FheUint8 {
    &(&(a + b) + c) - total
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(
    users: Users<'_>,
    ss: &State<MutexServerStorage>,
    status: &State<MutexServerStatus>,
) -> Value {
    let mut s = status.lock().await;
    match *s {
        ServerStatus::Waiting => {
            *s = ServerStatus::RunningFhe;
        }
        ServerStatus::RunningFhe => {
            return json!( {"status": "fail", "reason": "Fhe computation already running"});
        }
        ServerStatus::CompletedFhe => {
            return json!( {"status": "ok", "reason": "Fhe computation completed"});
        }
    }
    drop(s);
    let users = users.lock().await;
    println!("checking if we have all user submissions");
    if users.len() < TOTAL_USERS {
        *status.lock().await = ServerStatus::Waiting;
        return json!( {"status": "fail", "reason":"some users haven't registered yet"});
    }
    println!("load server keys and ciphers");
    let mut ss = ss.lock().await;

    let mut server_key_shares = vec![];
    let mut ciphers = vec![];
    for (user_id, _user) in users.iter().enumerate() {
        if let Some((cipher, sks)) = ss.users[user_id].get_cipher_sks() {
            server_key_shares.push(sks.clone());
            ciphers.push(cipher.clone());
            ss.users[user_id] = UserStorage::DecryptionShare(None);
        } else {
            *status.lock().await = ServerStatus::Waiting;
            return json!( {"status": "fail", "reason":format!("can't find cipher submission from user {user_id}")});
        }
    }

    println!("aggregate server key shares");
    let now = std::time::Instant::now();
    let server_key = aggregate_server_key_shares(server_key_shares.as_slice());
    println!("server key aggregation time: {:?}", now.elapsed());
    println!("set server key");
    server_key.set_server_key();

    println!("collect serialized cipher texts");

    let encs = ciphers
        .iter()
        .map(|c| c.unseed::<Vec<Vec<u64>>>())
        .collect_vec();
    let mut outs = vec![];
    for (my_id, me) in users.iter().enumerate() {
        println!("Compute {}'s karma", me.name);
        let my_scores_from_others = &encs
            .iter()
            .enumerate()
            .map(|(other_id, enc)| enc.key_switch(other_id).extract_at(my_id))
            .collect_vec();

        let total = encs[my_id].key_switch(my_id).extract_at(3);

        let now = std::time::Instant::now();
        let ct_out = sum_fhe(
            &my_scores_from_others[0],
            &my_scores_from_others[1],
            &my_scores_from_others[2],
            &total,
        );
        println!("sum_fhe evaluation time: {:?}", now.elapsed());
        outs.push(ct_out)
    }
    ss.fhe_outputs = outs;

    *status.lock().await = ServerStatus::CompletedFhe;

    json!({ "status": "ok"})
}

#[get("/fhe_output")]
async fn get_fhe_output(ss: &State<MutexServerStorage>) -> Result<Json<Vec<FheUint8>>, Value> {
    let ss: tokio::sync::MutexGuard<ServerStorage> = ss.lock().await;

    if ss.fhe_outputs.is_empty() {
        Err(json!({"status": "fail", "reason":"output not ready yet"}))
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
) -> Value {
    let user_id = submission.user_id;
    let mut ss = ss.lock().await;
    let decryption_shares = match ss.users[user_id].get_mut_decryption_shares() {
        Some(ds) => ds,
        None => return json!({"status": "fail", "reason":"The FHE computations has not been run"}),
    };
    *decryption_shares = Some(submission.decryption_shares.to_vec());

    let mut users = users.lock().await;

    users[user_id].registration = Registration::DecryptionShareSubmitted;
    json!({ "status": "ok", "user_id": user_id })
}

#[get("/decryption_share/<fhe_output_id>/<user_id>")]
async fn get_decryption_share(
    fhe_output_id: usize,
    user_id: UserId,
    ss: &State<MutexServerStorage>,
) -> Result<Json<DecryptionShare>, Value> {
    let mut ss = ss.lock().await;
    match ss.users[user_id].get_mut_decryption_shares() {
        None => Err(json!({"status": "fail", "reason":"The FHE computations has not been run"})),

        Some(decryption_shares_option) => match decryption_shares_option {
            Some(decryption_shares) => Ok(Json(decryption_shares[fhe_output_id].clone())),
            None => Err(
                json!({"stats": "fail", "reason": format!("find no decryption shares for output {} and user {}", fhe_output_id, user_id)}),
            ),
        },
    }
}

pub fn setup(seed: &[u8; 32]) {
    set_parameter_set(ParameterSelector::NonInteractiveLTE4Party);
    set_common_reference_seed(*seed);
}

#[launch]
pub fn rocket() -> _ {
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
