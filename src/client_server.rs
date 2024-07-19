use itertools::Itertools;
use phantom_zone::evaluator::NonInteractiveMultiPartyCrs;
use phantom_zone::parameters::BoolParameters;
use phantom_zone::{
    aggregate_server_key_shares, gen_client_key, gen_server_key_share,
    keys::CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare, set_common_reference_seed,
    set_parameter_set, ClientKey, Encryptor, FheUint8, KeySwitchWithId, MultiPartyDecryptor,
    ParameterSelector, SampleExtractor, SeededBatchedFheUint8,
};
use rand::{thread_rng, RngCore};
use std::borrow::Cow;
use std::collections::HashMap;

use rocket::tokio::sync::Mutex;
use rocket::State;
use rocket::{get, launch, post, routes};

use rocket::serde::json::{json, Json, Value};
use rocket::serde::msgpack::MsgPack;
use rocket::serde::{Deserialize, Serialize};

// The type to represent the ID of a message.
type UserId = usize;
pub type ServerKeyShare = CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare<
    Vec<Vec<u64>>,
    BoolParameters<u64>,
    NonInteractiveMultiPartyCrs<[u8; 32]>,
>;
pub type Cipher = SeededBatchedFheUint8<Vec<u64>, [u8; 32]>;
pub type DecryptionShare = Vec<u64>;

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
type DecryptionSharesMap = HashMap<(usize, UserId), DecryptionShare>;

// TODO: how should the user get this value before everyone registered?
pub const TOTAL_USERS: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
// We're not sending the User struct in rockets. This macro is here just for Serde reasons
#[serde(crate = "rocket::serde")]
pub struct User {
    name: String,
    // step 0: get seed
    seed: Option<[u8; 32]>,
    // step 0.5: gen client key
    ck: Option<ClientKey>,
    // step 1: get userID
    pub id: Option<UserId>,
    // step 2: assign scores
    scores: Option<[u8; 4]>,
    // step 3: gen key and cipher
    pub server_key: Option<ServerKeyShare>,
    pub cipher: Option<Cipher>,
    // step 4: get FHE output
    fhe_out: Option<Vec<FheUint8>>,
    // step 5: derive decryption shares
    pub decryption_shares: DecryptionSharesMap,
}

impl User {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ck: None,
            id: None,
            seed: None,
            scores: None,
            server_key: None,
            cipher: None,
            fhe_out: None,
            decryption_shares: HashMap::new(),
        }
    }

    pub fn update_name(&mut self, name: &str) -> &mut Self {
        self.name = name.to_string();
        self
    }

    pub fn assign_seed(&mut self, seed: [u8; 32]) -> &mut Self {
        self.seed = Some(seed);
        self
    }

    pub fn set_seed(&self) {
        set_common_reference_seed(self.seed.unwrap());
    }

    pub fn gen_client_key(&mut self) -> &mut Self {
        self.ck = Some(gen_client_key());
        self
    }

    pub fn set_id(&mut self, id: usize) -> &mut Self {
        self.id = Some(id);
        self
    }
    pub fn assign_scores(&mut self, scores: &[u8; 4]) -> &mut Self {
        self.scores = Some(*scores);
        self
    }

    pub fn gen_cipher(&mut self) -> &mut Self {
        let scores = self.scores.unwrap().to_vec();
        let ck: &ClientKey = self.ck.as_ref().unwrap();
        let cipher: SeededBatchedFheUint8<Vec<u64>, [u8; 32]> = ck.encrypt(scores.as_slice());
        self.cipher = Some(cipher);
        self
    }

    pub fn gen_server_key_share(&mut self) -> &mut Self {
        let server_key =
            gen_server_key_share(self.id.unwrap(), TOTAL_USERS, self.ck.as_ref().unwrap());
        self.server_key = Some(server_key);
        self
    }

    pub fn set_fhe_out(&mut self, fhe_out: Vec<FheUint8>) -> &mut Self {
        self.fhe_out = Some(fhe_out);
        self
    }
    /// Populate decryption_shares with my shares
    pub fn gen_decryption_shares(&mut self) -> &mut Self {
        let ck = self.ck.as_ref().expect("already exists");
        let fhe_out = self.fhe_out.as_ref().expect("exists");
        let my_id = self.id.expect("exists");
        for (output_id, out) in fhe_out.iter().enumerate() {
            let my_decryption_share = ck.gen_decryption_share(out);
            self.decryption_shares
                .insert((output_id, my_id), my_decryption_share);
        }
        self
    }

    pub fn get_my_shares(&self) -> Vec<DecryptionShare> {
        let my_id = self.id.expect("exists");
        (0..3)
            .map(|output_id| {
                self.decryption_shares
                    .get(&(output_id, my_id))
                    .expect("exists")
                    .to_owned()
            })
            .collect_vec()
    }

    pub fn decrypt_everything(&self) -> Vec<u8> {
        let ck = self.ck.as_ref().expect("already exists");
        let fhe_out = self.fhe_out.as_ref().expect("exists");

        fhe_out
            .iter()
            .enumerate()
            .map(|(output_id, output)| {
                let decryption_shares = (0..TOTAL_USERS)
                    .map(|user_id| {
                        self.decryption_shares
                            .get(&(output_id, user_id))
                            .expect("exists")
                            .to_owned()
                    })
                    .collect_vec();
                ck.aggregate_decryption_shares(output, &decryption_shares)
            })
            .collect_vec()
    }
}

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

#[get("/world")]
fn world() -> &'static str {
    "Hello, world!"
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
) -> Value {
    let user_id = submission.0.user_id;

    let mut users = users.lock().await;
    if users.len() <= user_id {
        return json!({ "status": "fail", "reason": format!("{user_id} hasn't registered yet") });
    }
    let mut ss = ss.lock().await;
    ss.users[user_id] = UserStorage::CipherSks(submission.0.cipher_text, submission.0.sks);

    users[user_id].registration = Registration::CipherSubmitted;
    json!({ "status": "ok", "user_id": user_id })
}

fn sum_fhe(a: &FheUint8, b: &FheUint8, c: &FheUint8, total: &FheUint8) -> FheUint8 {
    &(&(a + b) + c) - total
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(users: Users<'_>, ss: &State<MutexServerStorage>) -> Value {
    let users = users.lock().await;
    println!("checking if we have all user submissions");
    if users.len() < TOTAL_USERS {
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
        .mount("/hello", routes![world])
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

#[cfg(test)]
mod tests {

    use super::*;
    use rocket::local::blocking::Client;

    #[test]
    fn hello() {
        let client = Client::tracked(super::rocket()).unwrap();
        let response = client.get("/hello/world").dispatch();
        assert_eq!(response.into_string(), Some("Hello, world!".into()));
    }

    #[test]
    fn full_flow() {
        let client = Client::tracked(super::rocket()).unwrap();

        let mut users = vec![User::new("Barry"), User::new("Justin"), User::new("Brian")];

        println!("acquire seeds");

        // Acquire seeds
        for user in users.iter_mut() {
            let seed = client
                .get("/param")
                .dispatch()
                .into_json::<[u8; 32]>()
                .expect("exists");
            user.assign_seed(seed);
            user.gen_client_key();
        }

        println!("register users");

        // Register
        for user in users.iter_mut() {
            let out = client
                .post("/register")
                .body(user.name.to_string())
                .dispatch()
                .into_json::<RegistrationOut>()
                .expect("exists");
            user.set_id(out.user_id);
        }

        let users_record = client
            .get("/users")
            .dispatch()
            .into_json::<Vec<RegisteredUser>>()
            .expect("exists");
        println!("users records {:?}", users_record);

        // Assign scores
        users[0].assign_scores(&[0, 2, 4, 6]);
        users[1].assign_scores(&[1, 0, 1, 2]);
        users[2].assign_scores(&[1, 1, 0, 2]);

        for user in users.iter_mut() {
            println!("{} gen cipher", user.name);
            user.gen_cipher();
            println!("{} gen key share", user.name);
            let now = std::time::Instant::now();
            user.gen_server_key_share();
            println!("It takes {:#?} to gen server key", now.elapsed());
            println!("{} submit key and cipher", user.name);

            let user_id = user.id.unwrap();

            let submission = CipherSubmission::new(
                user_id,
                user.cipher.to_owned().unwrap(),
                user.server_key.to_owned().unwrap(),
            );
            let now = std::time::Instant::now();
            client.post("/submit").msgpack(&submission).dispatch();
            println!("It takes {:#?} to submit server key", now.elapsed());
        }

        // Admin runs the FHE computation
        client.post("/run").dispatch();

        // Users get FHE output, generate decryption shares, and submit decryption shares
        for user in users.iter_mut() {
            let fhe_output = client
                .get("/fhe_output")
                .dispatch()
                .into_json::<Vec<FheUint8>>()
                .expect("exists");

            user.set_fhe_out(fhe_output);
            user.gen_decryption_shares();
            let decryption_shares = &user.get_my_shares();
            let submission =
                DecryptionShareSubmission::new(user.id.expect("exist now"), decryption_shares);

            client
                .post("/submit_decryption_shares")
                .msgpack(&submission)
                .dispatch();
        }
        // Users acquire all decryption shares they want
        for user in users.iter_mut() {
            for (output_id, user_id) in (0..3).cartesian_product(0..TOTAL_USERS) {
                if user.decryption_shares.get(&(output_id, user_id)).is_none() {
                    let ds = client
                        .get(format!("/decryption_share/{output_id}/{user_id}"))
                        .dispatch()
                        .into_json::<DecryptionShare>()
                        .expect("exists");
                    user.decryption_shares.insert((output_id, user_id), ds);
                }
            }
        }
        // Users decrypt everything
        println!("Users decrypt everything");
        for user in users {
            let decrypted_outs = user.decrypt_everything();
            println!("{} sees {:?}", user.name, decrypted_outs);
        }
    }
}
