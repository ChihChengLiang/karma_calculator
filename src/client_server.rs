use itertools::Itertools;
use phantom_zone::{
    aggregate_server_key_shares, gen_client_key, gen_server_key_share, set_common_reference_seed,
    set_parameter_set, ClientKey, Encryptor, FheUint8, KeySwitchWithId, MultiPartyDecryptor,
    ParameterSelector, SampleExtractor, SeededBatchedFheUint8,
};
use rand::{thread_rng, RngCore};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::ops::Deref;

use rocket::tokio::sync::Mutex;
use rocket::State;
use rocket::{get, launch, post, routes};

use rocket::serde::json::{json, Json, Value};
use rocket::serde::msgpack::MsgPack;
use rocket::serde::{Deserialize, Serialize};

// The type to represent the ID of a message.
type UserId = usize;
type ServerKeyShare = Vec<u8>;
type Cipher = Vec<u8>;
type DecryptionShare = Vec<u64>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
enum Registration {
    IDAcquired,
    CipherSubmitted,
    DecryptionShareSubmitted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct RegisteredUser {
    name: String,
    registration: Registration,
}

// We're going to store all of the messages here. No need for a DB.
type UserList = Mutex<Vec<RegisteredUser>>;
type Users<'r> = &'r State<UserList>;

enum FHEOutput {
    NotReady,
    Ready(Vec<FheUint8>),
}

impl FHEOutput {
    fn ready(&mut self, outs: &[FheUint8]) {
        *self = Self::Ready(outs.to_vec())
    }
}

type MutexFHEOutput = Mutex<FHEOutput>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct Parameters {
    seed: [u8; 32],
}

impl Parameters {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

/// FheUint8 index -> user_id -> decryption share
type DecryptionSharesMap = HashMap<(usize, UserId), DecryptionShare>;
type MutexDecryptionSharesMap = Mutex<DecryptionSharesMap>;

// TODO: how should the user get this value before everyone registered?
const TOTAL_USERS: usize = 3;

struct User {
    name: String,
    // step 0: get seed
    seed: Option<[u8; 32]>,
    // step 0.5: gen client key
    ck: Option<ClientKey>,
    // step 1: get userID
    id: Option<UserId>,
    // step 2: assign scores
    scores: Option<[u8; 4]>,
    // step 3: gen key and cipher
    server_key: Option<ServerKeyShare>,
    cipher: Option<Cipher>,
    // step 4: get FHE output
    fhe_out: Option<Vec<FheUint8>>,
    // step 5: derive decryption shares
    decryption_shares: DecryptionSharesMap,
}

impl User {
    fn new(name: &str) -> Self {
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

    fn assign_seed(&mut self, seed: [u8; 32]) -> &mut Self {
        self.seed = Some(seed);
        self
    }

    fn set_seed(&self) {
        set_common_reference_seed(self.seed.unwrap());
    }

    fn gen_client_key(&mut self) -> &mut Self {
        self.ck = Some(gen_client_key());
        self
    }

    fn set_id(&mut self, id: usize) -> &mut Self {
        self.id = Some(id);
        self
    }
    fn assign_scores(&mut self, scores: &[u8; 4]) -> &mut Self {
        self.scores = Some(scores.clone());
        self
    }

    fn gen_cipher(&mut self) -> &mut Self {
        let scores = self.scores.unwrap().to_vec();
        let ck: &ClientKey = self.ck.as_ref().unwrap();
        let cipher = ck.encrypt(scores.as_slice());
        let cipher = bincode::serialize(&cipher).unwrap();
        // typically 16440. 17 KB
        println!("cipher size {}", cipher.len());
        self.cipher = Some(cipher);
        self
    }

    fn gen_server_key_share(&mut self) -> &mut Self {
        let server_key =
            gen_server_key_share(self.id.unwrap(), TOTAL_USERS, self.ck.as_ref().unwrap());
        let server_key = bincode::serialize(&server_key).unwrap();
        // typically 226383808. 226 MB
        println!("server_key size {}", server_key.len());
        self.server_key = Some(server_key);
        self
    }

    fn set_fhe_out(&mut self, fhe_out: Vec<FheUint8>) -> &mut Self {
        self.fhe_out = Some(fhe_out);
        self
    }
    /// Populate decryption_shares with my shares
    fn gen_decryption_shares(&mut self) -> &mut Self {
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

    fn get_my_shares(&self) -> Vec<DecryptionShare> {
        let my_id = self.id.expect("exists");
        println!(" self.decryption_shares {:?}", self.decryption_shares);
        (0..3)
            .map(|output_id| {
                self.decryption_shares
                    .get(&(output_id, my_id))
                    .expect("exists")
                    .to_owned()
            })
            .collect_vec()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct CipherSubmission<'r> {
    user_id: UserId,
    cipher_text: Cow<'r, Cipher>,
    sks: Cow<'r, ServerKeyShare>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct DecryptionShareSubmission<'r> {
    user_id: UserId,
    /// The user sends decryption share Vec<u64> for each FheUint8.
    decryption_shares: Cow<'r, Vec<Vec<u64>>>,
}

#[get("/world")]
fn world() -> &'static str {
    "Hello, world!"
}

#[get("/param")]
fn get_param(param: &State<Parameters>) -> Json<[u8; 32]> {
    Json(param.seed)
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct RegistrationOut {
    name: String,
    user_id: usize,
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
async fn submit(submission: MsgPack<CipherSubmission<'_>>, users: Users<'_>) -> Value {
    let user_id = submission.user_id;
    let data_path = std::env::temp_dir().join(format!("user_{user_id}.dat"));
    fs::write(
        data_path,
        bincode::serialize(&submission.0).expect("serialize success"),
    )
    .expect("sucess");

    let mut users = users.lock().await;

    if users.len() <= user_id {
        return json!({ "status": "fail", "reason": format!("{user_id} hasn't registered yet") });
    }
    users[user_id].registration = Registration::CipherSubmitted;
    json!({ "status": "ok", "user_id": user_id })
}

fn sum_fhe(a: &FheUint8, b: &FheUint8, c: &FheUint8, total: &FheUint8) -> FheUint8 {
    &(&(a + b) + c) - total
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(users: Users<'_>, fhe_output: &'_ State<MutexFHEOutput>) -> Value {
    let users = users.lock().await;
    println!("checking if we have all user submissions");
    if users.len() < TOTAL_USERS {
        return json!( {"status": "fail", "reason":"some users haven't registered yet"});
    }
    println!("load server keys and ciphers");

    let mut submissions = vec![];
    for (user_id, _user) in users.iter().enumerate() {
        let data_path = std::env::temp_dir().join(format!("user_{user_id}.dat"));
        if let Ok(data) = fs::read(data_path) {
            let submission: CipherSubmission =
                bincode::deserialize(&data).expect("deserialize success");
            submissions.push(submission);
        } else {
            return json!( {"status": "fail", "reason":format!("can't find cipher submission from user {user_id}")});
        }
    }

    println!("collect serialized server keys");

    let server_key_shares = &submissions
        .iter()
        .map(|s| bincode::deserialize(&s.sks).unwrap())
        .collect_vec();
    println!("aggregate server key shares");
    let now = std::time::Instant::now();
    let server_key = aggregate_server_key_shares(server_key_shares);
    println!("server key aggregation time: {:?}", now.elapsed());
    println!("set server key");
    server_key.set_server_key();

    println!("collect serialized cipher texts");
    let cipher_texts: &Vec<SeededBatchedFheUint8<_, _>> = &submissions
        .iter()
        .map(|s| bincode::deserialize(&s.cipher_text).unwrap())
        .collect_vec();

    let encs = &cipher_texts
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
    fhe_output.lock().await.ready(&outs);

    json!({ "status": "ok"})
}

#[get("/fhe_output")]
async fn get_fhe_output(
    fhe_output: &'_ State<MutexFHEOutput>,
) -> Result<Json<Vec<FheUint8>>, Value> {
    let fhe_output = fhe_output.lock().await;
    match fhe_output.deref() {
        FHEOutput::NotReady => Err(json!({"status": "fail", "reason":"output not ready yet"})),
        FHEOutput::Ready(output) => Ok(Json(output.to_vec())),
    }
}

/// The user submits the ciphertext
#[post("/submit_decryption_shares", data = "<submission>", format = "msgpack")]
async fn submit_decryption_shares(
    submission: MsgPack<DecryptionShareSubmission<'_>>,
    decryption_shares: &'_ State<MutexDecryptionSharesMap>,
    users: Users<'_>,
) -> Value {
    let user_id = submission.user_id;
    let mut decryption_shares = decryption_shares.lock().await;
    for (output_id, ds) in submission.decryption_shares.iter().enumerate() {
        decryption_shares.insert((output_id, user_id), ds.to_vec());
    }

    let mut users = users.lock().await;

    users[user_id].registration = Registration::DecryptionShareSubmitted;
    json!({ "status": "ok", "user_id": user_id })
}

#[get("/decryption_share/<fhe_output_id>/<user_id>")]
async fn get_decryption_share(
    fhe_output_id: usize,
    user_id: UserId,
    decryption_shares: &'_ State<MutexDecryptionSharesMap>,
) -> Result<Json<DecryptionShare>, Value> {
    let decryption_shares = decryption_shares.lock().await;
    match decryption_shares.deref().get(&(fhe_output_id, user_id)) {
        None => Err(
            json!({"stats": "fail", "reason": format!("find no decryption shares for output {} and user {}", fhe_output_id, user_id)}),
        ),
        Some(share) => Ok(Json(share.to_vec())),
    }
}

#[launch]
fn rocket() -> _ {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);

    set_parameter_set(ParameterSelector::NonInteractiveLTE4Party);
    set_common_reference_seed(seed);

    rocket::build()
        .manage(UserList::new(vec![]))
        .manage(Parameters::new(seed))
        .manage(MutexFHEOutput::new(FHEOutput::NotReady))
        .manage(MutexDecryptionSharesMap::new(HashMap::new()))
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
    use std::iter::zip;

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

            let submission = CipherSubmission {
                user_id,
                cipher_text: Cow::Borrowed(user.cipher.as_ref().unwrap()),
                sks: Cow::Borrowed(&user.server_key.as_ref().unwrap()),
            };
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
            let submission = DecryptionShareSubmission {
                user_id: user.id.expect("exist now"),
                decryption_shares: Cow::Borrowed(decryption_shares),
            };
            client
                .post("/submit_decryption_shares")
                .msgpack(&submission)
                .dispatch();
        }
        // Users acquire all decryption shares they want
        for user in users.iter_mut() {
            for (output_id, user_id) in zip(0..3, 0..TOTAL_USERS) {
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
    }
}
