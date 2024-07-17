use itertools::Itertools;
use phantom_zone::{
    aggregate_server_key_shares, gen_client_key, gen_server_key_share, ClientKey, Encryptor,
};
use std::borrow::Cow;

use rocket::tokio::sync::Mutex;
use rocket::State;
use rocket::{get, launch, post, routes};

use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};

// The type to represent the ID of a message.
type UserId = usize;
type ServerKeyShare = Vec<u8>;
type Cipher = Vec<u8>;

struct RegisteredUser {
    name: String,
    sks: ServerKeyShare,
    cipher: Option<Cipher>,
}

// We're going to store all of the messages here. No need for a DB.
type UserList = Mutex<Vec<RegisteredUser>>;
type Users<'r> = &'r State<UserList>;

// TODO: how should the user get this value before everyone registered?
const TOTAL_USERS: usize = 3;

struct User {
    id: Option<UserId>,
    name: String,
    ck: ClientKey,
}

impl User {
    fn new(name: &str) -> Self {
        let ck = gen_client_key();
        Self {
            id: None,
            name: name.to_string(),
            ck,
        }
    }

    fn gen_server_key_share(&self) -> ServerKeyShare {
        let server_key = gen_server_key_share(self.id.unwrap(), TOTAL_USERS, &self.ck);
        bincode::serialize(&server_key).unwrap()
    }

    fn assign_scores(&self, scores: &[u8]) -> Cipher {
        let cipher = self.ck.encrypt(scores);
        bincode::serialize(&cipher).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct KeyRegistration<'r> {
    name: Cow<'r, str>,
    key: Cow<'r, ServerKeyShare>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct CipherSubmission<'r> {
    user_id: UserId,
    cipher_text: Cow<'r, Cipher>,
}

#[get("/world")]
fn world() -> &'static str {
    "Hello, world!"
}

/// A user registers a key and get an ID
#[post("/register", data = "<reg>")]
async fn register(reg: Json<KeyRegistration<'_>>, users: Users<'_>) -> Value {
    let mut users = users.lock().await;
    let user_id = users.len();
    let user = RegisteredUser {
        name: reg.name.to_string(),
        sks: reg.key.to_vec(),
        cipher: None,
    };
    users.push(user);
    json!({ "status": "ok", "user_id": user_id })
}

/// The user submits the ciphertext
#[post("/submit", data = "<cipher>")]
async fn submit(cipher: Json<CipherSubmission<'_>>, users: Users<'_>) -> Value {
    let mut users = users.lock().await;
    let user_id = cipher.user_id;
    if users.len() <= user_id {
        return json!({ "status": "fail", "reason": format!("{user_id} hasn't registered yet") });
    }
    users[user_id].cipher = Some(cipher.cipher_text.to_vec());
    json!({ "status": "ok", "user_id": user_id })
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(users: Users<'_>) -> Value {
    let users = users.lock().await;
    println!("checking if we have all user submissions");
    if users.len() < TOTAL_USERS {
        return json!( {"status": "fail", "reason":"some users haven't registered yet"});
    }
    for (user_id, user) in users.iter().enumerate() {
        if user.cipher.is_none() {
            return json!( {"status": "fail", "reason":format!("user {user_id} hasn't submit cipher yet")});
        }
    }

    println!("derive server key");

    let server_key_shares = users
        .iter()
        .map(|u| bincode::deserialize(&u.cipher.clone().unwrap()).unwrap())
        .collect_vec();

    let server_key = aggregate_server_key_shares(&server_key_shares);
    server_key.set_server_key();

    json!({ "status": "ok"})
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/hello", routes![world])
        .mount("/", routes![register, submit, run])
}

#[cfg(test)]
mod tests {
    use rocket::local::blocking::Client;

    #[test]
    fn hello() {
        let client = Client::tracked(super::rocket()).unwrap();
        let response = client.get("/hello/world").dispatch();
        assert_eq!(response.into_string(), Some("Hello, world!".into()));
    }
}
