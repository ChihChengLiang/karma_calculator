use phantom_zone::{gen_client_key, gen_server_key_share, ClientKey, FheUint8};
use std::borrow::Cow;

use hex::{encode, ToHex};
use rocket::tokio::sync::Mutex;
use rocket::State;
use rocket::{get, launch, post, routes, FromForm};

use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};

// The type to represent the ID of a message.
type UserId = usize;
type ServerKeyShare = Vec<u8>;

// We're going to store all of the messages here. No need for a DB.
type UserList = Mutex<Vec<(String, ServerKeyShare)>>;
type Users<'r> = &'r State<UserList>;

struct User {
    id: Option<UserId>,
    total_users: Option<usize>,
    name: String,
    ck: ClientKey,
}

impl User {
    fn new(name: &str) -> Self {
        let ck = gen_client_key();
        Self {
            id: None,
            total_users: None,
            name: name.to_string(),
            ck,
        }
    }

    fn gen_server_key_share(&self) -> ServerKeyShare {
        let server_key =
            gen_server_key_share(self.id.unwrap(), self.total_users.unwrap(), &self.ck);
        bincode::serialize(&server_key).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct KeyRegistration<'r> {
    name: Cow<'r, str>,
    key: Cow<'r, ServerKeyShare>,
}

// #[derive(FromForm)]
// struct CipherSubmission {
//     cipher_text: FheUint8,
// }

#[get("/world")]
fn world() -> &'static str {
    "Hello, world!"
}

/// A user registers a key and get an ID
#[post("/register", data = "<reg>")]
async fn register(reg: Json<KeyRegistration<'_>>, users: Users<'_>) -> Value {
    let mut users = users.lock().await;
    let user_id = users.len();
    users.push((reg.name.to_string(), reg.key.to_vec()));
    json!({ "status": "ok", "user_id": user_id })
}

// /// The user submits the ciphertext
// #[post("/submit")]
// fn submit() -> &'static str {
//     "Hello, world!"
// }

// /// The admin runs the fhe computation
// #[post("/run")]
// fn submit() -> &'static str {
//     "Hello, world!"
// }

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/hello", routes![world])
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
