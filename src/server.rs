use phantom_zone::{set_common_reference_seed, set_parameter_set, FheUint8, ParameterSelector};

use crate::circuit::{derive_server_key, evaluate_circuit};
use crate::types::{
    CipherSubmission, DecryptionShareSubmission, MutexServerStatus, MutexServerStorage,
    RegisteredUser, ServerResponse, ServerStatus, ServerStorage, UserList, UserStatus, UserStorage,
    Users,
};
use crate::{DecryptionShare, Seed, UserId, TOTAL_USERS};
use rand::{thread_rng, RngCore};

use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};

use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;

#[get("/param")]
async fn get_param(ss: &State<MutexServerStorage>) -> Json<Seed> {
    let ss = ss.lock().await;
    Json(ss.seed)
}

/// A user registers a name and get an ID
#[post("/register", data = "<name>")]
async fn register(
    name: &str,
    users: Users<'_>,
    status: &State<MutexServerStatus>,
) -> Result<Json<RegisteredUser>, Json<ServerResponse>> {
    let s = status.lock().await;
    if !matches!(*s, ServerStatus::ReadyForJoining) {
        return Err(Json(ServerResponse::err_already_concluded(&s)));
    }
    let mut users = users.lock().await;
    let user_id = users.len();
    let user = RegisteredUser::new(user_id, name);
    users.push(user.clone());
    Ok(Json(user))
}

#[post("/conclude_registration")]
async fn conclude_registration(
    users: Users<'_>,
    status: &State<MutexServerStatus>,
) -> Result<Json<Vec<RegisteredUser>>, Json<ServerResponse>> {
    let mut s = status.lock().await;
    match *s {
        ServerStatus::ReadyForJoining => *s = ServerStatus::ReadyForInputs,
        _ => {
            return Err(Json(ServerResponse::err_already_concluded(&s)));
        }
    };
    let users = users.lock().await;
    Ok(Json(users.to_vec()))
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
    status: &State<MutexServerStatus>,
    ss: &State<MutexServerStorage>,
) -> Json<ServerResponse> {
    match *s {
        ServerStatus::ReadyForJoining => *s = ServerStatus::ReadyForInputs,
        ServerStatus::ReadyForInputs => todo!(),
        ServerStatus::ReadyForRunning => todo!(),
        ServerStatus::RunningFhe => todo!(),
        ServerStatus::CompletedFhe => todo!(),
    };

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
        ServerStatus::ReadyForJoining | ServerStatus::ReadyForInputs => {
            return Json(ServerResponse::err_not_ready_for_run(&s));
        }
        ServerStatus::ReadyForRunning => {
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
    let mut ss = ss.lock().await;

    let mut server_key_shares = vec![];
    let mut ciphers = vec![];
    for (user_id, user) in users.iter().enumerate() {
        if let Some((cipher, sks)) = ss.users[user_id].get_cipher_sks() {
            server_key_shares.push(sks.clone());
            ciphers.push((cipher.clone(), user.to_owned()));
            ss.users[user_id] = UserStorage::DecryptionShare(None);
        } else {
            *status.lock().await = ServerStatus::ReadyForRunning;
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
    submission: MsgPack<DecryptionShareSubmission>,
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
        .manage(MutexServerStatus::new(ServerStatus::ReadyForJoining))
        .mount(
            "/",
            routes![
                get_param,
                register,
                conclude_registration,
                get_users,
                submit,
                run,
                get_fhe_output,
                submit_decryption_shares,
                get_decryption_share,
            ],
        )
}
