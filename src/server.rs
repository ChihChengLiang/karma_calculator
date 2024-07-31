use crate::circuit::{derive_server_key, evaluate_circuit};
use crate::types::{
    CipherSubmission, Dashboard, DecryptionShareSubmission, Error, ErrorResponse,
    MutexServerStatus, MutexServerStorage, RegisteredUser, ServerStatus, ServerStorage, UserList,
    UserStatus, UserStorage, Users,
};
use crate::{DecryptionShare, Seed, UserId};
use phantom_zone::{set_common_reference_seed, set_parameter_set, FheUint8, ParameterSelector};
use rand::{thread_rng, RngCore};
use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};
use tokio::task;

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
    ss: &State<MutexServerStorage>,
) -> Result<Json<RegisteredUser>, ErrorResponse> {
    let s = status.lock().await;
    s.ensure(ServerStatus::ReadyForJoining)?;
    let mut users = users.lock().await;
    let user_id = users.len();
    let user = RegisteredUser::new(user_id, name);
    users.push(user.clone());
    let mut ss = ss.lock().await;
    ss.users.push(UserStorage::Empty);
    Ok(Json(user))
}

#[post("/conclude_registration")]
async fn conclude_registration(
    users: Users<'_>,
    status: &State<MutexServerStatus>,
) -> Result<Json<Dashboard>, ErrorResponse> {
    let mut s = status.lock().await;
    s.ensure(ServerStatus::ReadyForJoining)?;
    s.transit(ServerStatus::ReadyForInputs);
    let users = users.lock().await;
    let dashboard = Dashboard::new(&s, &users);
    Ok(Json(dashboard))
}

#[get("/dashboard")]
async fn get_dashboard(users: Users<'_>, status: &State<MutexServerStatus>) -> Json<Dashboard> {
    let s = status.lock().await;
    let users = users.lock().await;
    let dashboard = Dashboard::new(&s, &users);
    Json(dashboard)
}

/// The user submits the ciphertext
#[post("/submit", data = "<submission>", format = "msgpack")]
async fn submit(
    submission: MsgPack<CipherSubmission>,
    users: Users<'_>,
    status: &State<MutexServerStatus>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<UserId>, ErrorResponse> {
    {
        status.lock().await.ensure(ServerStatus::ReadyForInputs)?;
    }

    let CipherSubmission {
        user_id,
        cipher_text,
        sks,
    } = submission.0;

    let mut users = users.lock().await;
    if users.len() <= user_id {
        return Err(Error::UnregisteredUser { user_id }.into());
    }
    let mut ss = ss.lock().await;
    println!("{} Submited data", users[user_id].name);
    ss.users[user_id] = UserStorage::CipherSks(cipher_text, Box::new(sks));
    users[user_id].status = UserStatus::CipherSubmitted;

    if users
        .iter()
        .all(|user| matches!(user.status, UserStatus::CipherSubmitted))
    {
        status.lock().await.transit(ServerStatus::ReadyForRunning);
    }

    Ok(Json(user_id))
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(
    users: Users<'_>,
    ss: &State<MutexServerStorage>,
    status: &State<MutexServerStatus>,
) -> Result<Json<String>, ErrorResponse> {
    {
        let mut s = status.lock().await;
        match *s {
            ServerStatus::ReadyForRunning => {
                s.transit(ServerStatus::RunningFhe);
            }
            ServerStatus::CompletedFhe => {
                return Ok(Json("FHE already complete".to_string()));
            }
            _ => {
                return Err(Error::WrongServerState {
                    expect: ServerStatus::ReadyForRunning,
                    got: s.clone(),
                }
                .into())
            }
        }
    }
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
            status.lock().await.transit(ServerStatus::ReadyForInputs);
            return Err(Error::CipherNotFound { user_id }.into());
        }
    }

    ss.fhe_outputs = task::spawn_blocking(move || {
        // Long running, global variable change
        derive_server_key(&server_key_shares);
        // Long running
        evaluate_circuit(&ciphers)
    })
    .await
    .map_err(|err| ErrorResponse::ServerError(err.to_string()))?;

    status.lock().await.transit(ServerStatus::CompletedFhe);

    Ok(Json("FHE complete".to_string()))
}

#[get("/fhe_output")]
async fn get_fhe_output(
    ss: &State<MutexServerStorage>,
    status: &State<MutexServerStatus>,
) -> Result<Json<Vec<FheUint8>>, ErrorResponse> {
    status.lock().await.ensure(ServerStatus::CompletedFhe)?;
    let fhe_outputs = &ss.lock().await.fhe_outputs;
    Ok(Json(fhe_outputs.to_vec()))
}

/// The user submits the ciphertext
#[post("/submit_decryption_shares", data = "<submission>", format = "msgpack")]
async fn submit_decryption_shares(
    submission: MsgPack<DecryptionShareSubmission>,
    ss: &State<MutexServerStorage>,
    users: Users<'_>,
) -> Result<Json<UserId>, ErrorResponse> {
    let user_id = submission.user_id;
    let mut ss = ss.lock().await;
    let decryption_shares = ss.users[user_id]
        .get_mut_decryption_shares()
        .ok_or(Error::OutputNotReady)?;
    *decryption_shares = Some(submission.decryption_shares.to_vec());

    let mut users = users.lock().await;

    users[user_id].status = UserStatus::DecryptionShareSubmitted;
    Ok(Json(user_id))
}

#[get("/decryption_share/<output_id>/<user_id>")]
async fn get_decryption_share(
    output_id: usize,
    user_id: UserId,
    ss: &State<MutexServerStorage>,
) -> Result<Json<DecryptionShare>, ErrorResponse> {
    let decryption_shares = ss.lock().await.users[user_id]
        .get_mut_decryption_shares()
        .cloned()
        .ok_or(Error::OutputNotReady)?
        .ok_or(Error::DecryptionShareNotFound { output_id, user_id })?;
    Ok(Json(decryption_shares[output_id].clone()))
}

pub fn setup(seed: &Seed) {
    set_parameter_set(ParameterSelector::NonInteractiveLTE8Party);
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
                get_dashboard,
                submit,
                run,
                get_fhe_output,
                submit_decryption_shares,
                get_decryption_share,
            ],
        )
}
