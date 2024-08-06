use std::ops::DerefMut;

use crate::circuit::{derive_server_key, evaluate_circuit, PARAMETER};
use crate::types::{
    CipherSubmission, Dashboard, DecryptionShareSubmission, Error, ErrorResponse,
    MutexServerStatus, MutexServerStorage, RegisteredUser, ServerStatus, ServerStorage, UserList,
    UserStatus, UserStorage, Users,
};
use crate::{time, DecryptionShare, Seed, UserId};
use phantom_zone::{set_common_reference_seed, set_parameter_set, FheUint8};
use rand::{thread_rng, RngCore};
use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};

#[get("/param")]
async fn get_param(ss: &State<MutexServerStorage>) -> Json<Seed> {
    let ss = ss.lock().await;
    Json(ss.seed)
}

/// A user registers a name and get an ID
#[post("/register", data = "<name>")]
async fn register(
    name: &str,
    ss: &State<MutexServerStorage>,
) -> Result<Json<RegisteredUser>, ErrorResponse> {
    let mut ss = ss.lock().await;
    ss.status.ensure(ServerStatus::ReadyForJoining)?;
    let user_id = ss.users.len();
    let user = RegisteredUser::new(user_id, name);
    ss.users.push(UserStorage::Empty);
    Ok(Json(user))
}

#[post("/conclude_registration")]
async fn conclude_registration(
    ss: &State<MutexServerStorage>,
) -> Result<Json<Dashboard>, ErrorResponse> {
    let mut ss = ss.lock().await;
    ss.status.ensure(ServerStatus::ReadyForJoining)?;
    ss.status.transit(ServerStatus::ReadyForInputs);
    let dashboard = ss.get_dashboard();
    Ok(Json(dashboard))
}

#[get("/dashboard")]
async fn get_dashboard(ss: &State<MutexServerStorage>) -> Json<Dashboard> {
    let dashboard = ss.lock().await.get_dashboard();
    Json(dashboard)
}

/// The user submits the ciphertext
#[post("/submit", data = "<submission>", format = "msgpack")]
async fn submit(
    submission: MsgPack<CipherSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<UserId>, ErrorResponse> {
    let ss = ss.lock().await;

    ss.status.ensure(ServerStatus::ReadyForInputs)?;

    let CipherSubmission {
        user_id,
        cipher_text,
        sks,
    } = submission.0;

    let users = ss.users;
    if users.len() <= user_id {
        return Err(Error::UnregisteredUser { user_id }.into());
    }
    println!("{} submited data", users[user_id].name);
    users[user_id] = UserStorage::CipherSks(cipher_text, Box::new(sks));

    if users
        .iter()
        .all(|user| matches!(user, UserStorage::CipherSks(..)))
    {
        ss.status.transit(ServerStatus::ReadyForRunning);
    }

    Ok(Json(user_id))
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(ss: &State<MutexServerStorage>) -> Result<Json<String>, ErrorResponse> {
    let mut ss = ss.lock().await;
    let s = ss.status;
    let users = &ss.users;
    // let prev_s = std::mem::replace(s.deref_mut(), ServerStatus::ReadyForJoining);
    match s {
        ServerStatus::ReadyForRunning => {
            println!("Checking if we have all user submissions");
            let mut server_key_shares = vec![];
            let mut ciphers = vec![];
            for (user_id, user) in ss.users.iter_mut().enumerate() {
                if let Some((cipher, sks)) = user.get_cipher_sks() {
                    server_key_shares.push(sks.clone());
                    ciphers.push(cipher.clone());
                    *user = UserStorage::DecryptionShare(None);
                } else {
                    s.transit(ServerStatus::ReadyForInputs);
                    return Err(Error::CipherNotFound { user_id }.into());
                }
            }
            println!("We have all submissions!");
            let blocking_task = tokio::task::spawn_blocking(move || {
                rayon::ThreadPoolBuilder::new()
                    .build_scoped(
                        // Initialize thread-local storage parameters
                        |thread| {
                            set_parameter_set(PARAMETER);
                            thread.run()
                        },
                        // Run parallel code under this pool
                        |pool| {
                            pool.install(|| {
                                // Long running, global variable change
                                derive_server_key(&server_key_shares);
                                // Long running
                                time!(|| evaluate_circuit(&ciphers), "Evaluating Circuit")
                            })
                        },
                    )
                    .unwrap()
            });
            s.transit(ServerStatus::RunningFhe { blocking_task });
            Ok(Json("Awesome".to_string()))
        }
        ServerStatus::RunningFhe { blocking_task } => {
            if blocking_task.is_finished() {
                ss.status.transit(ServerStatus::CompletedFhe);
                ss.fhe_outputs = blocking_task.await.unwrap();

                println!("FHE computation completed");
                Ok(Json("FHE complete".to_string()))
            } else {
                s.transit(ServerStatus::RunningFhe { blocking_task });
                Ok(Json("FHE is still running".to_string()))
            }
        }
        ServerStatus::CompletedFhe => {
            s.transit(prev_s);
            Ok(Json("FHE already complete".to_string()))
        }
        _ => {
            s.transit(prev_s);
            Err(Error::WrongServerState {
                expect: ServerStatus::ReadyForRunning.to_string(),
                got: s.to_string(),
            }
            .into())
        }
    }
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
) -> Result<Json<UserId>, ErrorResponse> {
    let user_id = submission.user_id;
    let mut ss = ss.lock().await;
    let decryption_shares = ss.users[user_id]
        .get_mut_decryption_shares()
        .ok_or(Error::OutputNotReady)?;
    *decryption_shares = Some(submission.decryption_shares.to_vec());


    users[user_id].status = UserStatus::DecryptionShareSubmitted;
    Ok(Json(user_id))
}

#[get("/decryption_share/<fhe_output_id>/<user_id>")]
async fn get_decryption_share(
    fhe_output_id: usize,
    user_id: UserId,
    ss: &State<MutexServerStorage>,
) -> Result<Json<DecryptionShare>, ErrorResponse> {
    let mut ss: tokio::sync::MutexGuard<ServerStorage> = ss.lock().await;
    let decryption_shares = ss.users[user_id]
        .get_mut_decryption_shares()
        .cloned()
        .ok_or(Error::OutputNotReady)?
        .ok_or(Error::DecryptionShareNotFound {
            output_id: fhe_output_id,
            user_id,
        })?;
    Ok(Json(decryption_shares[fhe_output_id].clone()))
}

pub fn setup(seed: &Seed) {
    set_parameter_set(PARAMETER);
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
