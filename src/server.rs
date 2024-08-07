use std::ops::Deref;
use std::sync::Arc;

use crate::circuit::{derive_server_key, evaluate_circuit, PARAMETER};
use crate::dashboard::{Dashboard, RegisteredUser};
use crate::types::{
    CipherSubmission, DecryptionShareSubmission, Error, ErrorResponse, MutexServerStorage,
    ServerState, ServerStateView, ServerStorage, UserStorage,
};
use crate::{time, DecryptionShare, Seed, UserId};
use phantom_zone::{set_common_reference_seed, set_parameter_set, FheUint8};
use rand::{thread_rng, RngCore};
use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};
use tokio::sync::{oneshot, Mutex};

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
    ss.ensure(ServerStateView::ReadyForJoining)?;
    let user = ss.add_user(name);
    println!("{name} just joined!");

    Ok(Json(user))
}

#[post("/conclude_registration")]
async fn conclude_registration(
    ss: &State<MutexServerStorage>,
) -> Result<Json<Dashboard>, ErrorResponse> {
    let mut ss = ss.lock().await;
    ss.ensure(ServerStateView::ReadyForJoining)?;
    ss.transit(ServerState::ReadyForInputs);
    println!("Registration closed!");
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
    let mut ss = ss.lock().await;

    ss.ensure(ServerStateView::ReadyForInputs)?;

    let CipherSubmission {
        user_id,
        cipher_text,
        sks,
    } = submission.0;

    let user = ss.get_user(user_id)?;
    println!("{} submited data", user.name);
    user.storage = UserStorage::CipherSks(cipher_text, Box::new(sks));

    if ss.check_cipher_submission() {
        ss.transit(ServerState::ReadyForRunning);
    }

    Ok(Json(user_id))
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(ss: &State<MutexServerStorage>) -> Result<Json<ServerStateView>, ErrorResponse> {
    let s2 = (*ss).clone();
    let mut ss = ss.lock().await;

    match &mut ss.state {
        ServerState::ReadyForRunning => {
            println!("Checking if we have all user submissions");
            let (server_key_shares, ciphers) = ss.get_ciphers_and_sks()?;
            println!("We have all submissions!");

            tokio::task::spawn_blocking(move || async move {
                let (tx, rx) = oneshot::channel::<Vec<FheUint8>>();
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
                                let output =
                                    time!(|| evaluate_circuit(&ciphers), "Evaluating Circuit");

                                tx.send(output).unwrap();
                            })
                        },
                    )
                    .unwrap();
                let output = rx.await.unwrap();
                let mut ss = s2.lock().await;
                ss.fhe_outputs = output;
                ss.transit(ServerState::CompletedFhe);
                println!("FHE computation completed");
            });
            ss.transit(ServerState::RunningFhe);
            Ok(Json(ServerStateView::RunningFhe))
        }
        ServerState::RunningFhe => {
            Ok(Json(ServerStateView::RunningFhe))
        }
        // ServerState::RunningFhe { rx } => match rx.try_recv() {
        //     Ok(output) => {
        //         ss.fhe_outputs = output;
        //         ss.transit(ServerState::CompletedFhe);
        //         println!("FHE computation completed");
        //         Ok(Json(ServerStateView::CompletedFhe))
        //     }
        //     Err(oneshot::error::TryRecvError::Empty) => Ok(Json(ServerStateView::RunningFhe)),
        //     Err(err) => Err(Error::ChannelError(err.to_string()).into()),
        // },
        ServerState::CompletedFhe => Ok(Json(ServerStateView::CompletedFhe)),
        _ => Err(Error::WrongServerState {
            expect: ServerStateView::ReadyForRunning.to_string(),
            got: ServerStateView::from(&ss.state).to_string(),
        }
        .into()),
    }
}

#[get("/fhe_output")]
async fn get_fhe_output(
    ss: &State<MutexServerStorage>,
) -> Result<Json<Vec<FheUint8>>, ErrorResponse> {
    let ss = ss.lock().await;
    ss.ensure(ServerStateView::CompletedFhe)?;
    Ok(Json(ss.fhe_outputs.to_vec()))
}

/// The user submits the ciphertext
#[post("/submit_decryption_shares", data = "<submission>", format = "msgpack")]
async fn submit_decryption_shares(
    submission: MsgPack<DecryptionShareSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<UserId>, ErrorResponse> {
    let user_id = submission.user_id;
    let mut ss = ss.lock().await;
    let decryption_shares = ss
        .get_user(user_id)?
        .storage
        .get_mut_decryption_shares()
        .ok_or(Error::OutputNotReady)?;
    *decryption_shares = Some(submission.decryption_shares.to_vec());
    Ok(Json(user_id))
}

#[get("/decryption_share/<fhe_output_id>/<user_id>")]
async fn get_decryption_share(
    fhe_output_id: usize,
    user_id: UserId,
    ss: &State<MutexServerStorage>,
) -> Result<Json<DecryptionShare>, ErrorResponse> {
    let mut ss: tokio::sync::MutexGuard<ServerStorage> = ss.lock().await;
    let decryption_shares = ss
        .get_user(user_id)?
        .storage
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
        .manage(MutexServerStorage::new(Mutex::new(ServerStorage::new(
            seed,
        ))))
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
