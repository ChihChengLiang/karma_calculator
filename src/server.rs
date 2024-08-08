use crate::circuit::{derive_server_key, evaluate_circuit, PARAMETER};
use crate::dashboard::{Dashboard, RegisteredUser};
use crate::time;
use crate::types::{
    CircuitOutput, DecryptionShare, DecryptionShareSubmission, Error, ErrorResponse,
    InputSubmission, MutexServerStorage, Seed, ServerState, ServerStorage, UserId, UserStorage,
};
use itertools::Itertools;
use phantom_zone::{set_common_reference_seed, set_parameter_set};
use rand::{thread_rng, RngCore};
use rocket::serde::json::Json;
use rocket::serde::msgpack::MsgPack;
use rocket::{get, post, routes};
use rocket::{Build, Rocket, State};
use tokio::sync::Mutex;

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
    ss.ensure(ServerState::ReadyForJoining)?;
    let user = ss.add_user(name);
    println!("{name} just joined!");

    Ok(Json(user))
}

#[post("/conclude_registration")]
async fn conclude_registration(
    ss: &State<MutexServerStorage>,
) -> Result<Json<Dashboard>, ErrorResponse> {
    let mut ss = ss.lock().await;
    ss.ensure(ServerState::ReadyForJoining)?;
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
    submission: MsgPack<InputSubmission>,
    ss: &State<MutexServerStorage>,
) -> Result<Json<UserId>, ErrorResponse> {
    let mut ss = ss.lock().await;

    ss.ensure(ServerState::ReadyForInputs)?;

    let InputSubmission { user_id, ei, sks } = submission.0;

    let user = ss.get_user(user_id)?;
    println!("{} submited data", user.name);
    user.storage = UserStorage::CipherSks(ei, Box::new(sks));

    if ss.check_cipher_submission() {
        ss.transit(ServerState::ReadyForRunning);
    }

    Ok(Json(user_id))
}

/// The admin runs the fhe computation
#[post("/run")]
async fn run(ss: &State<MutexServerStorage>) -> Result<Json<ServerState>, ErrorResponse> {
    let s2 = (*ss).clone();
    let mut ss = ss.lock().await;

    match &ss.state {
        ServerState::ReadyForRunning => {
            let (server_key_shares, encrypted_inputs) = ss.get_ciphers_and_sks()?;

            tokio::task::spawn_blocking(move || {
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
                                println!("Begin FHE run");
                                // Long running, global variable change
                                derive_server_key(&server_key_shares);

                                // Unpack to get circuit inputs
                                let cis = encrypted_inputs
                                    .iter()
                                    .enumerate()
                                    .map(|(user_id, ei)| ei.unpack(user_id))
                                    .collect_vec();

                                // Long running
                                let output = time!(|| evaluate_circuit(&cis), "Evaluating Circuit");
                                let mut ss = s2.blocking_lock();
                                ss.fhe_outputs = Some(output);
                                ss.transit(ServerState::CompletedFhe);
                                println!("FHE computation completed");
                            })
                        },
                    )
                    .unwrap();
            });
            ss.transit(ServerState::RunningFhe);
            Ok(Json(ServerState::RunningFhe))
        }
        ServerState::RunningFhe => Ok(Json(ServerState::RunningFhe)),
        ServerState::CompletedFhe => Ok(Json(ServerState::CompletedFhe)),
        _ => Err(Error::WrongServerState {
            expect: ServerState::ReadyForRunning.to_string(),
            got: ss.state.to_string(),
        }
        .into()),
    }
}

#[get("/fhe_output")]
async fn get_fhe_output(
    ss: &State<MutexServerStorage>,
) -> Result<Json<CircuitOutput>, ErrorResponse> {
    let ss = ss.lock().await;
    ss.ensure(ServerState::CompletedFhe)?;
    let output = ss
        .fhe_outputs
        .clone()
        .expect("Should exist after CompletedFhe");
    Ok(Json(output))
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
