use anyhow::{bail, Result};
use std::{fs, iter::zip};

use clap::command;
use itertools::Itertools;
use karma_calculator::{
    setup, Cipher, CipherSubmission, DecryptionShare, DecryptionShareSubmission, RegisteredUser,
    RegistrationOut, ServerKeyShare, User, TOTAL_USERS,
};
use rustyline::{error::ReadlineError, DefaultEditor};

use phantom_zone::{gen_client_key, gen_server_key_share, ClientKey, Encryptor, FheUint8};
use tokio;

use clap::{Parser, Subcommand};
use reqwest::{
    self,
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use toml;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    /// Acquire seeds and setup parameters
    Init {
        url: Option<String>,
    },
    Register {
        name: String,
    },
    Users,
    Rate {
        scores: Vec<u8>,
    },
    SubmitCipher,
    AcquireFheOutput,
    SubmitDecryptionShares,
    AcquireDecryptionShares,
    ComputePlainText,
    // Admin
    RunFhe,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli2 {
    /// Optional name to operate on
    name: String,
    url: String,
}

enum State {
    Init(StateInit),
    Setup(StateSetup),
    GotNames(StateGotNames),
    EncryptedInput(EncryptedInput),
    WaitRun,
    DownloadedOutput,
    PublishedShares,
    Decrypted,
}

struct StateInit {
    name: String,
    url: String,
}

struct StateSetup {
    name: String,
    url: String,
    ck: ClientKey,
    user_id: usize,
}

struct StateGotNames {
    name: String,
    url: String,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
}

struct EncryptedInput {
    name: String,
    url: String,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
    scores: [u8; 4],
    cipher: Cipher,
    sks: ServerKeyShare,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli2::parse();
    let name = cli.name;
    let url: String = cli.url;

    let mut rl = DefaultEditor::new().unwrap();
    let mut state = State::Init(StateInit { name, url });
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str()).unwrap();
                state = run(state, line.as_str()).await?;
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    Ok(())
}

async fn run(state: State, line: &str) -> Result<State> {
    let terms: Vec<&str> = line.split_whitespace().collect();
    if terms.len() == 0 {
        return Ok(state);
    }
    let cmd = &terms[0];
    let args = &terms[1..];
    if cmd == &"setup" {
        match state {
            State::Init(StateInit { name, url }) => {
                let seed: [u8; 32] = reqwest::get(format!("{url}/param")).await?.json().await?;
                println!("Acquired seed {:?}", seed);
                println!("Run setup");
                setup(&seed);
                println!("Gen client key");
                let ck = gen_client_key();
                let reg: RegistrationOut = Client::new()
                    .post(format!("{url}/register"))
                    .body(name.to_string())
                    .send()
                    .await?
                    .json()
                    .await?;
                println!(
                    "Hi {}, you are registered with ID: {}",
                    reg.name, reg.user_id
                );
                return Ok(State::Setup(StateSetup {
                    name,
                    url,
                    ck,
                    user_id: reg.user_id,
                }));
            }
            _ => bail!("Expected state Init"),
        }
    } else if cmd == &"getNames" {
        match state {
            State::Setup(StateSetup {
                name,
                url,
                ck,
                user_id,
            }) => {
                let users: Vec<RegisteredUser> =
                    reqwest::get(format!("{url}/users")).await?.json().await?;
                println!("Users {:?}", users);
                let names = users.iter().map(|reg| reg.name.clone()).collect_vec();
                return Ok(State::GotNames(StateGotNames {
                    name,
                    url,
                    ck,
                    user_id,
                    names,
                }));
            }
            _ => bail!("Expected StateSetup"),
        }
    } else if cmd == &"scoreEncrypt" {
        if args.len() != 3 {
            println!("Error: Invalid args: {:?}", args);
            return Ok(state);
        }
        match state {
            State::GotNames(StateGotNames {
                name,
                url,
                ck,
                user_id,
                names,
            }) => {
                let score: Result<Vec<u8>> = args
                    .iter()
                    .map(|s| {
                        s.parse::<u8>()
                            .map_err(|err| anyhow::format_err!(err.to_string()))
                    })
                    .collect_vec()
                    .into_iter()
                    .collect();
                let score = score?;
                let total = score[0..3].iter().sum();
                let scores: [u8; 4] = [score[0], score[1], score[2], total];
                for (name, score) in zip(&names, score[0..3].iter()) {
                    println!("Give {name} {score} karma");
                }
                println!("I gave out {total} karma");

                println!("Encrypting Inputs");
                let cipher = ck.encrypt(scores.as_slice());
                println!("Generating server key share");
                let sks = gen_server_key_share(user_id, TOTAL_USERS, &ck);

                println!("Submit the cipher and the server key share");
                let submission = CipherSubmission::new(user_id, cipher.clone(), sks.clone());
                Client::new()
                    .post(format!("{url}/submit"))
                    .headers({
                        let mut headers = HeaderMap::new();
                        headers.insert(
                            CONTENT_TYPE,
                            HeaderValue::from_static("application/msgpack"),
                        );
                        headers
                    })
                    .body(bincode::serialize(&submission).expect("serialization works"))
                    .send()
                    .await?
                    .json()
                    .await?;

                return Ok(State::EncryptedInput(EncryptedInput {
                    name,
                    url,
                    ck,
                    user_id,
                    names,
                    scores,
                    cipher,
                    sks,
                }));
            }
            _ => bail!("Expected StateGotNames"),
        }
    } else if cmd == &"run" {
    } else if cmd == &"downloadResult" {
    } else if cmd.starts_with("#") {
    } else {
        bail!("Unknown command {}", cmd);
    }
    Ok(state)
}

#[tokio::main]
async fn _main() -> Result<(), reqwest::Error> {
    // let base_url = "http://localhost:8000";

    let cli = Cli::parse();
    let mut me = User::new("");
    let dir = std::env::temp_dir();
    println!("Temporary directory: {}", dir.display());
    fs::write(dir, toml::to_string(&me).expect("serde works")).expect("save works");

    let mut root_url = String::from("http://127.0.0.1:5566");

    match &cli.commands {
        Commands::Init { url } => {
            if let Some(url) = url {
                root_url = url.to_string();
            }
            println!("Acquiring seed");
            let seed: [u8; 32] = reqwest::get(format!("{root_url}/param"))
                .await?
                .json()
                .await?;
            println!("Acquired seed {:?}", seed);
            println!("Run setup");
            setup(&seed);
            println!("Gen client key");
            me.gen_client_key();
        }
        Commands::Register { name } => {
            me.update_name(name);
            let reg: RegistrationOut = Client::new()
                .post(format!("{root_url}/register"))
                .body(name.to_string())
                .send()
                .await?
                .json()
                .await?;
            me.set_id(reg.user_id);
            println!(
                "Hi {}, you are registered with ID: {}",
                reg.name, reg.user_id
            );
        }
        Commands::Users => {
            let users: Vec<RegisteredUser> = reqwest::get(format!("{root_url}/users"))
                .await?
                .json()
                .await?;
            println!("Users {:?}", users);
        }
        Commands::Rate { scores } => {
            assert_eq!(scores.len(), 3);
            //TODO: handle all exceptions
            let total = scores.iter().sum();
            me.assign_scores(&[scores[0], scores[1], scores[2], total]);
            println!("Generating cipher");
            me.gen_cipher();
            println!("Generating server key share");
            me.gen_server_key_share();
        }
        Commands::SubmitCipher => {
            let submission = CipherSubmission::new(
                me.id.expect("id exists"),
                me.cipher.to_owned().expect("exists"),
                me.server_key.to_owned().expect("exists"),
            );
            Client::new()
                .post(format!("{root_url}/submit"))
                .headers({
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/msgpack"),
                    );
                    headers
                })
                .body(bincode::serialize(&submission).expect("serialization works"))
                .send()
                .await?
                .json()
                .await?;
        }
        Commands::AcquireFheOutput => {
            let fhe_output: Vec<FheUint8> = reqwest::get(format!("{root_url}/fhe_output"))
                .await?
                .json()
                .await?;
            println!("Saving FHE output");
            me.set_fhe_out(fhe_output);
            println!("Generate my decrypting shares");
            me.gen_decryption_shares();
        }
        Commands::SubmitDecryptionShares => {
            let decryption_shares = &me.get_my_shares();
            let submission =
                DecryptionShareSubmission::new(me.id.expect("exists"), decryption_shares);

            Client::new()
                .post(format!("{root_url}/submit_decryption_shares"))
                .headers({
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/msgpack"),
                    );
                    headers
                })
                .body(bincode::serialize(&submission).expect("serialization works"))
                .send()
                .await?;
        }
        Commands::AcquireDecryptionShares => {
            println!("Acquiring decryption shares needed");
            for (output_id, user_id) in (0..3).cartesian_product(0..3) {
                if me.decryption_shares.get(&(output_id, user_id)).is_none() {
                    println!("Acquiring user {user_id}'s decryption shares for output {output_id}");
                    let ds: DecryptionShare =
                        reqwest::get(format!("{root_url}/decryption_share/{output_id}/{user_id}"))
                            .await?
                            .json()
                            .await?;
                    me.decryption_shares.insert((output_id, user_id), ds);
                } else {
                    println!("Already have user {user_id}'s decryption shares for output {output_id}, skip.");
                }
            }
        }
        Commands::ComputePlainText => {
            println!("Decrypt the encrypted output");
            let final_output = me.decrypt_everything();
            println!("final output {:?}", final_output);
        }
        Commands::RunFhe => {
            Client::new().post(format!("{root_url}/run")).send().await?;
        }
    };
    Ok(())
}
