use anyhow::{bail, Result};
use std::fs;

use clap::command;
use itertools::Itertools;
use karma_calculator::{
    setup, CipherSubmission, DecryptionShare, DecryptionShareSubmission, RegisteredUser,
    RegistrationOut, User,
};
use rustyline::{error::ReadlineError, DefaultEditor};

use phantom_zone::{gen_client_key, ClientKey, FheUint8, MultiPartyDecryptor};
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
    WaitRun(StateWaitRun),
    DownloadedOutput(StateDownloadedOuput),
    PublishedShares(StatePublishedShares),
    Decrypted(StateDecrypted),
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
}

struct StateWaitRun {
    name: String,
    url: String,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
    scores: [u8; 4],
}

struct StateDownloadedOuput {
    name: String,
    url: String,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
    scores: [u8; 4],
    fhe_out: Vec<FheUint8>,
}

struct StatePublishedShares {
    name: String,
    url: String,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
    scores: [u8; 4],
    fhe_out: Vec<FheUint8>,
    shares: (),
}

struct StateDecrypted {
    out: (),
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
                let users: Vec<RegisteredUser> =
                    reqwest::get(format!("{url}/users")).await?.json().await?;
                println!("Users {:?}", users);
                let names = users.iter().map(|reg| reg.name.clone()).collect_vec();

                let scores = [0u8; 4];
                return Ok(State::EncryptedInput(EncryptedInput {
                    name,
                    url,
                    ck,
                    user_id,
                    names,
                    scores: todo!(),
                }));
            }
            _ => bail!("Expected StateGotNames"),
        }
    } else if cmd == &"downloadOutput" {
        // - Download fhe output
        // - Generate my decryption key shares
        // - Upload my decryption key shares
        match state {
            State::WaitRun(StateWaitRun {
                name,
                url,
                ck,
                user_id,
                names,
                scores,
            }) => {
                println!("Downloading fhe output");
                let fhe_out: Vec<FheUint8> = reqwest::get(format!("{url}/fhe_output"))
                    .await?
                    .json()
                    .await?;
                println!("Generating my decrypting shares");
                let mut my_decryption_shares = Vec::new();
                for out in fhe_out.iter() {
                    my_decryption_shares.push(ck.gen_decryption_share(out));
                }

                let submission = DecryptionShareSubmission::new(user_id, &my_decryption_shares);

                println!("Submitting my decrypting shares");
                Client::new()
                    .post(format!("{url}/submit_decryption_shares"))
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

                return Ok(State::DownloadedOutput(StateDownloadedOuput {
                    name,
                    url,
                    ck,
                    user_id,
                    names,
                    scores: todo!(),
                    fhe_out,
                }));
            }
            _ => bail!("Expected StateEncryptedInput"),
        }
    } else if cmd == &"downloadShares" {
        // - Download others decryption key shares
        // - Decrypt fhe output
        match state {
            State::DownloadedOutput(StateDownloadedOuput {
                name,
                url,
                ck,
                user_id,
                names,
                scores,
                fhe_out,
            }) => {
                println!("Acquiring decryption shares needed");
                // TODO
                // for (output_id, user_id) in (0..3).cartesian_product(0..3) {
                //     if me.decryption_shares.get(&(output_id, user_id)).is_none() {
                //         println!(
                //             "Acquiring user {user_id}'s decryption shares for output {output_id}"
                //         );
                //         let ds: DecryptionShare = reqwest::get(format!(
                //             "{root_url}/decryption_share/{output_id}/{user_id}"
                //         ))
                //         .await?
                //         .json()
                //         .await?;
                //         me.decryption_shares.insert((output_id, user_id), ds);
                //     } else {
                //         println!("Already have user {user_id}'s decryption shares for output {output_id}, skip.");
                //     }
                // }
                return Ok(State::Decrypted(StateDecrypted { out: todo!() }));
            }
            _ => bail!("Expected StateDownloadedOuput"),
        }
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
