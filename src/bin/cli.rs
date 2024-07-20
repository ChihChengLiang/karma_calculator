use anyhow::{anyhow, bail, Error};
use std::{collections::HashMap, iter::zip};

use clap::command;
use itertools::Itertools;
use karma_calculator::{
    setup, Cipher, CipherSubmission, DecryptionShare, DecryptionShareSubmission,
    DecryptionSharesMap, RegisteredUser, RegistrationOut, ServerKeyShare, ServerResponse,
    TOTAL_USERS,
};
use rocket::serde::msgpack;
use rustyline::{error::ReadlineError, DefaultEditor};

use phantom_zone::{
    gen_client_key, gen_server_key_share, ClientKey, Encryptor, FheUint8, MultiPartyDecryptor,
};
use tokio;

use clap::Parser;
use reqwest::{
    self,
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};

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
    cipher: Cipher,
    sks: ServerKeyShare,
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
    shares: DecryptionSharesMap,
}

struct StatePublishedShares {
    name: String,
    url: String,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
    scores: [u8; 4],
    fhe_out: Vec<FheUint8>,
    shares: DecryptionSharesMap,
}

struct StateDecrypted {
    names: Vec<String>,
    fhe_out: Vec<FheUint8>,
    shares: DecryptionSharesMap,
    decrypted_output: Vec<u8>,
}

#[tokio::main]
async fn main() {
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
                state = match run(state, line.as_str()).await {
                    Ok(state) => state,
                    Err((err, state)) => {
                        println!("Error: {:?}", err);
                        state
                    }
                };
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
}

async fn cmd_setup(name: &String, url: &String) -> Result<(ClientKey, usize), Error> {
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
    Ok((ck, reg.user_id))
}

async fn cmd_get_names(url: &String) -> Result<Vec<String>, Error> {
    let users: Vec<RegisteredUser> = reqwest::get(format!("{url}/users")).await?.json().await?;
    println!("Users {:?}", users);
    let names = users.iter().map(|reg| reg.name.clone()).collect_vec();
    Ok(names)
}

async fn cmd_score_encrypt(
    args: &[&str],
    url: &String,
    user_id: &usize,
    names: &Vec<String>,
    ck: &ClientKey,
) -> Result<([u8; 4], Cipher, ServerKeyShare), Error> {
    let score: Result<Vec<u8>, Error> = args
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
    for (name, score) in zip(names, score[0..3].iter()) {
        println!("Give {name} {score} karma");
    }
    println!("I gave out {total} karma");

    println!("Encrypting Inputs");
    let cipher = ck.encrypt(scores.as_slice());
    println!("Generating server key share");
    let sks = gen_server_key_share(*user_id, TOTAL_USERS, ck);

    println!("Submit the cipher and the server key share");
    let submission = CipherSubmission::new(*user_id, cipher.clone(), sks.clone());
    let response: ServerResponse = Client::new()
        .post(format!("{url}/submit"))
        .headers({
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/msgpack"),
            );
            headers
        })
        .body(msgpack::to_compact_vec(&submission).expect("works"))
        .send()
        .await?
        .json()
        .await?;

    let scores = [0u8; 4];
    Ok((scores, cipher, sks))
}

async fn cmd_download_output(
    url: &String,
    user_id: &usize,
    ck: &ClientKey,
) -> Result<(Vec<FheUint8>, HashMap<(usize, usize), Vec<u64>>), Error> {
    println!("Downloading fhe output");
    let fhe_out: Vec<FheUint8> = reqwest::get(format!("{url}/fhe_output"))
        .await?
        .json()
        .await?;
    println!("Generating my decrypting shares");
    let mut shares = HashMap::new();
    let mut my_decryption_shares = Vec::new();
    for (out_id, out) in fhe_out.iter().enumerate() {
        let share = ck.gen_decryption_share(out);
        my_decryption_shares.push(share.clone());
        shares.insert((out_id, *user_id), share);
    }
    let submission = DecryptionShareSubmission::new(*user_id, &my_decryption_shares);

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
        .body(msgpack::to_compact_vec(&submission).expect("serialization works"))
        .send()
        .await?;

    Ok((fhe_out, shares))
}

async fn cmd_download_shares(
    url: &String,
    user_id: &usize,
    names: &Vec<String>,
    ck: &ClientKey,
    shares: &mut HashMap<(usize, usize), Vec<u64>>,
    fhe_out: &Vec<FheUint8>,
) -> Result<Vec<u8>, Error> {
    println!("Acquiring decryption shares needed");
    for (output_id, user_id) in (0..3).cartesian_product(0..3) {
        if shares.get(&(output_id, user_id)).is_none() {
            println!("Acquiring user {user_id}'s decryption shares for output {output_id}");
            let ds: DecryptionShare =
                reqwest::get(format!("{url}/decryption_share/{output_id}/{user_id}"))
                    .await?
                    .json()
                    .await?;
            shares.insert((output_id, user_id), ds);
        } else {
            println!(
                "Already have user {user_id}'s decryption shares for output {output_id}, skip."
            );
        }
    }
    println!("Decrypt the encrypted output");
    let decrypted_output = fhe_out
        .iter()
        .enumerate()
        .map(|(output_id, output)| {
            let decryption_shares = (0..TOTAL_USERS)
                .map(|user_id| {
                    shares
                        .get(&(output_id, user_id))
                        .expect("exists")
                        .to_owned()
                })
                .collect_vec();
            ck.aggregate_decryption_shares(output, &decryption_shares)
        })
        .collect_vec();
    println!("Final decrypted output:");
    for (name, output) in zip(names, &decrypted_output) {
        println!("\t{} has {} karma", name, output);
    }

    Ok(decrypted_output)
}

async fn run(state: State, line: &str) -> Result<State, (Error, State)> {
    let terms: Vec<&str> = line.split_whitespace().collect();
    if terms.len() == 0 {
        return Ok(state);
    }
    let cmd = &terms[0];
    let args = &terms[1..];
    if cmd == &"setup" {
        match state {
            State::Init(StateInit { name, url }) => match cmd_setup(&name, &url).await {
                Ok((ck, user_id)) => Ok(State::Setup(StateSetup {
                    name,
                    url,
                    ck,
                    user_id,
                })),
                Err(err) => Err((err, State::Init(StateInit { name, url }))),
            },
            _ => Err((anyhow!("Expected state Init"), state)),
        }
    } else if cmd == &"getNames" {
        match state {
            State::Setup(s) => match cmd_get_names(&s.url).await {
                Ok(names) => Ok(State::GotNames(StateGotNames {
                    name: s.name,
                    url: s.url,
                    ck: s.ck,
                    user_id: s.user_id,
                    names,
                })),
                Err(err) => Err((err, State::Setup(s))),
            },
            _ => Err((anyhow!("Expected state Setup"), state)),
        }
    } else if cmd == &"scoreEncrypt" {
        if args.len() != 3 {
            return Err((anyhow!("Invalid args: {:?}", args), state));
        }
        match state {
            State::GotNames(s) => {
                match cmd_score_encrypt(args, &s.url, &s.user_id, &s.names, &s.ck).await {
                    Ok((scores, cipher, sks)) => Ok(State::EncryptedInput(EncryptedInput {
                        name: s.name,
                        url: s.url,
                        ck: s.ck,
                        user_id: s.user_id,
                        names: s.names,
                        scores,
                        cipher,
                        sks,
                    })),
                    Err(err) => Err((err, State::GotNames(s))),
                }
            }
            _ => Err((anyhow!("Expected state GotNames"), state)),
        }
    } else if cmd == &"downloadOutput" {
        // - Download fhe output
        // - Generate my decryption key shares
        // - Upload my decryption key shares
        match state {
            State::WaitRun(s) => match cmd_download_output(&s.url, &s.user_id, &s.ck).await {
                Ok((fhe_out, shares)) => Ok(State::DownloadedOutput(StateDownloadedOuput {
                    name: s.name,
                    url: s.url,
                    ck: s.ck,
                    user_id: s.user_id,
                    names: s.names,
                    scores: s.scores,
                    fhe_out,
                    shares,
                })),
                Err(err) => Err((err, State::WaitRun(s))),
            },
            _ => Err((anyhow!("Expected state EncryptedInput"), state)),
        }
    } else if cmd == &"downloadShares" {
        // - Download others decryption key shares
        // - Decrypt fhe output
        match state {
            State::DownloadedOutput(mut s) => match cmd_download_shares(
                &s.url,
                &s.user_id,
                &s.names,
                &s.ck,
                &mut s.shares,
                &s.fhe_out,
            )
            .await
            {
                Ok(decrypted_output) => Ok(State::Decrypted(StateDecrypted {
                    names: s.names,
                    fhe_out: s.fhe_out,
                    shares: s.shares,
                    decrypted_output,
                })),
                Err(err) => Err((err, State::DownloadedOutput(s))),
            },
            _ => Err((anyhow!("Expected state DownloadedOuput"), state)),
        }
    } else if cmd.starts_with("#") {
        Ok(state)
    } else {
        Err((anyhow!("Unknown command {}", cmd), state))
    }
}
