use anyhow::{anyhow, bail, ensure, Error};
use std::{collections::HashMap, fmt::Display, iter::zip};
use tabled::{settings::Style, Table, Tabled};

use clap::command;
use itertools::Itertools;
use karma_calculator::{
    setup, CircuitInput, CircuitOutput, DecryptionSharesMap, Score, ServerState, WebClient,
};

use rustyline::{error::ReadlineError, DefaultEditor};

use phantom_zone::{gen_client_key, gen_server_key_share, ClientKey};

use clap::Parser;

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
    ConcludedRegistration(ConcludedRegistration),
    EncryptedInput(EncryptedInput),
    TriggeredRun(StateTriggeredRun),
    DownloadedOutput(StateDownloadedOuput),
    Decrypted(StateDecrypted),
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            State::Init(_) => "Initialization",
            State::Setup(_) => "Setup",
            State::ConcludedRegistration(_) => "Concluded Registration",
            State::EncryptedInput(_) => "Encrypted Input",
            State::TriggeredRun(_) => "Triggered Run",
            State::DownloadedOutput(_) => "Downloaded Output",
            State::Decrypted(_) => "Decrypted",
        };
        write!(f, "{{{{ {} }}}}", label)
    }
}

impl State {
    fn print_status_update(&self) {
        let msg = match self {
            State::Init(StateInit { name, client }) => {
                format!("Hi {}, we just connected to server {}.", name, client.url())
            }
            State::Setup(StateSetup { .. }) => "✅ Setup completed!".to_string(),
            State::ConcludedRegistration(_) => "✅ Users' names acquired!".to_string(),
            State::EncryptedInput(_) => "✅ Ciphertext submitted!".to_string(),
            State::TriggeredRun(_) => "✅ FHE run triggered!".to_string(),
            State::DownloadedOutput(_) => "✅ FHE output downloaded!".to_string(),
            State::Decrypted(_) => "✅ FHE output decrypted!".to_string(),
        };
        println!("{}", msg)
    }

    fn print_instruction(&self) {
        let msg = match self {
            State::Setup(_) => "Enter `conclude` to end registration or `next` to proceed",
            State::ConcludedRegistration(ConcludedRegistration { names, .. }) => {
                let total_users = names.len();
                &format!(
                    "Enter `next` with scores for each user to continue. Example: `next {}`",
                    (0..total_users)
                        .map(|n| n.to_string())
                        .collect::<Vec<String>>()
                        .join(" ")
                )
            }
            State::Decrypted(_) => "Exit with `CTRL-D`",
            _ => "Enter `next` to continue",
        };
        println!("👇 {}", msg)
    }
}

struct StateInit {
    name: String,
    client: WebClient,
}

struct StateSetup {
    name: String,
    client: WebClient,
    ck: ClientKey,
    user_id: usize,
}

struct ConcludedRegistration {
    name: String,
    client: WebClient,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
}

struct EncryptedInput {
    name: String,
    client: WebClient,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
    scores: Vec<Score>,
}

struct StateTriggeredRun {
    name: String,
    client: WebClient,
    ck: ClientKey,
    user_id: usize,
    names: Vec<String>,
    scores: Vec<Score>,
}

struct StateDownloadedOuput {
    #[allow(dead_code)]
    name: String,
    client: WebClient,
    ck: ClientKey,
    names: Vec<String>,
    scores: Vec<Score>,
    fhe_out: CircuitOutput,
    shares: DecryptionSharesMap,
}

struct StateDecrypted {
    names: Vec<String>,
    client: WebClient,
    scores: Vec<Score>,
    decrypted_output: Vec<Score>,
}

#[tokio::main]
async fn main() {
    let cli = Cli2::parse();
    let name = cli.name;
    let url: String = cli.url;

    let mut rl = DefaultEditor::new().unwrap();
    let client = WebClient::new(&url);
    let mut state = State::Init(StateInit { name, client });
    println!("{}", state);
    state.print_status_update();
    state.print_instruction();
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str()).unwrap();
                state = match run(state, line.as_str()).await {
                    Ok(state) => {
                        println!("{}", state);
                        state.print_status_update();
                        state
                    }
                    Err((err, state)) => {
                        println!("❌ Error: {:?}", err);
                        println!("Fallback to {}", state);
                        state
                    }
                };
                state.print_instruction();
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

async fn cmd_setup(name: &str, client: &WebClient) -> Result<(ClientKey, usize), Error> {
    let seed = client.get_seed().await?;
    println!(
        "Acquired seed for commen reference string (CRS) 0x{}",
        hex::encode(seed)
    );
    println!("Setup my CRS");
    setup(&seed);
    println!("Generate my client key");
    let ck = gen_client_key();
    let user = client.register(name).await?;
    println!("Hi {}, you are registered with ID: {}", user.name, user.id);
    Ok((ck, user.id))
}

async fn cmd_get_names(client: &WebClient) -> Result<(bool, Vec<String>), Error> {
    let d = client.get_dashboard().await?;
    d.print_presentation();
    Ok((d.is_concluded(), d.get_names()))
}

async fn cmd_conclude_registration(client: &WebClient) -> Result<Vec<String>, Error> {
    let dashboard = client.conclude_registration().await?;
    Ok(dashboard.get_names())
}

async fn cmd_score_encrypt(
    args: &[&str],
    client: &WebClient,
    user_id: &usize,
    names: &Vec<String>,
    ck: &ClientKey,
) -> Result<Vec<Score>, Error> {
    let total_users = names.len();
    let scores: Result<Vec<_>, Error> = args
        .iter()
        .map(|s| {
            s.parse::<Score>()
                .map_err(|err| anyhow::format_err!(err.to_string()))
        })
        .collect_vec()
        .into_iter()
        .collect();
    let scores = scores?;
    ensure!(
        scores.len() == total_users,
        "Mismatch scores and user number. Score: {}, users: {}",
        scores.len(),
        total_users
    );
    let max = Score::max_value();
    ensure!(
        scores.iter().all(|&x| x <= max),
        "All scores should be less or equal than {}. Scores: {:#?}",
        max,
        scores,
    );
    let total: Score = scores.iter().sum();
    for (name, score) in zip(names, scores.iter()) {
        println!("Give {name} {score} karma");
    }
    println!("I gave out {total} karma");

    let ci = CircuitInput::from_plain(ck, &scores);

    println!("Generating server key share");
    let sks = gen_server_key_share(*user_id, total_users, ck);

    println!("Submit the cipher and the server key share");
    client.submit_cipher(*user_id, &ci, &sks).await?;
    Ok(scores)
}

async fn cmd_run(client: &WebClient) -> Result<(), Error> {
    println!("Requesting FHE run ...");
    let resp = client.trigger_fhe_run().await?;
    println!("Server: {}", resp);
    Ok(())
}

async fn cmd_download_output(
    client: &WebClient,
    user_id: &usize,
    ck: &ClientKey,
) -> Result<(CircuitOutput, HashMap<(usize, usize), Vec<u64>>), Error> {
    let resp = client.trigger_fhe_run().await?;
    if !matches!(resp, ServerState::CompletedFhe) {
        bail!("FHE is still running")
    }

    println!("Downloading fhe output");
    let fhe_out = client.get_fhe_output().await?;

    println!("Generating my decrypting shares");
    let mut shares = HashMap::new();
    let my_decryption_shares = fhe_out.gen_decryption_shares(ck);
    for (out_id, share) in my_decryption_shares.iter().enumerate() {
        shares.insert((out_id, *user_id), share.to_vec());
    }
    println!("Submitting my decrypting shares");
    client
        .submit_decryption_shares(*user_id, &my_decryption_shares)
        .await?;
    Ok((fhe_out, shares))
}

async fn cmd_download_shares(
    client: &WebClient,
    names: &[String],
    ck: &ClientKey,
    shares: &mut HashMap<(usize, usize), Vec<u64>>,
    co: &CircuitOutput,
    scores: &[Score],
) -> Result<Vec<Score>, Error> {
    let total_users = names.len();
    println!("Acquiring decryption shares needed");
    for (output_id, user_id) in (0..co.n()).cartesian_product(0..total_users) {
        if shares.get(&(output_id, user_id)).is_none() {
            let ds = client.get_decryption_share(output_id, user_id).await?;
            shares.insert((output_id, user_id), ds);
        }
    }
    println!("Decrypt the encrypted output");
    // Problem: How do you know output id?
    let dss = (0..co.n())
        .map(|output_id| {
            (0..total_users)
                .map(|user_id| {
                    shares
                        .get(&(output_id, user_id))
                        .expect("exists")
                        .to_owned()
                })
                .collect_vec()
        })
        .collect_vec();
    let decrypted_output = co.decrypt(ck, &dss);
    println!("Final decrypted output:");
    present_balance(names, scores, &decrypted_output);
    Ok(decrypted_output)
}

async fn run(state: State, line: &str) -> Result<State, (Error, State)> {
    let terms: Vec<&str> = line.split_whitespace().collect();
    if terms.is_empty() {
        return Ok(state);
    }
    let cmd = &terms[0];
    let args = &terms[1..];
    if cmd == &"next" {
        match state {
            State::Init(s) => match cmd_setup(&s.name, &s.client).await {
                Ok((ck, user_id)) => Ok(State::Setup(StateSetup {
                    name: s.name,
                    client: s.client,
                    ck,
                    user_id,
                })),
                Err(err) => Err((err, State::Init(s))),
            },
            State::Setup(s) => match cmd_get_names(&s.client).await {
                Ok((is_concluded, names)) => {
                    if is_concluded {
                        Ok(State::ConcludedRegistration(ConcludedRegistration {
                            name: s.name,
                            client: s.client,
                            ck: s.ck,
                            user_id: s.user_id,
                            names,
                        }))
                    } else {
                        Ok(State::Setup(s))
                    }
                }
                Err(err) => Err((err, State::Setup(s))),
            },
            State::ConcludedRegistration(s) => {
                match cmd_score_encrypt(args, &s.client, &s.user_id, &s.names, &s.ck).await {
                    Ok(scores) => Ok(State::EncryptedInput(EncryptedInput {
                        name: s.name,
                        client: s.client,
                        ck: s.ck,
                        user_id: s.user_id,
                        names: s.names,
                        scores,
                    })),
                    Err(err) => Err((err, State::ConcludedRegistration(s))),
                }
            }
            State::EncryptedInput(s) => match cmd_run(&s.client).await {
                Ok(()) => Ok(State::TriggeredRun(StateTriggeredRun {
                    name: s.name,
                    client: s.client,
                    ck: s.ck,
                    user_id: s.user_id,
                    names: s.names,
                    scores: s.scores,
                })),
                Err(err) => Err((err, State::EncryptedInput(s))),
            },
            State::TriggeredRun(s) => match cmd_download_output(&s.client, &s.user_id, &s.ck).await
            {
                Ok((fhe_out, shares)) => Ok(State::DownloadedOutput(StateDownloadedOuput {
                    name: s.name,
                    client: s.client,
                    ck: s.ck,
                    names: s.names,
                    scores: s.scores,
                    fhe_out,
                    shares,
                })),
                Err(err) => Err((err, State::TriggeredRun(s))),
            },
            State::DownloadedOutput(mut s) => {
                match cmd_download_shares(
                    &s.client,
                    &s.names,
                    &s.ck,
                    &mut s.shares,
                    &s.fhe_out,
                    &s.scores,
                )
                .await
                {
                    Ok(decrypted_output) => Ok(State::Decrypted(StateDecrypted {
                        names: s.names,
                        client: s.client,
                        decrypted_output,
                        scores: s.scores,
                    })),
                    Err(err) => Err((err, State::DownloadedOutput(s))),
                }
            }
            State::Decrypted(StateDecrypted {
                names,
                client,
                decrypted_output,
                scores,
            }) => {
                present_balance(&names, &scores, &decrypted_output);
                Ok(State::Decrypted(StateDecrypted {
                    names,
                    client,
                    decrypted_output,
                    scores,
                }))
            }
        }
    } else if cmd == &"conclude" {
        match state {
            State::Setup(s) => match cmd_conclude_registration(&s.client).await {
                Ok(names) => Ok(State::ConcludedRegistration(ConcludedRegistration {
                    name: s.name,
                    client: s.client,
                    ck: s.ck,
                    user_id: s.user_id,
                    names,
                })),
                Err(err) => Err((err, State::Setup(s))),
            },
            _ => Err((anyhow!("Invalid state for command {}", cmd), state)),
        }
    } else if cmd == &"status" {
        match &state {
            State::Init(StateInit { client, .. })
            | State::Setup(StateSetup { client, .. })
            | State::ConcludedRegistration(ConcludedRegistration { client, .. })
            | State::EncryptedInput(EncryptedInput { client, .. })
            | State::TriggeredRun(StateTriggeredRun { client, .. })
            | State::DownloadedOutput(StateDownloadedOuput { client, .. })
            | State::Decrypted(StateDecrypted { client, .. }) => {
                match client.get_dashboard().await {
                    Ok(dashbaord) => {
                        dashbaord.print_presentation();
                        Ok(state)
                    }
                    Err(err) => Err((err, state)),
                }
            }
        }
    } else if cmd.starts_with('#') {
        Ok(state)
    } else {
        Err((anyhow!("Unknown command {}", cmd), state))
    }
}

fn present_balance(names: &[String], scores: &[Score], final_balances: &[Score]) {
    #[derive(Tabled)]
    struct Row {
        name: String,
        karma_i_sent: Score,
        decrypted_karma_balance: i16,
    }
    let table = zip(zip(names, scores), final_balances)
        .map(|((name, &karma_i_sent), &decrypted_karma_balance)| Row {
            name: name.to_string(),
            karma_i_sent,
            decrypted_karma_balance: decrypted_karma_balance as i16,
        })
        .collect_vec();
    println!("{}", Table::new(table).with(Style::ascii_rounded()));
}
