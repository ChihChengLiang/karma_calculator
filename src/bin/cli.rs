use std::collections::HashMap;

use clap::command;
use karma_calculator::{setup, CipherSubmission, RegisteredUser, RegistrationOut, User};

use tokio;

use clap::{Parser, Subcommand};
use reqwest::{
    self,
    header::{self, HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};

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
    SubmitDecryptionShares,
    ComputeFheOutput,
    // Admin
    RunFhe,
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    // let base_url = "http://localhost:8000";

    let cli = Cli::parse();
    let mut me = User::new("");

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
                me.cipher.as_ref().expect("exists"),
                &me.server_key.as_ref().expect("exists"),
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
        Commands::SubmitDecryptionShares => todo!(),
        Commands::ComputeFheOutput => todo!(),
        Commands::RunFhe => todo!(),
    };
    Ok(())
}
