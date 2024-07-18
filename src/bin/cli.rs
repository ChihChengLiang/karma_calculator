use clap::command;
use karma_calculator::{setup, RegistrationOut, User};

use tokio;

use clap::{Parser, Subcommand};
use reqwest::{self, Client};

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
    Rate,
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
            let seed: [u8; 32] = reqwest::get(format!("{root_url}/param"))
                .await?
                .json()
                .await?;
            println!("acquired seed {:?}", seed);
            setup(&seed);
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
        Commands::Rate => todo!(),
        Commands::SubmitCipher => todo!(),
        Commands::SubmitDecryptionShares => todo!(),
        Commands::ComputeFheOutput => todo!(),
        Commands::RunFhe => todo!(),
    };
    Ok(())
}
