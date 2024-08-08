use crate::{
    dashboard::{Dashboard, RegisteredUser},
    types::{
        CircuitInput, CircuitOutput, DecryptionShare, DecryptionShareSubmission, InputSubmission,
        Seed, ServerKeyShare, ServerState, UserId,
    },
};
use anyhow::{anyhow, bail, Error};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{self, header::CONTENT_TYPE, Client};
use rocket::serde::msgpack;
use serde::{Deserialize, Serialize};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

pub enum WebClient {
    Prod {
        url: String,
        client: reqwest::Client,
    },
    Test(Box<rocket::local::asynchronous::Client>),
}

impl WebClient {
    pub fn new(url: &str) -> Self {
        Self::Prod {
            url: url.to_string(),
            client: Client::new(),
        }
    }

    pub fn url(&self) -> String {
        match self {
            WebClient::Prod { url, .. } => url.to_string(),
            WebClient::Test(_) => panic!("No url for testing"),
        }
    }

    fn path(&self, path: &str) -> String {
        match self {
            WebClient::Prod { url, .. } => format!("{}/{}", url, path),
            WebClient::Test(_) => unreachable!(),
        }
    }

    async fn get<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> Result<T, Error> {
        match self {
            WebClient::Prod { client, .. } => {
                let response = client.get(self.path(path)).send().await?;
                handle_response_prod(response).await
            }
            WebClient::Test(client) => {
                let response = client.get(path).dispatch().await;
                handle_response_test(response).await
            }
        }
    }
    async fn post_nobody<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> Result<T, Error> {
        match self {
            WebClient::Prod { client, .. } => {
                let response = client.post(self.path(path)).send().await?;
                handle_response_prod(response).await
            }
            WebClient::Test(client) => {
                let response = client.post(path).dispatch().await;
                handle_response_test(response).await
            }
        }
    }
    async fn post<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<T, Error> {
        match self {
            WebClient::Prod { client, .. } => {
                let response = client.post(self.path(path)).body(body).send().await?;
                handle_response_prod(response).await
            }
            WebClient::Test(client) => {
                let response = client.post(path).body(body).dispatch().await;
                handle_response_test(response).await
            }
        }
    }
    async fn post_msgpack<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, Error> {
        match self {
            WebClient::Prod { client, .. } => {
                let body = msgpack::to_compact_vec(body)?;
                let reader = ProgressReader::new(&body, 128 * 1024);
                let stream = ReaderStream::new(reader);

                let response = client
                    .post(self.path(path))
                    .header(CONTENT_TYPE, "application/msgpack")
                    .body(reqwest::Body::wrap_stream(stream))
                    .send()
                    .await?;
                handle_response_prod(response).await
            }
            WebClient::Test(client) => {
                let response = client.post(path).msgpack(body).dispatch().await;
                handle_response_test(response).await
            }
        }
    }

    pub async fn get_seed(&self) -> Result<Seed, Error> {
        self.get("/param").await
    }

    pub async fn register(&self, name: &str) -> Result<RegisteredUser, Error> {
        self.post("/register", name.as_bytes().to_vec()).await
    }
    pub async fn get_dashboard(&self) -> Result<Dashboard, Error> {
        self.get("/dashboard").await
    }

    pub async fn conclude_registration(&self) -> Result<Dashboard, Error> {
        self.post_nobody("/conclude_registration").await
    }

    pub async fn submit_cipher(
        &self,
        user_id: UserId,
        ci: &CircuitInput,
        sks: &ServerKeyShare,
    ) -> Result<UserId, Error> {
        let submission = InputSubmission {
            user_id,
            ci: ci.clone(),
            sks: sks.clone(),
        };
        self.post_msgpack("/submit", &submission).await
    }

    pub async fn trigger_fhe_run(&self) -> Result<ServerState, Error> {
        self.post_nobody("/run").await
    }

    pub async fn get_fhe_output(&self) -> Result<CircuitOutput, Error> {
        self.get("/fhe_output").await
    }

    pub async fn submit_decryption_shares(
        &self,
        user_id: usize,
        decryption_shares: &[DecryptionShare],
    ) -> Result<UserId, Error> {
        let submission = DecryptionShareSubmission {
            user_id,
            decryption_shares: decryption_shares.to_vec(),
        };
        self.post_msgpack("/submit_decryption_shares", &submission)
            .await
    }

    pub async fn get_decryption_share(
        &self,
        output_id: usize,
        user_id: usize,
    ) -> Result<DecryptionShare, Error> {
        self.get(&format!("/decryption_share/{output_id}/{user_id}"))
            .await
    }
}

async fn handle_response_prod<T: Send + for<'de> Deserialize<'de> + 'static>(
    response: reqwest::Response,
) -> Result<T, Error> {
    match response.status().as_u16() {
        200 => Ok(response.json::<T>().await?),
        _ => {
            let err = response.text().await?;
            bail!("Server responded error: {:?}", err)
        }
    }
}

async fn handle_response_test<T: Send + for<'de> Deserialize<'de> + 'static>(
    response: rocket::local::asynchronous::LocalResponse<'_>,
) -> Result<T, Error> {
    match response.status().code {
        200 => response
            .into_json::<T>()
            .await
            .ok_or(anyhow!("Can't parse response output")),
        _ => {
            let err = response
                .into_string()
                .await
                .ok_or(anyhow!("Can't parse response output"))?;
            bail!("Server responded error: {:?}", err)
        }
    }
}

struct ProgressReader {
    inner: Vec<u8>,
    progress_bar: ProgressBar,
    position: usize,
    chunk_size: usize,
}

impl ProgressReader {
    fn new(body: &[u8], chunk_size: usize) -> Self {
        let total_bytes = body.len() as u64;
        println!("Total size {} B", total_bytes);
        let bar = ProgressBar::new(total_bytes);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {percent}% {bytes_per_sec} {msg}",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        bar.set_message("Uploading...");

        Self {
            inner: body.to_vec(),
            progress_bar: bar,
            position: 0,
            chunk_size,
        }
    }
}

impl AsyncRead for ProgressReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let remaining = self.inner.len() - self.position;
        let to_read = self.chunk_size.min(remaining.min(buf.remaining()));
        let end = self.position + to_read;
        buf.put_slice(&self.inner[self.position..end]);
        self.position = end;
        self.progress_bar.set_position(self.position as u64);

        if to_read == 0 {
            self.progress_bar.finish_with_message("Upload complete")
        }

        Poll::Ready(Ok(()))
    }
}
