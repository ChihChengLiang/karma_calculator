use crate::types::{
    Cipher, CipherSubmission, Dashboard, DecryptionShare, DecryptionShareSubmission, FheUint8,
    RegisteredUser, Seed, ServerKeyShare, UserId,
};
use anyhow::{anyhow, bail, Error};
use indicatif::ProgressBar;
use reqwest::{self, header::CONTENT_TYPE, Client};
use rocket::{futures::StreamExt, serde::msgpack};
use serde::{Deserialize, Serialize};
use std::io::Write;
use tempfile::tempfile;
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
                // let body = msgpack::to_compact_vec(body)?.chunks(64 * 2014);
                let body = msgpack::to_compact_vec(body)?;
                let mut file = tempfile()?;
                file.write_all(&body)?;
                let file = tokio::fs::File::from(file);

                // let mut stream = ReaderStream::new(body.as_slice());
                let total_size = body.len() as u64;
                let bar = ProgressBar::new(total_size);
                let mut uploaded = 0;
                let mut reader_stream = ReaderStream::new(file);
                let async_stream = async_stream::stream! {
                    while let Some(chunk) = reader_stream.next().await {
                        if let Ok(chunk) = &chunk {
                            uploaded += chunk.len() as u64;
                            uploaded = uploaded.min(total_size);
                            bar.set_position(uploaded);
                            if uploaded >= total_size {
                                bar.finish();
                            }

                        }
                        yield chunk;
                    }
                };

                let response = client
                    .post(self.path(path))
                    .header(CONTENT_TYPE, "application/msgpack")
                    .body(reqwest::Body::wrap_stream(async_stream))
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
        cipher_text: &Cipher,
        sks: &ServerKeyShare,
    ) -> Result<UserId, Error> {
        let submission = CipherSubmission {
            user_id,
            cipher_text: cipher_text.clone(),
            sks: sks.clone(),
        };
        self.post_msgpack("/submit", &submission).await
    }

    pub async fn trigger_fhe_run(&self) -> Result<String, Error> {
        self.post_nobody("/run").await
    }

    pub async fn get_fhe_output(&self) -> Result<Vec<FheUint8>, Error> {
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
