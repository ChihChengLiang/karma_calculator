use crate::types::{
    Cipher, CipherSubmission, DecryptionShare, DecryptionShareSubmission, FheUint8, RegisteredUser,
    Seed, ServerKeyShare, ServerResponse, UserId,
};
use anyhow::{anyhow, Error};
use reqwest::{
    self,
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use rocket::serde::msgpack;
use serde::{Deserialize, Serialize};

pub enum WebClient {
    Prod {
        url: String,
        client: reqwest::Client,
    },
    Test(rocket::local::asynchronous::Client),
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
                let result = client
                    .get(self.path(path))
                    .send()
                    .await?
                    .json::<T>()
                    .await?;
                Ok(result)
            }
            WebClient::Test(client) => client
                .get(path)
                .dispatch()
                .await
                .into_json::<T>()
                .await
                .ok_or(anyhow!("Request failed")),
        }
    }
    async fn post_nobody<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
    ) -> Result<T, Error> {
        match self {
            WebClient::Prod { client, .. } => {
                let result = client.post(self.path(path)).send().await?.json().await?;
                Ok(result)
            }
            WebClient::Test(client) => client
                .post(path)
                .dispatch()
                .await
                .into_json::<T>()
                .await
                .ok_or(anyhow!("Request failed")),
        }
    }
    async fn post<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<T, Error> {
        match self {
            WebClient::Prod { client, .. } => {
                let result = client
                    .post(self.path(path))
                    .body(body)
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(result)
            }
            WebClient::Test(client) => client
                .post(path)
                .body(body)
                .dispatch()
                .await
                .into_json::<T>()
                .await
                .ok_or(anyhow!("Request failed")),
        }
    }
    async fn post_msgpack<T: Send + for<'de> Deserialize<'de> + 'static>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, Error> {
        match self {
            WebClient::Prod { client, .. } => {
                let result = client
                    .post(self.path(path))
                    .headers(HeaderMap::from_iter([(
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/msgpack"),
                    )]))
                    .body(msgpack::to_compact_vec(body)?)
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(result)
            }
            WebClient::Test(client) => client
                .post(path)
                .msgpack(body)
                .dispatch()
                .await
                .into_json::<T>()
                .await
                .ok_or(anyhow!("Request failed")),
        }
    }

    pub async fn get_seed(&self) -> Result<Seed, Error> {
        self.get("/param").await
    }

    pub async fn register(&self, name: &str) -> Result<RegisteredUser, Error> {
        self.post("/register", name.as_bytes().to_vec()).await
    }
    pub async fn get_names(&self) -> Result<Vec<RegisteredUser>, Error> {
        self.get("/users").await
    }

    pub async fn submit_cipher(
        &self,
        user_id: UserId,
        cipher_text: &Cipher,
        sks: &ServerKeyShare,
    ) -> Result<ServerResponse, Error> {
        let submission = CipherSubmission {
            user_id,
            cipher_text: cipher_text.clone(),
            sks: sks.clone(),
        };
        self.post_msgpack("/submit", &submission).await
    }

    pub async fn trigger_fhe_run(&self) -> Result<ServerResponse, Error> {
        self.post_nobody("/run").await
    }

    pub async fn get_fhe_output(&self) -> Result<Vec<FheUint8>, Error> {
        self.get("/fhe_output").await
    }

    pub async fn submit_decryption_shares(
        &self,
        user_id: usize,
        decryption_shares: &Vec<DecryptionShare>,
    ) -> Result<ServerResponse, Error> {
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
