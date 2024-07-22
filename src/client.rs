use crate::{
    CipherSubmission, DecryptionShare, DecryptionShareSubmission, FheUint8, RegisteredUser,
    RegistrationOut, Seed, ServerResponse,
};
use anyhow::Error;
use reqwest::{
    self,
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use rocket::serde::msgpack;
use serde::{Deserialize, Serialize};

pub struct WebClient {
    // The root URL
    url: String,
    client: Client,
}

impl WebClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: Client::new(),
        }
    }
    fn path(&self, path: &str) -> String {
        format!("{}/{}", self.url, path)
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, Error> {
        let result = self
            .client
            .get(self.path(path))
            .send()
            .await?
            .json::<T>()
            .await?;
        Ok(result)
    }
    async fn post_nobody<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, Error> {
        let result = self
            .client
            .post(self.path(path))
            .send()
            .await?
            .json()
            .await?;
        Ok(result)
    }
    async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: impl Into<reqwest::Body>,
    ) -> Result<T, Error> {
        let result = self
            .client
            .post(self.path(path))
            .body(body)
            .send()
            .await?
            .json()
            .await?;
        Ok(result)
    }
    async fn post_msgpack<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, Error> {
        let result = self
            .client
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

    pub async fn get_seed(&self) -> Result<Seed, Error> {
        self.get("param").await
    }

    pub async fn register(&self, name: &str) -> Result<RegistrationOut, Error> {
        self.post("register", name.to_string()).await
    }
    pub async fn get_names(&self) -> Result<Vec<RegisteredUser>, Error> {
        self.get("users").await
    }

    pub async fn submit_cipher(
        &self,
        submission: &CipherSubmission,
    ) -> Result<ServerResponse, Error> {
        self.post_msgpack("submit", submission).await
    }

    pub async fn trigger_fhe_run(&self) -> Result<ServerResponse, Error> {
        self.post_nobody("run").await
    }

    pub async fn get_fhe_output(&self) -> Result<Vec<FheUint8>, Error> {
        self.get("fhe_output").await
    }

    pub async fn submit_decryption_shares(
        &self,
        submission: &DecryptionShareSubmission<'_>,
    ) -> Result<ServerResponse, Error> {
        self.post_msgpack("submit_decryption_shares", submission)
            .await
    }

    pub async fn get_decryption_share(
        &self,
        output_id: usize,
        user_id: usize,
    ) -> Result<DecryptionShare, Error> {
        self.get(&format!("decryption_share/{output_id}/{user_id}"))
            .await
    }
}
