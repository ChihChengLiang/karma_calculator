use itertools::Itertools;
use phantom_zone::{gen_client_key, gen_server_key_share, Encryptor, MultiPartyDecryptor};
use std::collections::HashMap;

use crate::*;
use anyhow::Error;
use phantom_zone::set_common_reference_seed;
use rocket::{
    serde::{Deserialize, Serialize},
    Build, Rocket,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
// We're not sending the User struct in rockets. This macro is here just for Serde reasons
#[serde(crate = "rocket::serde")]
pub struct User {
    name: String,
    // step 0: get seed
    seed: Option<Seed>,
    // step 0.5: gen client key
    ck: Option<ClientKey>,
    // step 1: get userID
    pub id: Option<UserId>,
    // step 2: assign scores
    scores: Option<[u8; 4]>,
    // step 3: gen key and cipher
    pub server_key: Option<ServerKeyShare>,
    pub cipher: Option<Cipher>,
    // step 4: get FHE output
    fhe_out: Option<Vec<FheUint8>>,
    // step 5: derive decryption shares
    pub decryption_shares: DecryptionSharesMap,
}

impl User {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ck: None,
            id: None,
            seed: None,
            scores: None,
            server_key: None,
            cipher: None,
            fhe_out: None,
            decryption_shares: HashMap::new(),
        }
    }

    pub fn update_name(&mut self, name: &str) -> &mut Self {
        self.name = name.to_string();
        self
    }

    pub fn assign_seed(&mut self, seed: Seed) -> &mut Self {
        self.seed = Some(seed);
        self
    }

    pub fn set_seed(&self) {
        set_common_reference_seed(self.seed.unwrap());
    }

    pub fn gen_client_key(&mut self) -> &mut Self {
        self.ck = Some(gen_client_key());
        self
    }

    pub fn set_id(&mut self, id: usize) -> &mut Self {
        self.id = Some(id);
        self
    }
    pub fn assign_scores(&mut self, scores: &[u8; 4]) -> &mut Self {
        self.scores = Some(*scores);
        self
    }

    pub fn gen_cipher(&mut self) -> &mut Self {
        let scores = self.scores.unwrap().to_vec();
        let ck: &ClientKey = self.ck.as_ref().unwrap();
        let cipher: Cipher = ck.encrypt(scores.as_slice());
        self.cipher = Some(cipher);
        self
    }

    pub fn gen_server_key_share(&mut self) -> &mut Self {
        let server_key =
            gen_server_key_share(self.id.unwrap(), TOTAL_USERS, self.ck.as_ref().unwrap());
        self.server_key = Some(server_key);
        self
    }

    pub fn set_fhe_out(&mut self, fhe_out: Vec<FheUint8>) -> &mut Self {
        self.fhe_out = Some(fhe_out);
        self
    }
    /// Populate decryption_shares with my shares
    pub fn gen_decryption_shares(&mut self) -> &mut Self {
        let ck = self.ck.as_ref().expect("already exists");
        let fhe_out = self.fhe_out.as_ref().expect("exists");
        let my_id = self.id.expect("exists");
        for (output_id, out) in fhe_out.iter().enumerate() {
            let my_decryption_share = ck.gen_decryption_share(out);
            self.decryption_shares
                .insert((output_id, my_id), my_decryption_share);
        }
        self
    }

    pub fn get_my_shares(&self) -> Vec<DecryptionShare> {
        let my_id = self.id.expect("exists");
        (0..3)
            .map(|output_id| {
                self.decryption_shares
                    .get(&(output_id, my_id))
                    .expect("exists")
                    .to_owned()
            })
            .collect_vec()
    }

    pub fn decrypt_everything(&self) -> Vec<u8> {
        let ck = self.ck.as_ref().expect("already exists");
        let fhe_out = self.fhe_out.as_ref().expect("exists");

        fhe_out
            .iter()
            .enumerate()
            .map(|(output_id, output)| {
                let decryption_shares = (0..TOTAL_USERS)
                    .map(|user_id| {
                        self.decryption_shares
                            .get(&(output_id, user_id))
                            .expect("exists")
                            .to_owned()
                    })
                    .collect_vec();
                ck.aggregate_decryption_shares(output, &decryption_shares)
            })
            .collect_vec()
    }
}

impl WebClient {
    pub(crate) async fn new_test(rocket: Rocket<Build>) -> Result<Self, Error> {
        let client = rocket::local::asynchronous::Client::tracked(rocket).await?;
        Ok(Self::Test(client))
    }
}

#[rocket::async_test]
async fn full_flow() {
    let client = WebClient::new_test(rocket()).await.unwrap();

    let mut users = vec![User::new("Barry"), User::new("Justin"), User::new("Brian")];

    println!("acquire seeds");

    // Acquire seeds
    for user in users.iter_mut() {
        let seed = client.get_seed().await.unwrap();
        user.assign_seed(seed);
        user.gen_client_key();
    }

    println!("register users");

    // Register
    for user in users.iter_mut() {
        let reg = client.register(&user.name).await.unwrap();
        user.set_id(reg.id);
    }

    let users_record = client.get_names().await.unwrap();
    println!("users records {:?}", users_record);

    // Assign scores
    users[0].assign_scores(&[0, 2, 4, 6]);
    users[1].assign_scores(&[1, 0, 1, 2]);
    users[2].assign_scores(&[1, 1, 0, 2]);

    for user in users.iter_mut() {
        println!("{} gen cipher", user.name);
        user.gen_cipher();
        println!("{} gen key share", user.name);
        let now = std::time::Instant::now();
        user.gen_server_key_share();
        println!("It takes {:#?} to gen server key", now.elapsed());
        println!("{} submit key and cipher", user.name);

        let user_id = user.id.unwrap();

        let now = std::time::Instant::now();
        client
            .submit_cipher(
                user_id,
                &user.cipher.as_ref().unwrap(),
                &user.server_key.as_ref().unwrap(),
            )
            .await
            .unwrap();
        println!("It takes {:#?} to submit server key", now.elapsed());
    }

    // Admin runs the FHE computation
    client.trigger_fhe_run().await.unwrap();

    // Users get FHE output, generate decryption shares, and submit decryption shares
    for user in users.iter_mut() {
        let fhe_output = client.get_fhe_output().await.unwrap();

        user.set_fhe_out(fhe_output);
        user.gen_decryption_shares();

        client
            .submit_decryption_shares(user.id.expect("exist now"), &user.get_my_shares())
            .await
            .unwrap();
    }
    // Users acquire all decryption shares they want
    for user in users.iter_mut() {
        for (output_id, user_id) in (0..3).cartesian_product(0..TOTAL_USERS) {
            if user.decryption_shares.get(&(output_id, user_id)).is_none() {
                let ds = client
                    .get_decryption_share(output_id, user_id)
                    .await
                    .unwrap();
                user.decryption_shares.insert((output_id, user_id), ds);
            }
        }
    }
    // Users decrypt everything
    println!("Users decrypt everything");
    for user in users {
        let decrypted_outs = user.decrypt_everything();
        println!("{} sees {:?}", user.name, decrypted_outs);
    }
}
