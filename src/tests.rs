use circuit::PARAMETER;
use itertools::Itertools;
use phantom_zone::{
    gen_client_key, gen_server_key_share, set_parameter_set, Encryptor, MultiPartyDecryptor,
};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use std::{collections::HashMap, time::Duration};
use tokio::time::sleep;

use crate::*;
use anyhow::Error;
use futures::future::join_all;
use rocket::{
    serde::{msgpack, Deserialize, Serialize},
    Build, Rocket,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
// We're not sending the User struct in rockets. This macro is here just for Serde reasons
#[serde(crate = "rocket::serde")]
struct User {
    name: String,
    // step 0: get seed
    seed: Option<Seed>,
    // step 0.5: gen client key
    ck: Option<ClientKey>,
    // step 1: get userID
    id: Option<UserId>,
    total_users: Option<usize>,
    // step 2: assign scores
    scores: Option<Vec<u8>>,
    // step 3: gen key and cipher
    server_key: Option<ServerKeyShare>,
    cipher: Option<Cipher>,
    // step 4: get FHE output
    fhe_out: Option<Vec<FheUint8>>,
    // step 5: derive decryption shares
    decryption_shares: DecryptionSharesMap,
}

impl User {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            seed: None,
            ck: None,
            id: None,
            total_users: None,
            scores: None,
            server_key: None,
            cipher: None,
            fhe_out: None,
            decryption_shares: HashMap::new(),
        }
    }
    fn assign_seed(&mut self, seed: Seed) -> &mut Self {
        self.seed = Some(seed);
        self
    }

    fn gen_client_key(&mut self) -> &mut Self {
        self.ck = Some(gen_client_key());
        self
    }

    fn set_id(&mut self, id: usize) -> &mut Self {
        self.id = Some(id);
        self
    }

    fn set_total_users(&mut self, total_users: usize) -> &mut Self {
        self.total_users = Some(total_users);
        self
    }
    fn assign_scores(&mut self, scores: &[u8]) -> &mut Self {
        self.scores = Some(scores.to_vec());
        self
    }

    fn gen_cipher(&mut self) -> &mut Self {
        let scores = self.scores.as_ref().unwrap().to_vec();
        let ck: &ClientKey = self.ck.as_ref().unwrap();
        let cipher: Cipher = ck.encrypt(scores.as_slice());
        self.cipher = Some(cipher);
        self
    }

    fn gen_server_key_share(&mut self) -> &mut Self {
        let server_key = gen_server_key_share(
            self.id.unwrap(),
            self.total_users.unwrap(),
            self.ck.as_ref().unwrap(),
        );
        self.server_key = Some(server_key);
        self
    }

    fn set_fhe_out(&mut self, fhe_out: Vec<FheUint8>) -> &mut Self {
        self.fhe_out = Some(fhe_out);
        self
    }
    /// Populate decryption_shares with my shares
    fn gen_decryption_shares(&mut self) -> &mut Self {
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

    fn get_my_shares(&self) -> Vec<DecryptionShare> {
        let total_users = self.total_users.expect("exist");
        let my_id = self.id.expect("exists");
        (0..total_users)
            .map(|output_id| {
                self.decryption_shares
                    .get(&(output_id, my_id))
                    .expect("exists")
                    .to_owned()
            })
            .collect_vec()
    }

    fn decrypt_everything(&self) -> Vec<u8> {
        let total_users = self.total_users.expect("exist");
        let ck = self.ck.as_ref().expect("already exists");
        let fhe_out = self.fhe_out.as_ref().expect("exists");

        fhe_out
            .iter()
            .enumerate()
            .map(|(output_id, output)| {
                let decryption_shares = (0..total_users)
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
        Ok(Self::Test(Box::new(client)))
    }
}

async fn run_flow_with_n_users(total_users: usize) -> Result<(), Error> {
    let client = WebClient::new_test(rocket()).await.unwrap();

    let mut users = (0..total_users)
        .map(|i| User::new(&format!("User {i}")))
        .collect_vec();

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
    // Conclude the registration
    client.conclude_registration().await.unwrap();

    for user in users.iter_mut() {
        let dashboard = client.get_dashboard().await.unwrap();
        user.set_total_users(dashboard.get_names().len());
    }

    // Assign scores
    for user in users.iter_mut() {
        let scores: Vec<u8> = (0u8..total_users.try_into().unwrap()).collect_vec();
        user.assign_scores(&scores);
    }

    let mut correct_output = vec![];
    for (my_id, me) in users.iter().enumerate() {
        let given_out = me.scores.as_ref().unwrap().iter().sum::<u8>();
        let mut received = 0u8;
        for other in users.iter() {
            received += other.scores.as_ref().unwrap()[my_id];
        }
        correct_output.push(received - given_out)
    }

    users.par_iter_mut().for_each(|user| {
        set_parameter_set(PARAMETER);
        println!("{} Gen cipher", user.name);
        user.gen_cipher();
        time!(
            || {
                user.gen_server_key_share();
            },
            format!("{} Gen server key share", user.name)
        );
        println!("{} submit key and cipher", user.name);
    });

    async fn submit_cipher(client: &WebClient, user: &mut User) {
        let user_id = user.id.unwrap();
        let cipher_text = user.cipher.as_ref().unwrap();
        let sks = user.server_key.as_ref().unwrap();
        if user_id == 0 {
            let cipher_text = msgpack::to_vec(cipher_text).unwrap();
            let sks = msgpack::to_vec(sks).unwrap();
            println!("cipher_text size {}", cipher_text.len());
            println!("sks size {}", sks.len());
        }
        println!("Submit cipher and server key");
        client
            .submit_cipher(user_id, &cipher_text, &sks)
            .await
            .unwrap();
        // Drop here to save mem
        user.server_key = None;
    }
    // Submit cipher in concurrent
    join_all(users.iter_mut().map(|user| submit_cipher(&client, user))).await;

    // Admin runs the FHE computation
    client.trigger_fhe_run().await.unwrap();
    while client.trigger_fhe_run().await.unwrap() != "FHE already complete" {
        sleep(Duration::from_secs(1)).await
    }

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
        for (output_id, user_id) in (0..total_users).cartesian_product(0..total_users) {
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
        assert_eq!(decrypted_outs, correct_output);
    }
    Ok(())
}

#[rocket::async_test]
async fn full_flow() {
    // Need to fix the global variable thing to allow multiple flow run
    // run_flow_with_n_users(2).await.unwrap();
    // run_flow_with_n_users(3).await.unwrap();
    run_flow_with_n_users(4).await.unwrap();
}
