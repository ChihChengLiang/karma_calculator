use itertools::Itertools;
use phantom_zone::{
    aggregate_server_key_shares, KeySwitchWithId, ParameterSelector, SampleExtractor,
};
use rayon::prelude::*;

use crate::{time, Cipher, FheUint8, RegisteredUser, ServerKeyShare};

pub const PARAMETER: ParameterSelector = ParameterSelector::NonInteractiveLTE40PartyExperimental;

/// Circuit
pub(crate) fn sum_fhe_dyn(receving_karmas: &[FheUint8]) -> FheUint8 {
    let sum = receving_karmas
        .iter()
        .cloned()
        .reduce(|a, b| &a + &b)
        .expect("At least one input is received");
    sum
}

/// Server work
/// Warning: global variable change
pub(crate) fn derive_server_key(server_key_shares: &[ServerKeyShare]) {
    let server_key = time!(
        || aggregate_server_key_shares(server_key_shares),
        "Aggregate server key shares"
    );
    println!("set server key");
    server_key.set_server_key();
}

/// Server work
pub(crate) fn evaluate_circuit(users: &[(Cipher, RegisteredUser)]) -> Vec<FheUint8> {
    // Preprocess ciphers
    // 1. Decompression: A cipher is a matrix generated from a seed. The seed is sent through the network as a compression. By calling the `unseed` method we recovered the matrix here.
    // 2. Key Switch: We reencrypt the cipher with the server key for the computation. We need to specify the original signer of the cipher.
    // 3. Extract: A user's encrypted inputs are packed in `BatchedFheUint8` struct. We call `extract_all` method to convert it to `Vec<FheUint8>` for easier manipulation.
    let ciphers = users
        .iter()
        .enumerate()
        .map(|(user_id, u)| {
            u.0.unseed::<Vec<Vec<u64>>>()
                .key_switch(user_id)
                .extract_all()
        })
        .collect_vec();

    let mut outs = vec![];

    users
        .par_iter()
        .enumerate()
        .map(|(my_id, (_, me))| {
            println!("Compute {}'s karma", me.name);
            let sent = sum_fhe_dyn(&ciphers[my_id]);
            let received = ciphers.iter().map(|enc| enc[my_id].clone()).collect_vec();
            let received = sum_fhe_dyn(&received);

            &received - &sent
        })
        .collect_into_vec(&mut outs);
    outs
}
