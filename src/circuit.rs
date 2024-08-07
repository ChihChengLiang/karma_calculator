use crate::{karma_rs_fhe_lib::karma_add, types::Word, Payload};
use itertools::Itertools;
use phantom_zone::{aggregate_server_key_shares, set_parameter_set, ParameterSelector};
use rayon::prelude::*;

use crate::{time, ServerKeyShare};

pub const PARAMETER: ParameterSelector = ParameterSelector::NonInteractiveLTE40PartyExperimental;

/// Circuit
pub(crate) fn sum_fhe_dyn(input: &[Word]) -> Word {
    let sum = input
        .par_iter()
        .cloned()
        .reduce_with(|a, b| {
            // HACK: How come the set_parameter_set didn't propagate to karma_add?
            set_parameter_set(PARAMETER);
            karma_add(&a, &b)
        })
        .expect("Not None");
    sum
}

/// Server work
/// Warning: global variable change
pub(crate) fn derive_server_key(server_key_shares: &[ServerKeyShare]) {
    let server_key = time!(
        || aggregate_server_key_shares(server_key_shares),
        "Aggregate server key shares"
    );
    server_key.set_server_key();
}

/// Server work
pub(crate) fn evaluate_circuit(ciphers: &[Payload]) -> Vec<Word> {
    // Preprocess ciphers
    // 1. Decompression: A cipher is a matrix generated from a seed. The seed is sent through the network as a compression. By calling the `unseed` method we recovered the matrix here.
    // 2. Key Switch: We reencrypt the cipher with the server key for the computation. We need to specify the original signer of the cipher.
    // 3. Extract: A user's encrypted inputs are packed in `BatchedFheUint8` struct. We call `extract_all` method to convert it to `Vec<FheUint8>` for easier manipulation.
    let ciphers = ciphers
        .iter()
        .enumerate()
        .map(|(user_id, payload)| payload.unpack(user_id))
        .collect_vec();

    let mut outs = vec![];

    ciphers
        .par_iter()
        .enumerate()
        .map(|(my_id, my_ciphers)| {
            let sent = sum_fhe_dyn(my_ciphers);
            let received = ciphers.iter().map(|enc| enc[my_id].clone()).collect_vec();
            let received = sum_fhe_dyn(&received);
            // &received - &sent
            received
        })
        .collect_into_vec(&mut outs);
    outs
}
