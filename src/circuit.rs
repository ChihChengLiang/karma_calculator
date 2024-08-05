use itertools::Itertools;
use phantom_zone::{
    aggregate_server_key_shares, set_parameter_set, KeySwitchWithId, ParameterSelector,
    SampleExtractor,
};
use rayon::prelude::*;

use crate::{time, Cipher, FheUint8, RegisteredUser, ServerKeyShare};

pub const PARAMETER: ParameterSelector = ParameterSelector::NonInteractiveLTE40PartyExperimental;

/// Circuit
pub(crate) fn sum_fhe_dyn(receving_karmas: &[FheUint8]) -> FheUint8 {
    let sum: FheUint8 = receving_karmas
        .iter()
        .cloned()
        .reduce(|a, b| &a + &b)
        .expect("At least one input is received");
    sum
}

/// Server work
/// Warning: global variable change
pub(crate) fn derive_server_key(server_key_shares: &[ServerKeyShare]) {
    // HACK to make sure that paremeters are set in each thread.
    set_parameter_set(PARAMETER);
    let server_key = time!(
        || aggregate_server_key_shares(server_key_shares),
        "Aggregate server key shares"
    );
    println!("set server key");
    server_key.set_server_key();
}

/// Server work
pub(crate) fn evaluate_circuit(users: &[(Cipher, RegisteredUser)]) -> Vec<FheUint8> {
    // Unseed ciphers
    let ciphers = users
        .iter()
        .map(|u| u.0.unseed::<Vec<Vec<u64>>>())
        .collect_vec();

    let mut outs = vec![];

    users
        .par_iter()
        .enumerate()
        .map(|(my_id, (_, me))| {
            set_parameter_set(PARAMETER);
            println!("Compute user {}'s karma", me.name);
            let my_scores_from_others = &ciphers
                .iter()
                .enumerate()
                .map(|(other_id, enc)| enc.key_switch(other_id).extract_at(my_id))
                .collect_vec();

            let given_out = ciphers
                .iter()
                .map(|other| other.key_switch(my_id).extract_at(my_id))
                .collect_vec();
            let given_out = time!(|| { sum_fhe_dyn(&given_out) }, "FHE Sum: ");

            let ct_out = time!(
                || { &sum_fhe_dyn(my_scores_from_others) - &given_out },
                "FHE Sum"
            );
            ct_out
        })
        .collect_into_vec(&mut outs);
    outs
}
