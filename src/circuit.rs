use itertools::Itertools;
use phantom_zone::{
    aggregate_server_key_shares, set_parameter_set, KeySwitchWithId, ParameterSelector,
    SampleExtractor,
};

use crate::{Cipher, FheUint8, RegisteredUser, ServerKeyShare};

pub(crate) struct FHEConfig {
    max_users: usize,
    param: ParameterSelector,
}

impl FHEConfig {
    pub fn new(max_users: usize) -> Self {
        Self {
            max_users,
            param: ParameterSelector::NonInteractiveLTE4Party,
        }
    }
}

pub fn sum_fhe(a: &FheUint8, b: &FheUint8, c: &FheUint8, total: &FheUint8) -> FheUint8 {
    &(&(a + b) + c) - total
}

pub(crate) fn sum_fhe_dyn(receving_karmas: &[FheUint8], given_out: &FheUint8) -> FheUint8 {
    let sum: FheUint8 = receving_karmas
        .iter()
        .cloned()
        .reduce(|a, b| &a + &b)
        .expect("At least one input is received");
    &sum - given_out
}

/// Warning: global variable change
pub(crate) fn derive_server_key(server_key_shares: &[ServerKeyShare]) {
    // HACK to make sure that paremeters are set in each thread.
    set_parameter_set(ParameterSelector::NonInteractiveLTE4Party);
    println!("aggregate server key shares");
    let now = std::time::Instant::now();
    let server_key = aggregate_server_key_shares(server_key_shares);
    println!("server key aggregation time: {:?}", now.elapsed());
    println!("set server key");
    server_key.set_server_key();
}

pub(crate) fn evaluate_circuit(users: &[(Cipher, RegisteredUser)]) -> Vec<FheUint8> {
    // Unseed ciphers
    let ciphers = users
        .iter()
        .map(|u| u.0.unseed::<Vec<Vec<u64>>>())
        .collect_vec();

    let mut outs = vec![];
    for (my_id, (_, me)) in users.iter().enumerate() {
        println!("Compute user {}'s karma", me.name);
        let my_scores_from_others = &ciphers
            .iter()
            .enumerate()
            .map(|(other_id, enc)| enc.key_switch(other_id).extract_at(my_id))
            .collect_vec();

        let total = ciphers[my_id].key_switch(my_id).extract_at(3);

        let now = std::time::Instant::now();
        let ct_out = sum_fhe(
            &my_scores_from_others[0],
            &my_scores_from_others[1],
            &my_scores_from_others[2],
            &total,
        );
        println!("sum_fhe evaluation time: {:?}", now.elapsed());
        outs.push(ct_out)
    }
    outs
}
