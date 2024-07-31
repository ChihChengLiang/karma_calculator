use itertools::Itertools;
use phantom_zone::{
    aggregate_server_key_shares, set_parameter_set, KeySwitchWithId, ParameterSelector,
    SampleExtractor,
};

use crate::{time, Cipher, FheUint8, RegisteredUser, ServerKeyShare};

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
    // HACK to make sure that paremeters are set in each thread.
    set_parameter_set(ParameterSelector::NonInteractiveLTE8Party);
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
    for (my_id, (_, me)) in users.iter().enumerate() {
        println!("Compute user {}'s karma", me.name);
        let karma_sent = ciphers
            .iter()
            .map(|other| other.key_switch(my_id).extract_at(my_id))
            .collect_vec();
        let karma_received = &ciphers
            .iter()
            .enumerate()
            .map(|(other_id, enc)| enc.key_switch(other_id).extract_at(my_id))
            .collect_vec();

        let karma_sent = time!(|| { sum_fhe_dyn(&karma_sent) }, "FHE Sum: ");
        let karma_received = time!(|| sum_fhe_dyn(karma_received), "FHE Sum");
        let my_balance = &karma_received - &karma_sent;
        outs.push(my_balance)
    }
    outs
}
