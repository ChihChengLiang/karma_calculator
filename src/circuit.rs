use crate::{
    compiled::{karma_add, karma_sub},
    time,
    types::{CircuitInput, CircuitOutput, ServerKeyShare, Word},
};
use itertools::Itertools;
use phantom_zone::{aggregate_server_key_shares, set_parameter_set, ParameterSelector};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

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
pub(crate) fn evaluate_circuit(cis: &[CircuitInput]) -> CircuitOutput {
    let cis = cis
        .iter()
        .enumerate()
        .map(|(user_id, ci)| ci.unpack(user_id))
        .collect_vec();

    let mut outs = vec![];

    cis.par_iter()
        .enumerate()
        .map(|(my_id, my_ci)| {
            let sent = sum_fhe_dyn(my_ci);
            let received = cis.iter().map(|enc| enc[my_id].clone()).collect_vec();
            let received = sum_fhe_dyn(&received);
            set_parameter_set(PARAMETER);
            karma_sub(&received, &sent)
        })
        .collect_into_vec(&mut outs);
    CircuitOutput::new(outs)
}
