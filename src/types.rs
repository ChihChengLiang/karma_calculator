use phantom_zone::{
    evaluator::NonInteractiveMultiPartyCrs,
    keys::CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare, parameters::BoolParameters,
    SeededBatchedFheUint8,
};

pub type ServerKeyShare = CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare<
    Vec<Vec<u64>>,
    BoolParameters<u64>,
    NonInteractiveMultiPartyCrs<[u8; 32]>,
>;
pub type Cipher = SeededBatchedFheUint8<Vec<u64>, [u8; 32]>;
pub type DecryptionShare = Vec<u64>;
pub type ClientKey = phantom_zone::ClientKey;
pub type UserId = usize;
pub type FheUint8 = phantom_zone::FheUint8;
