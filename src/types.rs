use phantom_zone::{
    evaluator::NonInteractiveMultiPartyCrs,
    keys::CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare, parameters::BoolParameters,
    SeededBatchedFheUint8,
};

pub type Seed = [u8; 32];
pub type ServerKeyShare = CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare<
    Vec<Vec<u64>>,
    BoolParameters<u64>,
    NonInteractiveMultiPartyCrs<Seed>,
>;
pub type Cipher = SeededBatchedFheUint8<Vec<u64>, Seed>;
pub type DecryptionShare = Vec<u64>;
pub type ClientKey = phantom_zone::ClientKey;
pub type UserId = usize;
pub type FheUint8 = phantom_zone::FheUint8;
