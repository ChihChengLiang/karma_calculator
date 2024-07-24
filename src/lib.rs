mod circuit;
mod client;
mod server;
mod types;

pub use client::WebClient;
pub use server::{rocket, setup};

pub use types::{
    Cipher, CipherSubmission, ClientKey, DecryptionShare, DecryptionShareSubmission,
    DecryptionSharesMap, FheUint8, MutexServerStatus, RegisteredUser, Seed, ServerKeyShare,
    ServerResponse, UserId, TOTAL_USERS,
};

#[cfg(test)]
mod tests;
