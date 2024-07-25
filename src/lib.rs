mod circuit;
mod client;
mod server;
mod types;

pub use client::WebClient;
pub use server::{rocket, setup};

pub use types::{
    Cipher, ClientKey, DecryptionShare, DecryptionSharesMap, FheUint8, MutexServerStatus,
    RegisteredUser, Seed, ServerKeyShare, ServerStatus, UserId, TOTAL_USERS,
};

#[cfg(test)]
mod tests;
