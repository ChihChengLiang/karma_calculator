mod client;
mod server;
mod types;

pub use client::WebClient;
pub use server::{
    rocket, setup, CipherSubmission, DecryptionShareSubmission, DecryptionSharesMap,
    RegisteredUser, RegistrationOut, ServerResponse, TOTAL_USERS,
};

pub use types::{Cipher, ClientKey, DecryptionShare, FheUint8, Seed, ServerKeyShare, UserId};

#[cfg(test)]
mod tests;
