mod client_server;
mod types;

pub use client_server::{
    rocket, setup, CipherSubmission, DecryptionShareSubmission, DecryptionSharesMap,
    RegisteredUser, RegistrationOut, ServerResponse, TOTAL_USERS,
};

pub use types::{Cipher, ClientKey, DecryptionShare, FheUint8, Seed, ServerKeyShare, UserId};

#[cfg(test)]
mod tests;
