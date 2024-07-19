mod client_server;
mod types;

pub use client_server::{
    rocket, setup, Cipher, CipherSubmission, DecryptionShare, DecryptionShareSubmission,
    DecryptionSharesMap, RegisteredUser, RegistrationOut, ServerKeyShare, ServerResponse, User,
    TOTAL_USERS,
};

pub use types::{Cipher, ClientKey, DecryptionShare, FheUint8, ServerKeyShare, UserId};

#[cfg(test)]
mod tests;
