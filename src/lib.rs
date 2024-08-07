mod circuit;
mod client;
mod dashboard;
mod karma_rs_fhe_lib;
mod server;
mod types;

pub use client::WebClient;
pub use server::{rocket, setup};

pub use types::{
    recover, u64_to_binary, ClientKey, DecryptionShare, DecryptionSharesMap, Score, Seed,
    ServerKeyShare, UserId, Word, *,
};

#[cfg(test)]
mod tests;

/// Utility to time a long running function
#[macro_export]
macro_rules! time {
    ($block:expr, $label:expr) => {{
        let start = std::time::Instant::now();
        print!("{}", $label);
        let result = $block();
        println!(" | elapsed: {:.2?}", start.elapsed());
        result
    }};
}
