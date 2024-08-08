mod circuit;
mod client;
mod compiled;
mod dashboard;
mod server;
mod types;

pub use client::WebClient;
pub use server::{rocket, setup};
pub use types::{
    recover, u64_to_binary, CircuitInput, CircuitOutput, ClientKey, DecryptionSharesMap, Score,
    ServerState, UserId,
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
