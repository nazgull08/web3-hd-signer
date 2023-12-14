pub mod balance;
pub mod error;
pub mod fee;
pub mod functions;
pub mod rates;
pub mod tron;
pub mod tron_grpc;
pub mod types;
pub mod wallet;

#[cfg(test)]
mod tests {
    #[test]
    fn test_wallet() {}
}
