#![cfg_attr(not(feature = "user"), no_std)]
pub mod data;
pub use data::{SQLExecution, MAX_BUF_SIZE};
