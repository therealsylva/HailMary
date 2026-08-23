#![forbid(unsafe_code)]

pub mod agent;
pub mod bundle;
pub mod config;
pub mod controller;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod listener;
pub mod model;
pub mod policy;
pub mod protocol;
pub mod task;
pub mod trust;
pub mod util;

pub use error::{Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
