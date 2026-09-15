use reverse_core::CoreError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LinuxError {
    #[error("Netlink error: {0}")]
    Netlink(String),

    #[error("Privilege/Capability error: {0}")]
    Capability(String),

    #[error("DNS backend error: {0}")]
    Dns(String),

    #[error("Health probe error: {0}")]
    Probe(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Core error: {0}")]
    Core(#[from] CoreError),
}
