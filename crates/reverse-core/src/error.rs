use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid target expression: {0}")]
    InvalidTarget(String),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Policy resolution error: {0}")]
    Policy(String),

    #[error("Planner error: {0}")]
    Planner(String),

    #[error("Classification error: {0}")]
    Classification(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
