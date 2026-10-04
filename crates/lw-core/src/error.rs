use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("sqlite error: {0}")]
    Sqlite(String),

    #[error("cancelled")]
    Cancelled,

    #[error("invalid case: {0}")]
    InvalidCase(String),

    #[error("parse error: {0}")]
    Parse(String),
}

impl Error {
    pub fn msg(m: impl Into<String>) -> Self {
        Self::Msg(m.into())
    }
}
