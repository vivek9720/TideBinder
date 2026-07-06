use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TideError {
    Truncated {
        at: usize,
        needed: usize,
        remaining: usize,
    },
    InvalidMagic,
    BadVarint,
    BadUtf8,
    UnknownSection(u8),
    LimitExceeded(&'static str),
    InvalidRecord(&'static str),
    ScriptFault(&'static str),
}

pub type Result<T> = core::result::Result<T, TideError>;

impl fmt::Display for TideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TideError::Truncated { at, needed, remaining } => write!(
                f,
                "truncated input at byte {at}: needed {needed}, remaining {remaining}"
            ),
            TideError::InvalidMagic => f.write_str("invalid TideBinder magic"),
            TideError::BadVarint => f.write_str("invalid variable length integer"),
            TideError::BadUtf8 => f.write_str("dictionary symbol is not UTF-8"),
            TideError::UnknownSection(kind) => write!(f, "unknown section kind {kind}"),
            TideError::LimitExceeded(name) => write!(f, "limit exceeded while decoding {name}"),
            TideError::InvalidRecord(name) => write!(f, "invalid {name} record"),
            TideError::ScriptFault(name) => write!(f, "query bytecode fault: {name}"),
        }
    }
}

impl std::error::Error for TideError {}
