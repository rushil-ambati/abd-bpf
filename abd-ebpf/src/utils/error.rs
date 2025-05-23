#![allow(dead_code)]

/// All helper-level errors bubble up as one of these.
#[derive(Copy, Clone)]
pub enum AbdError {
    HeaderParsingError,
    NotAnAbdPacket,
    InvalidMagicNumber,
    InvalidSenderID,
    InvalidMessageType,
    MapLookupError,
    LockRetryLimitHit,
    CounterNotNewer,
    CloneRedirectFailed,
    RedirectFailed,
    ChecksumError,
    CastFailed,
    SkbStoreFailed,
    GlobalUnset,
    UnexpectedMessageType,
}

impl AsRef<str> for AbdError {
    /// Static str for tracing.
    fn as_ref(&self) -> &str {
        match self {
            Self::HeaderParsingError => "header parsing error",
            Self::NotAnAbdPacket => "not an ABD packet",
            Self::InvalidMagicNumber => "invalid magic number",
            Self::InvalidSenderID => "invalid sender ID",
            Self::InvalidMessageType => "invalid message type",
            Self::MapLookupError => "map lookup error",
            Self::LockRetryLimitHit => "lock retry limit hit",
            Self::CounterNotNewer => "counter not newer",
            Self::CloneRedirectFailed => "clone redirect failed",
            Self::RedirectFailed => "redirect failed",
            Self::ChecksumError => "checksum error",
            Self::CastFailed => "cast failed",
            Self::SkbStoreFailed => "skb store failed",
            Self::GlobalUnset => "global unset",
            Self::UnexpectedMessageType => "unexpected message type",
        }
    }
}
