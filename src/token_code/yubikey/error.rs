use std::error;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    NoDevice,
    InsufficientData,
    UnexpectedTag(u8),
    Unknown([u8; 2]),
    PCSC(pcsc::Error),
    NoSpace,
    NoSuchObject,
    AuthRequired,
    WrongSyntax,
    GenericError,
}

impl From<pcsc::Error> for Error {
    fn from(value: pcsc::Error) -> Self {
        Error::PCSC(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Error::NoDevice => write!(f, "No Yubikey found"),
            Error::InsufficientData => write!(f, "Received data does not have enough length"),
            Error::UnexpectedTag(tag) => write!(f, "Unexpected tag (0x{:02x})", tag),
            Error::Unknown(code) => write!(f, "Unknown response code ({:02x?})", code),
            Error::PCSC(err) => err.fmt(f),
            _ => fmt::Debug::fmt(self, f),
        }
    }
}

impl error::Error for Error {}
