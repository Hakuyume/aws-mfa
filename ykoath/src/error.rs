use std::error;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    NoDevice,
    InsufficientData,
    UnexpectedTag(u8),
    Unknown(u16),
    PCSC(pcsc::Error),
    NoSpace,
    NoSuchObject,
    AuthRequired,
    WrongSyntax,
    GenericError,
}

pub(crate) fn check_code(code: u16) -> Result<bool, Error> {
    match code {
        0x9000 => Ok(false),
        0x6100..=0x61ff => Ok(true),
        0x6a84 => Err(Error::NoSpace),
        0x6984 => Err(Error::NoSuchObject),
        0x6982 => Err(Error::AuthRequired),
        0x6a80 => Err(Error::WrongSyntax),
        0x6581 => Err(Error::GenericError),
        _ => Err(Error::Unknown(code)),
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Error::NoDevice => write!(f, "No Yubikey found"),
            Error::InsufficientData => write!(f, "Received data does not have enough length"),
            Error::UnexpectedTag(tag) => write!(f, "Unexpected tag (0x{:02x})", tag),
            Error::Unknown(code) => write!(f, "Unknown response code (0x{:04x})", code),
            Error::PCSC(err) => err.fmt(f),
            _ => fmt::Debug::fmt(self, f),
        }
    }
}

impl error::Error for Error {}

impl From<pcsc::Error> for Error {
    fn from(value: pcsc::Error) -> Self {
        Error::PCSC(value)
    }
}
