#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No Yubikey found")]
    NoDevice,
    #[error("Received data does not have enough length")]
    InsufficientData,
    #[error("Unexpected tag (0x{0:02x})")]
    UnexpectedTag(u8),
    #[error("Unexpected length ({0})")]
    UnexpectedLength(u8),
    #[error("Unknown response code (0x{0:04x})")]
    Unknown(u16),
    #[error(transparent)]
    Pcsc(#[from] pcsc::Error),
    #[error("No space")]
    NoSpace,
    #[error("No such object")]
    NoSuchObject,
    #[error("Auth required")]
    AuthRequired,
    #[error("Wrong syntax")]
    WrongSyntax,
    #[error("Generic error")]
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
