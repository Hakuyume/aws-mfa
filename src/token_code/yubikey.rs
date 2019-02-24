use log::info;
use pcsc::{Card, Context, Protocols, ShareMode, MAX_BUFFER_SIZE};
use std::error;
use std::fmt;

pub struct Yubikey {
    card: Card,
}

impl Yubikey {
    pub fn connect(context: &Context, buffer: &mut Vec<u8>) -> Result<Self, Error> {
        const YK_READER_NAME: &'static str = "yubico yubikey";

        buffer.resize(context.list_readers_len()?, 0);
        let reader = context
            .list_readers(buffer)?
            .find(|reader| {
                reader
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .starts_with(YK_READER_NAME)
            })
            .ok_or(Error::NoDevice)?;
        Ok(Self {
            card: context.connect(reader, ShareMode::Exclusive, Protocols::ANY)?,
        })
    }

    pub fn select(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        const SEND: &'static [u8] = &[
            0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01,
        ];
        buffer.resize(MAX_BUFFER_SIZE, 0);
        let recv = self.card.transmit(SEND, buffer)?;
        // TODO: handle the case of AuthRequired.
        let mut parser = parse_recv(recv)?;
        let version = parser(0x79)?;
        let name = parser(0x71)?;
        info!(
            "oath select: {{ version: {:02x?}, name: {:02x?} }}",
            version, name
        );
        Ok(())
    }

    pub fn calculate<'a>(
        &self,
        name: &str,
        challenge: &[u8],
        buffer: &'a mut Vec<u8>,
    ) -> Result<(u8, &'a [u8]), Error> {
        buffer.clear();

        let name = name.as_bytes();
        let name_len = name.len() as _;
        let challenge_len = challenge.len() as _;
        buffer.extend_from_slice(&[0x00, 0xa2, 0x00, 0x00, 2 + name_len + 2 + challenge_len]);
        buffer.extend_from_slice(&[0x71, name_len]);
        buffer.extend_from_slice(name);
        buffer.extend_from_slice(&[0x74, challenge_len]);
        buffer.extend_from_slice(challenge);

        let mid = buffer.len();
        buffer.resize(mid + MAX_BUFFER_SIZE, 0);
        let (send, recv) = buffer.split_at_mut(mid);

        let recv = self.card.transmit(send, recv)?;
        // TODO: handle the case of AuthRequired.
        let mut parser = parse_recv(recv)?;
        let response = parser(0x75)?;
        Ok((response[0], &response[1..]))
    }
}

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

fn parse_recv<'a>(
    mut recv: &'a [u8],
) -> Result<impl 'a + FnMut(u8) -> Result<&'a [u8], Error>, Error> {
    let code = recv
        .get(recv.len().wrapping_sub(2)..)
        .ok_or(Error::InsufficientData)?;
    recv = &recv[..recv.len().wrapping_sub(2)];

    match code {
        &[0x90, 0x00] => Ok(move |expected_tag| {
            let tag = *recv.get(0).ok_or(Error::InsufficientData)?;
            if tag == expected_tag {
                let len = *recv.get(1).ok_or(Error::InsufficientData)? as usize;
                let data = recv.get(2..2 + len).ok_or(Error::InsufficientData)?;
                recv = &recv[2 + len..];
                Ok(data)
            } else {
                Err(Error::UnexpectedTag(tag))
            }
        }),
        &[0x6a, 0x84] => Err(Error::NoSpace),
        &[0x69, 0x84] => Err(Error::NoSuchObject),
        &[0x69, 0x82] => Err(Error::AuthRequired),
        &[0x6a, 0x80] => Err(Error::WrongSyntax),
        &[0x65, 0x81] => Err(Error::GenericError),
        _ => Err(Error::Unknown(unsafe { *(code.as_ptr() as *const _) })),
    }
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
