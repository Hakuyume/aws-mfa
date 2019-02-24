mod error;
mod request;

pub use self::error::Error;
use self::request::Request;
use log::info;
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

pub struct Yubikey {
    card: Card,
}

impl Yubikey {
    pub fn connect(buf: &mut Vec<u8>) -> Result<Self, Error> {
        let context = Context::establish(Scope::User)?;
        Self::connect_with(&context, buf)
    }

    pub fn connect_with(context: &Context, buf: &mut Vec<u8>) -> Result<Self, Error> {
        const YK_READER_NAME: &'static str = "yubico yubikey";

        unsafe {
            let len = context.list_readers_len()?;
            buf.clear();
            buf.reserve(len);
            buf.set_len(len);
        }
        let reader = context
            .list_readers(buf)?
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

    pub fn select(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        let recv = Request::new(0x00, 0xa4, 0x04, 0x00, buf)
            .push_aid(&[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
            .transmit(&self.card)?;
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
        buf: &'a mut Vec<u8>,
    ) -> Result<(u8, &'a [u8]), Error> {
        let recv = Request::new(0x00, 0xa2, 0x00, 0x00, buf)
            .push(0x71, name.as_bytes())
            .push(0x74, challenge)
            .transmit(&self.card)?;
        // TODO: handle the case of AuthRequired.
        let mut parser = parse_recv(recv)?;
        let response = parser(0x75)?;
        Ok((response[0], &response[1..]))
    }
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
