mod error;
mod request;

use self::error::check_code;
pub use self::error::Error;
use self::request::Request;
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

    pub fn select<'a>(&self, buf: &'a mut Vec<u8>) -> Result<(&'a [u8], &'a [u8]), Error> {
        let recv = Request::new(0x00, 0xa4, 0x04, 0x00, buf)
            .push_aid(&[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
            .transmit(&self.card)?;
        // TODO: handle the case of AuthRequired.
        let mut parser = parse_recv(recv)?;
        let version = parser(0x79)?;
        let name = parser(0x71)?;
        Ok((version, name))
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
    {
        let code = recv
            .get(recv.len().wrapping_sub(2)..)
            .ok_or(Error::InsufficientData)?;
        check_code(u16::from_be(unsafe { *(code.as_ptr() as *const _) }))?;
        recv = &recv[..recv.len().wrapping_sub(2)];
    }

    Ok(move |expected_tag| {
        let tag = *recv.get(0).ok_or(Error::InsufficientData)?;
        if tag == expected_tag {
            let len = *recv.get(1).ok_or(Error::InsufficientData)? as usize;
            let data = recv.get(2..2 + len).ok_or(Error::InsufficientData)?;
            recv = &recv[2 + len..];
            Ok(data)
        } else {
            Err(Error::UnexpectedTag(tag))
        }
    })
}
