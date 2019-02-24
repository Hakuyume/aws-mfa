mod error;
mod request;
mod response;

use self::error::check_code;
pub use self::error::Error;
use self::request::Request;
use self::response::Response;
pub use pcsc;
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use std::iter;

pub struct Yubikey {
    card: Card,
}

impl Yubikey {
    pub fn connect(buf: &mut Vec<u8>) -> Result<Self, Error> {
        let context = Context::establish(Scope::User)?;
        Self::connect_with(&context, buf)
    }

    pub fn connect_with(context: &Context, buf: &mut Vec<u8>) -> Result<Self, Error> {
        const YK_READER_NAME: &str = "yubico yubikey";

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

    pub fn select<'a>(
        &self,
        buf: &'a mut Vec<u8>,
    ) -> Result<(&'a [u8], &'a [u8], Option<(&'a [u8], &'a [u8])>), Error> {
        let mut res = Request::new(0x00, 0xa4, 0x04, 0x00, buf)
            .push_aid([0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
            .transmit(&self.card)?;
        let version = res.pop(0x79)?;
        let name = res.pop(0x71)?;
        let authentication = if res.is_empty() {
            None
        } else {
            let challenge = res.pop(0x74)?;
            let algorithm = res.pop(0x7b)?;
            Some((challenge, algorithm))
        };
        Ok((version, name, authentication))
    }

    pub fn calculate<'a>(
        &self,
        truncate: bool,
        name: &[u8],
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<(u8, &'a [u8]), Error> {
        let mut res = Request::new(0x00, 0xa2, 0x00, if truncate { 0x01 } else { 0x00 }, buf)
            .push(0x71, name)
            .push(0x74, challenge)
            .transmit(&self.card)?;
        let r = res.pop(if truncate { 0x76 } else { 0x75 })?;
        Ok((
            *r.get(0).ok_or(Error::InsufficientData)?,
            r.get(1..).ok_or(Error::InsufficientData)?,
        ))
    }

    pub fn calculate_all<'a>(
        &self,
        truncate: bool,
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<impl 'a + Iterator<Item = Result<(&'a [u8], CalculateAllResponse<'a>), Error>>, Error>
    {
        let res = Request::new(0x00, 0xa4, 0x00, if truncate { 0x01 } else { 0x00 }, buf)
            .push(0x74, challenge)
            .transmit(&self.card)?;
        Ok(iter::repeat(()).scan(res, move |res, _| {
            if res.is_empty() {
                None
            } else {
                Some(res.pop(0x71).and_then(|name| {
                    let r = res
                        .pop(if truncate { 0x76 } else { 0x75 })
                        .and_then(|r| {
                            Ok(CalculateAllResponse::Response(
                                *r.get(0).ok_or(Error::InsufficientData)?,
                                r.get(1..).ok_or(Error::InsufficientData)?,
                            ))
                        })
                        .or_else(|_| res.pop(0x77).map(|_| CalculateAllResponse::HOTP))
                        .or_else(|_| res.pop(0x7c).map(|_| CalculateAllResponse::Touch))?;
                    Ok((name, r))
                }))
            }
        }))
    }
}

#[derive(Debug)]
pub enum CalculateAllResponse<'a> {
    Response(u8, &'a [u8]),
    HOTP,
    Touch,
}
