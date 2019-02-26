mod apdu_request;
mod apdu_response;
mod error;

use self::apdu_request::ApduRequest;
use self::apdu_response::ApduResponse;
use self::error::check_code;
pub use self::error::Error;
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

    pub fn select<'a>(&self, buf: &'a mut Vec<u8>) -> Result<SelectResponse<'a>, Error> {
        let mut apdu_res = ApduRequest::new(0x00, 0xa4, 0x04, 0x00, buf)
            .push_aid([0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
            .transmit(&self.card)?;
        let version = apdu_res.pop(0x79)?;
        let name = apdu_res.pop(0x71)?;
        let challenge = if apdu_res.is_empty() {
            None
        } else {
            let challenge = apdu_res.pop(0x74)?;
            let algorithm = apdu_res.pop(0x7b).and_then(|a| match a.len() {
                1 => Ok(a[0]),
                len => Err(Error::UnexpectedLength(len as _)),
            })?;
            Some(ChallengeWithAlgorithm {
                challenge,
                algorithm,
            })
        };
        Ok(SelectResponse {
            version,
            name,
            challenge,
        })
    }

    pub fn calculate<'a>(
        &self,
        truncate: bool,
        name: &[u8],
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<CalculateResponse<'a>, Error> {
        let mut apdu_res =
            ApduRequest::new(0x00, 0xa2, 0x00, if truncate { 0x01 } else { 0x00 }, buf)
                .push(0x71, name)
                .push(0x74, challenge)
                .transmit(&self.card)?;
        let response = pop_response_with_digits(&mut apdu_res, truncate)?;
        Ok(CalculateResponse { response })
    }

    pub fn calculate_all<'a>(
        &self,
        truncate: bool,
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<impl 'a + Iterator<Item = Result<CalculateAllResponse<'a>, Error>>, Error> {
        let apdu_res = ApduRequest::new(0x00, 0xa4, 0x00, if truncate { 0x01 } else { 0x00 }, buf)
            .push(0x74, challenge)
            .transmit(&self.card)?;
        Ok(iter::repeat(()).scan(apdu_res, move |apdu_res, _| {
            if apdu_res.is_empty() {
                None
            } else {
                Some(apdu_res.pop(0x71).and_then(|name| {
                    let response = pop_response_with_digits(apdu_res, truncate)
                        .map(ResponseWithTag::Response)
                        .or_else(|_| apdu_res.pop(0x77).map(|_| ResponseWithTag::HOTP))
                        .or_else(|_| apdu_res.pop(0x7c).map(|_| ResponseWithTag::Touch))?;
                    Ok(CalculateAllResponse { name, response })
                }))
            }
        }))
    }
}

#[derive(Debug)]
pub struct ChallengeWithAlgorithm<'a> {
    pub challenge: &'a [u8],
    pub algorithm: u8,
}

#[derive(Debug)]
pub struct ResponseWithDigits<'a> {
    pub digits: u8,
    pub response: &'a [u8],
}

#[derive(Debug)]
pub enum ResponseWithTag<'a> {
    HOTP,
    Touch,
    Response(ResponseWithDigits<'a>),
}

#[derive(Debug)]
pub struct SelectResponse<'a> {
    pub version: &'a [u8],
    pub name: &'a [u8],
    pub challenge: Option<ChallengeWithAlgorithm<'a>>,
}

#[derive(Debug)]
pub struct CalculateResponse<'a> {
    pub response: ResponseWithDigits<'a>,
}

#[derive(Debug)]
pub struct CalculateAllResponse<'a> {
    pub name: &'a [u8],
    pub response: ResponseWithTag<'a>,
}

fn pop_response_with_digits<'a>(
    apdu_res: &mut ApduResponse<'a>,
    truncate: bool,
) -> Result<ResponseWithDigits<'a>, Error> {
    apdu_res
        .pop(if truncate { 0x76 } else { 0x75 })
        .and_then(|r| {
            Ok(ResponseWithDigits {
                digits: *r.get(0).ok_or(Error::InsufficientData)?,
                response: r.get(1..).ok_or(Error::InsufficientData)?,
            })
        })
}
