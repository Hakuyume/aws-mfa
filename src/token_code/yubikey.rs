mod error;
mod request;
mod response;

use self::error::check_code;
pub use self::error::Error;
use self::request::Request;
use self::response::Response;
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

    pub fn select<'a>(
        &self,
        buf: &'a mut Vec<u8>,
    ) -> Result<(&'a [u8], &'a [u8], Option<(&'a [u8], &'a [u8])>), Error> {
        let mut res = Request::new(0x00, 0xa4, 0x04, 0x00, buf)
            .push_aid(&[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
            .transmit(&self.card)?;
        let version = res.pop(0x79)?;
        let name = res.pop(0x71)?;
        if res.is_empty() {
            Ok((version, name, None))
        } else {
            let challenge = res.pop(0x74)?;
            let algorithm = res.pop(0x7b)?;
            Ok((version, name, Some((challenge, algorithm))))
        }
    }

    pub fn calculate<'a>(
        &self,
        name: &str,
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<(u8, &'a [u8]), Error> {
        let mut res = Request::new(0x00, 0xa2, 0x00, 0x00, buf)
            .push(0x71, name.as_bytes())
            .push(0x74, challenge)
            .transmit(&self.card)?;
        let response = res.pop(0x75)?;
        Ok((response[0], &response[1..]))
    }
}
