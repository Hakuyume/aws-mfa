use super::{check_code, Error};

pub struct Response<'a>(&'a [u8]);

impl<'a> Response<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        let code = buf
            .get(buf.len().wrapping_sub(2)..)
            .ok_or(Error::InsufficientData)?;
        check_code(u16::from_be(unsafe { *(code.as_ptr() as *const _) }))?;
        Ok(Self(&buf[..buf.len().wrapping_sub(2)]))
    }

    pub fn pop(&mut self, expected_tag: u8) -> Result<&'a [u8], Error> {
        let tag = *self.0.get(0).ok_or(Error::InsufficientData)?;
        if tag == expected_tag {
            let len = *self.0.get(1).ok_or(Error::InsufficientData)? as usize;
            let data = self.0.get(2..2 + len).ok_or(Error::InsufficientData)?;
            self.0 = &self.0[2 + len..];
            Ok(data)
        } else {
            Err(Error::UnexpectedTag(tag))
        }
    }
}
