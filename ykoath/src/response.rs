use super::Error;

pub(crate) struct Response<'a>(pub(crate) &'a [u8]);

impl<'a> Response<'a> {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn pop(&mut self, expected_tag: u8) -> Result<&'a [u8], Error> {
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
