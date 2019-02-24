use super::{check_code, Error, Response};
use pcsc::{Card, MAX_BUFFER_SIZE};

pub(crate) struct Request<'a>(&'a mut Vec<u8>);

impl<'a> Request<'a> {
    pub(crate) fn new(cla: u8, ins: u8, p1: u8, p2: u8, buf: &'a mut Vec<u8>) -> Self {
        buf.clear();
        buf.extend_from_slice(&[cla, ins, p1, p2]);
        Self(buf)
    }

    pub(crate) fn push_aid(self, aid: [u8; 7]) -> Self {
        if self.0.len() < 5 {
            self.0.push(0x00);
        }
        self.0.extend_from_slice(&aid);
        self
    }

    pub(crate) fn push(self, tag: u8, data: &[u8]) -> Self {
        if self.0.len() < 5 {
            self.0.push(0x00);
        }
        self.0.push(tag);
        self.0.push(data.len() as _);
        self.0.extend_from_slice(data);
        self
    }

    pub(crate) fn transmit(self, card: &Card) -> Result<Response<'a>, Error> {
        if self.0.len() >= 5 {
            self.0[4] = (self.0.len() - 5) as _;
        }
        let mid = self.0.len();

        let mut remain = true;
        while remain {
            let offset = self.0.len() - mid;
            unsafe {
                self.0.reserve(MAX_BUFFER_SIZE);
                self.0.set_len(self.0.len() + MAX_BUFFER_SIZE);
            }
            let (send, recv) = self.0.split_at_mut(mid);
            let recv = card.transmit(
                if offset == 0 {
                    send
                } else {
                    &[0x00, 0xa5, 0x00, 0x00]
                },
                &mut recv[offset..],
            )?;
            let code = u16::from_be_bytes(unsafe {
                *(recv
                    .get(recv.len().wrapping_sub(2)..)
                    .ok_or(Error::InsufficientData)?
                    .as_ptr() as *const _)
            });
            remain = check_code(code)?;
            let recv_len = recv.len();
            self.0.truncate(mid + offset + recv_len - 2);
        }
        Ok(Response(&self.0[mid..]))
    }
}
