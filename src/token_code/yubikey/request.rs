use pcsc::{Card, MAX_BUFFER_SIZE};

pub struct Request<'a>(&'a mut Vec<u8>);

impl<'a> Request<'a> {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, buf: &'a mut Vec<u8>) -> Self {
        buf.clear();
        buf.extend_from_slice(&[cla, ins, p1, p2]);
        Self(buf)
    }

    pub fn push_aid(self, aid: &[u8; 7]) -> Self {
        if self.0.len() < 5 {
            self.0.push(0x00);
        }
        self.0.extend_from_slice(aid);
        self
    }

    pub fn push(self, tag: u8, data: &[u8]) -> Self {
        if self.0.len() < 5 {
            self.0.push(0x00);
        }
        self.0.push(tag);
        self.0.push(data.len() as _);
        self.0.extend_from_slice(data);
        self
    }

    pub fn transmit(self, card: &Card) -> Result<&'a [u8], pcsc::Error> {
        if self.0.len() >= 5 {
            self.0[4] = (self.0.len() - 5) as _;
        }
        let mid = self.0.len();
        unsafe {
            self.0.reserve(MAX_BUFFER_SIZE);
            self.0.set_len(mid + MAX_BUFFER_SIZE);
        }
        let (send, recv) = self.0.split_at_mut(mid);
        card.transmit(send, recv)
    }
}
