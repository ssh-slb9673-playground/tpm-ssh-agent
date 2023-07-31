use crate::tpm::TpmData;
use crate::tpm::TpmError;
use crate::util::{p16be, u16be};
use crate::TpmResult;

#[derive(Debug, Clone)]
pub struct Tpm2BDigest {
    pub buffer: Vec<u8>,
}

impl TpmData for Tpm2BDigest {
    fn to_tpm(&self) -> Vec<u8> {
        [&p16be(self.buffer.len() as u16), self.buffer.as_slice()].concat()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        if v.len() < 2 {
            return Err(TpmError::Parse.into());
        }
        let len = u16be(&v[0..2]) as usize;
        Ok((
            Tpm2BDigest {
                buffer: v[2..(2 + len)].to_vec(),
            },
            &v[(2 + len)..],
        ))
    }
}

impl Tpm2BDigest {
    pub fn new(v: &[u8]) -> Tpm2BDigest {
        Tpm2BDigest { buffer: v.to_vec() }
    }
}

pub type Tpm2BNonce = Tpm2BDigest;
pub type Tpm2BAuth = Tpm2BDigest;
