use crate::tpm::TpmData;
use crate::tpm::TpmError;
use crate::util::{p16be, u16be};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmUint16 {
    pub value: u16,
}

impl TpmUint16 {
    pub fn new(value: u16) -> Self {
        TpmUint16 { value }
    }
}

impl TpmData for TpmUint16 {
    fn to_tpm(&self) -> Vec<u8> {
        p16be(self.value).to_vec()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        if v.len() < 2 {
            return Err(TpmError::Parse.into());
        }
        Ok((TpmUint16::new(u16be(&v[0..2])), &v[2..]))
    }
}
