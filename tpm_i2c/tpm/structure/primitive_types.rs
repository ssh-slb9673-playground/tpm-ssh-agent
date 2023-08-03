use crate::tpm::TpmData;
use crate::tpm::TpmError;
use crate::util::{p16be, p32be, u16be, u32be};
use crate::TpmResult;

macro_rules! define_tpm_codec {
    ($name:ty, $enc:path, $dec:path, $len: expr) => {
        impl TpmData for $name {
            fn to_tpm(&self) -> Vec<u8> {
                $enc(*self).to_vec()
            }

            fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
                if v.len() < $len {
                    return Err(TpmError::create_parse_error("length mismatch").into());
                }
                Ok(($dec(&v[0..$len]), &v[$len..]))
            }
        }
    };
}
impl TpmData for u8 {
    fn to_tpm(&self) -> Vec<u8> {
        vec![*self]
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        if v.is_empty() {
            return Err(TpmError::create_parse_error("length mismatch").into());
        }
        Ok((v[0], &v[1..]))
    }
}

define_tpm_codec!(u16, p16be, u16be, 2);
define_tpm_codec!(u32, p32be, u32be, 4);

#[derive(Debug)]
pub struct TpmsEmpty;

impl TpmData for TpmsEmpty {
    fn to_tpm(&self) -> Vec<u8> {
        vec![]
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        Ok((TpmsEmpty {}, v))
    }
}

impl TpmsEmpty {
    pub fn new() -> Self {
        TpmsEmpty {}
    }
}

pub type TpmModifierIndicator = u32;
pub type TpmAuthorizationSize = u32;
pub type TpmParameterSize = u32;
pub type TpmKeySize = u16;
pub type TpmKeyBits = u16;
