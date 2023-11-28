use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::TpmError;
use crate::tpm::{FromTpm, ToTpm};
use crate::util::{p16be, p32be, u16be, u32be};
use crate::TpmResult;

macro_rules! define_tpm_codec {
    ($name:ty, $enc:path, $dec:path, $len: expr) => {
        impl ToTpm for $name {
            fn to_tpm(&self) -> Vec<u8> {
                $enc(*self).to_vec()
            }
        }

        impl FromTpm for $name {
            fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
                if v.len() < $len {
                    return Err(TpmError::create_parse_error("length mismatch").into());
                }
                Ok(($dec(&v[0..$len]), &v[$len..]))
            }
        }
    };
}

impl_to_tpm! {
    u8(self) {
        vec![*self]
    }

    TpmsEmpty(self) {
        vec![]
    }
}

impl_from_tpm! {
    u8(v) {
        if v.is_empty() {
            return Err(TpmError::create_parse_error("length mismatch").into());
        }
        Ok((v[0], &v[1..]))
    }

    TpmsEmpty(v) {
        Ok((TpmsEmpty {}, v))
    }
}

define_tpm_codec!(u16, p16be, u16be, 2);
define_tpm_codec!(u32, p32be, u32be, 4);

#[derive(Debug, Default, Clone)]
pub struct TpmsEmpty;

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
