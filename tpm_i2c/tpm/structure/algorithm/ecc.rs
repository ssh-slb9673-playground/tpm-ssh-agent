use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::Tpm2BEccParameter;
use crate::tpm::{FromTpm, ToTpm};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmsEccPoint {
    pub x: Tpm2BEccParameter,
    pub y: Tpm2BEccParameter,
}

impl_to_tpm! {
    TpmsEccPoint(self) {
        [self.x.to_tpm(), self.y.to_tpm()].concat()
    }
}

impl_from_tpm! {
    TpmsEccPoint(v) {
        let (x, v) = Tpm2BEccParameter::from_tpm(v)?;
        let (y, v) = Tpm2BEccParameter::from_tpm(v)?;
        Ok((TpmsEccPoint { x, y }, v))
    }
}
