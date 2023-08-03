use crate::tpm::structure::Tpm2BEccParameter;
use crate::tpm::TpmData;
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmsEccPoint {
    pub x: Tpm2BEccParameter,
    pub y: Tpm2BEccParameter,
}

impl TpmData for TpmsEccPoint {
    fn to_tpm(&self) -> Vec<u8> {
        [self.x.to_tpm(), self.y.to_tpm()].concat()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (x, v) = Tpm2BEccParameter::from_tpm(v)?;
        let (y, v) = Tpm2BEccParameter::from_tpm(v)?;
        Ok((TpmsEccPoint { x, y }, v))
    }
}
