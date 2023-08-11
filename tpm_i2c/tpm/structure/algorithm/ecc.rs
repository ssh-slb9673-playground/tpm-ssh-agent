use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::{
    Tpm2BEccParameter, TpmiAlgorithmAsymmetricScheme, TpmiAlgorithmEccScheme, TpmuAsymmetricScheme,
};
use crate::tpm::{FromTpm, FromTpmWithSelector, ToTpm};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmsEccPoint {
    pub x: Tpm2BEccParameter,
    pub y: Tpm2BEccParameter,
}

#[derive(Debug)]
pub struct TpmtEccScheme {
    pub scheme: TpmiAlgorithmEccScheme,
    pub details: TpmuAsymmetricScheme,
}

impl_to_tpm! {
    TpmsEccPoint(self) {
        [self.x.to_tpm(), self.y.to_tpm()].concat()
    }

    TpmtEccScheme(self) {
        [self.scheme.to_tpm(), self.details.to_tpm()].concat()
    }
}

impl_from_tpm! {
    TpmsEccPoint(v) {
        let (x, v) = Tpm2BEccParameter::from_tpm(v)?;
        let (y, v) = Tpm2BEccParameter::from_tpm(v)?;
        Ok((TpmsEccPoint { x, y }, v))
    }

    TpmtEccScheme(v) {
        let (scheme, v) = TpmiAlgorithmEccScheme::from_tpm(v)?;
        let scheme_asym : TpmiAlgorithmAsymmetricScheme =
            num_traits::FromPrimitive::from_u32(
                num_traits::ToPrimitive::to_u32(&scheme).unwrap()
            ).unwrap();
        let (details, v) = TpmuAsymmetricScheme::from_tpm(v, &scheme_asym)?;

        Ok((TpmtEccScheme {
            scheme, details
        }, v))
    }
}
