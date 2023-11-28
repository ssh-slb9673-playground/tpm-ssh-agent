use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::{
    TpmiAlgorithmAsymmetricScheme, TpmiAlgorithmRsaScheme, TpmuAsymmetricScheme,
};
use crate::tpm::{FromTpm, FromTpmWithSelector, ToTpm};
use crate::TpmResult;

#[derive(Debug, Clone)]
pub struct TpmtRsaScheme {
    pub scheme: TpmiAlgorithmRsaScheme,
    pub details: TpmuAsymmetricScheme,
}

impl_to_tpm! {
    TpmtRsaScheme(self) {
        [
            self.scheme.to_tpm(),
            self.details.to_tpm(),
        ].concat()
    }
}

impl_from_tpm! {
    TpmtRsaScheme(v) {
        let (scheme, v) = TpmiAlgorithmRsaScheme::from_tpm(v)?;
        let scheme_asym : TpmiAlgorithmAsymmetricScheme =
            num_traits::FromPrimitive::from_u32(
                num_traits::ToPrimitive::to_u32(&scheme).unwrap()
            ).unwrap();
        let (details, v) = TpmuAsymmetricScheme::from_tpm(v, &scheme_asym)?;

        Ok((TpmtRsaScheme {
            scheme,
            details,
        }, v))
    }
}
