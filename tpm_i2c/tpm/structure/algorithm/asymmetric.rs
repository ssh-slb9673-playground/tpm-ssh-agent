use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_from_tpm_with_selector, impl_to_tpm};
use crate::tpm::structure::{
    TpmAlgorithm, TpmAlgorithmType, TpmiAlgorithmAsymmetricScheme, TpmiAlgorithmSigScheme,
    TpmsSchemeHash, TpmsSchemeHmac, TpmsSignatureScheme,
};
use crate::tpm::{FromTpm, FromTpmWithSelector, ToTpm};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmtSignatureScheme {
    pub scheme: TpmiAlgorithmSigScheme,
    pub details: TpmsSignatureScheme,
}

#[derive(Debug)]
pub enum TpmuSignatureScheme {
    AX(TpmsSignatureScheme),
    Hmac(TpmsSchemeHmac),
    Any(TpmsSchemeHash),
    Null,
}

impl_to_tpm! {
    TpmtSignatureScheme(self) {
        [
            self.scheme.to_tpm(),
            self.details.to_tpm(),
        ].concat()
    }

    TpmuSignatureScheme(self) {
        match self {
            TpmuSignatureScheme::AX(scheme) => scheme.to_tpm(),
            TpmuSignatureScheme::Hmac(scheme) => scheme.to_tpm(),
            TpmuSignatureScheme::Any(scheme) => scheme.to_tpm(),
            TpmuSignatureScheme::Null => vec![],
        }
    }
}

impl_from_tpm! {
    TpmtSignatureScheme(v) {
        let (scheme, v) = TpmiAlgorithmSigScheme::from_tpm(v)?;
        let scheme_asym : TpmiAlgorithmAsymmetricScheme =
            num_traits::FromPrimitive::from_u32(
                num_traits::ToPrimitive::to_u32(&scheme).unwrap()
            ).unwrap();
        let (details, v) = TpmsSignatureScheme::from_tpm(v, &scheme_asym)?;

        Ok((TpmtSignatureScheme {
            scheme,
            details,
        }, v))
    }
}

impl_from_tpm_with_selector! {
    TpmuSignatureScheme<TpmiAlgorithmSigScheme>(v, selector) {
        let t = selector.get_type();
        let selector_asym : TpmiAlgorithmAsymmetricScheme =
            num_traits::FromPrimitive::from_u32(
                num_traits::ToPrimitive::to_u32(selector).unwrap()
            ).unwrap();
        Ok(if t.contains(&TpmAlgorithmType::Asymmetric) && t.contains(&TpmAlgorithmType::Signing) {
            let (scheme, v) = TpmsSignatureScheme::from_tpm(v, &selector_asym)?;
            (TpmuSignatureScheme::AX(scheme), v)
        } else if selector == &TpmiAlgorithmSigScheme::Hmac {
            let (scheme, v) = TpmsSchemeHmac::from_tpm(v)?;
            (TpmuSignatureScheme::Hmac(scheme), v)
        } else {
            // TPMU_SIG_SCHEME::Any doesn't belongs to any selector
            (TpmuSignatureScheme::Null, v)
        })
    }
}
