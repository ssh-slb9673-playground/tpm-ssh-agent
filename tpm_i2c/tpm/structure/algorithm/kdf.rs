use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_from_tpm_with_selector, impl_to_tpm};
use crate::tpm::structure::{TpmAlgorithm, TpmAlgorithmType, TpmiAlgorithmHash, TpmiAlgorithmKdf};
use crate::tpm::{FromTpm, FromTpmWithSelector, ToTpm, TpmResult};
use std::collections::HashSet;

#[derive(Debug)]
pub struct TpmtKdfScheme {
    pub scheme: TpmiAlgorithmKdf,
    pub details: TpmuKdfScheme,
}

#[derive(Debug)]
pub enum TpmuKdfScheme {
    HM(TpmiAlgorithmHash),
    Null,
}

impl_to_tpm! {
    TpmuKdfScheme(self) {
        match self {
            Self::HM(algorithm_hash) => algorithm_hash.to_tpm(),
            Self::Null => vec![]
        }
    }

    TpmtKdfScheme(self) {
        [
            self.scheme.to_tpm(),
            self.details.to_tpm(),
        ].concat()
    }
}

impl_from_tpm! {
    TpmtKdfScheme(v) {
        let (scheme, v) = TpmiAlgorithmKdf::from_tpm(v)?;
        let (details, v) = TpmuKdfScheme::from_tpm(v, &scheme)?;
        Ok((TpmtKdfScheme {
            scheme,
            details,
        }, v))
    }
}

impl_from_tpm_with_selector! {
    TpmuKdfScheme<TpmiAlgorithmKdf>(v, selector) {
        Ok(if selector.get_type() == HashSet::from([TpmAlgorithmType::Hash, TpmAlgorithmType::MaskGeneration]) {
            let (algorithm_hash, v) = TpmiAlgorithmHash::from_tpm(v)?;
            (Self::HM(algorithm_hash), v)
        } else {
            (Self::Null, v)
        })
    }
}
