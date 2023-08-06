use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_from_tpm_with_selector, impl_to_tpm};
use crate::tpm::structure::{
    Tpm2BEccParameter, Tpm2BPublicKeyRsa, TpmAlgorithm, TpmiAlgorithmAsymmetricScheme,
    TpmiAlgorithmHash, TpmiAlgorithmSigScheme, TpmsEmpty, TpmsSchemeHash,
};
use crate::tpm::{FromTpm, FromTpmWithSelector, ToTpm};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmtSignature {
    pub signature_algorithm: TpmiAlgorithmSigScheme,
    pub details: TpmuSignature,
}

#[derive(Debug)]
pub struct TpmsSignatureRsa {
    pub hash_algorithm: TpmiAlgorithmHash,
    pub signature: Tpm2BPublicKeyRsa,
}

#[derive(Debug)]
pub struct TpmsSignatureEcc {
    pub hash_algorithm: TpmiAlgorithmHash,
    pub signature_r: Tpm2BEccParameter,
    pub signature_s: Tpm2BEccParameter,
}

#[derive(Debug)]
pub enum TpmuSignature {
    Rsa(TpmsSignatureRsa),
    Ecc(TpmsSignatureEcc),
    Hmac(TpmsEmpty), // TPMT_HA is not implemented yet
    Any(TpmsSchemeHash),
    Null,
}

impl_to_tpm! {
    TpmsSignatureRsa(self) {
        [
            self.hash_algorithm.to_tpm(),
            self.signature.to_tpm(),
        ].concat()
    }

    TpmsSignatureEcc(self) {
        [
            self.hash_algorithm.to_tpm(),
            self.signature_r.to_tpm(),
            self.signature_s.to_tpm(),
        ].concat()
    }

    TpmtSignature(self) {
        [
            self.signature_algorithm.to_tpm(),
            self.details.to_tpm(),
        ].concat()
    }

    TpmuSignature(self) {
        match self {
            TpmuSignature::Rsa(scheme) => scheme.to_tpm(),
            TpmuSignature::Ecc(scheme) => scheme.to_tpm(),
            TpmuSignature::Hmac(scheme) => todo!(),
            TpmuSignature::Any(scheme) => scheme.to_tpm(),
            TpmuSignature::Null => vec![],
        }
    }
}

impl_from_tpm! {
    TpmsSignatureRsa(v) {
        let (hash_algorithm, v) = TpmiAlgorithmHash::from_tpm(v)?;
        let (signature, v) = Tpm2BPublicKeyRsa::from_tpm(v)?;
        Ok((TpmsSignatureRsa {
            hash_algorithm,
            signature
        }, v))
    }

    TpmsSignatureEcc(v) {
        let (hash_algorithm, v) = TpmiAlgorithmHash::from_tpm(v)?;
        let (signature_r, v) = Tpm2BEccParameter::from_tpm(v)?;
        let (signature_s, v) = Tpm2BEccParameter::from_tpm(v)?;
        Ok((TpmsSignatureEcc {
            hash_algorithm,
            signature_r,
            signature_s
        }, v))
    }

    TpmtSignature(v) {
        let (signature_algorithm, v) = TpmiAlgorithmSigScheme::from_tpm(v)?;
        let (details, v) = TpmuSignature::from_tpm(v, &signature_algorithm)?;

        Ok((TpmtSignature{
            signature_algorithm,
            details,
        }, v))
    }
}

impl_from_tpm_with_selector! {
    TpmuSignature<TpmiAlgorithmSigScheme>(v, selector) {
        let t = selector.get_type();
        let selector_asym : TpmiAlgorithmAsymmetricScheme =
            num_traits::FromPrimitive::from_u32(
                num_traits::ToPrimitive::to_u32(selector).unwrap()
            ).unwrap();
        Ok(if selector == &TpmiAlgorithmSigScheme::RsaSsa
                || selector == &TpmiAlgorithmSigScheme::RsaPss {
            let (scheme, v) = TpmsSignatureRsa::from_tpm(v)?;
            (TpmuSignature::Rsa(scheme), v)
        } else if selector == &TpmiAlgorithmSigScheme::EcDsa
                || selector == &TpmiAlgorithmSigScheme::EcDaa
                || selector == &TpmiAlgorithmSigScheme::EcSchnorr {
            let (scheme, v) = TpmsSignatureEcc::from_tpm(v)?;
            (TpmuSignature::Ecc(scheme), v)
        } else if selector == &TpmiAlgorithmSigScheme::Hmac {
            // unimplemented now
            todo!();
        } else {
            // TPMU_SIG_SCHEME::Any doesn't belongs to any selector
            (TpmuSignature::Null, v)
        })
    }
}
