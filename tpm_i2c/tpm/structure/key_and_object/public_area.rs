use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_from_tpm_with_selector, impl_to_tpm};
use crate::tpm::structure::{
    Tpm2BDigest, Tpm2BPublicKeyRsa, TpmAlgorithm, TpmAlgorithmType, TpmAttrObject, TpmKeyBits,
    TpmiAlgorithmAsymmetricScheme, TpmiAlgorithmHash, TpmiAlgorithmPublic, TpmiEccCurve,
    TpmsEccPoint, TpmsEmpty, TpmsSymcipherParams, TpmtEccScheme, TpmtKdfScheme, TpmtRsaScheme,
    TpmtSymdefObject,
};
use crate::tpm::{FromTpm, FromTpmWithSelector, ToTpm, TpmError};
use crate::util::{p16be, u16be};
use crate::TpmResult;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Tpm2BPublic {
    pub public_area: Option<TpmtPublic>,
}

#[derive(Debug, Clone)]
pub struct TpmtPublic {
    pub algorithm_type: TpmiAlgorithmPublic,
    pub algorithm_name: TpmiAlgorithmHash,
    pub object_attributes: TpmAttrObject,
    pub auth_policy: Tpm2BDigest,
    pub parameters: TpmuPublicParams,
    pub unique: TpmuPublicIdentifier,
}

#[derive(Debug, Clone)]
pub enum TpmuPublicParams {
    // keydeHashDetail
    SymDetail(TpmsSymcipherParams),
    RsaDetail(TpmsRsaParams),
    EccDetail(TpmsEccParams),
}

#[derive(Debug, Clone)]
pub struct TpmsEccParams {
    pub symmetric: TpmtSymdefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmiEccCurve,
    pub kdf: TpmtKdfScheme,
}

#[derive(Debug, Clone)]
pub struct TpmtPublicParams {
    pub algorithm_type: TpmiAlgorithmPublic,
    pub parameters: TpmuPublicParams,
}

#[derive(Debug, Clone)]
pub enum TpmuPublicIdentifier {
    Sym(Tpm2BDigest),
    Rsa(Tpm2BPublicKeyRsa),
    Ecc(TpmsEccPoint),
    // TODO: to be implement
    // KeyedHash(Tpm2BDigest),
    // Derive(TpmsDerive),
}

#[derive(Debug, Clone)]
pub struct TpmsAsymmetricParams {
    pub symmetric: TpmtSymdefObject,
    pub scheme: TpmtAsymmetricScheme,
}

#[derive(Debug, Clone)]
pub struct TpmsRsaParams {
    pub symmetric: TpmtSymdefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmKeyBits,
    pub exponent: u32,
}

#[derive(Debug, Clone)]
pub struct TpmtAsymmetricScheme {
    pub scheme: TpmiAlgorithmAsymmetricScheme,
    pub details: TpmuAsymmetricScheme,
}

#[derive(Debug, Clone)]
pub struct TpmsSchemeHash {
    pub hash_algorithm: TpmiAlgorithmHash,
}

pub type TpmsKeyScheme = TpmsSchemeHash;

#[derive(Debug, Clone)]
pub enum TpmuAsymmetricScheme {
    Kdf(TpmsKeyScheme),
    Signature(TpmsSignatureScheme),
    Encryption(TpmsEncryptionScheme),
    AnySig(TpmsSchemeHash),
    Null,
}

#[derive(Debug, Clone)]
pub enum TpmsEncryptionScheme {
    AEH(TpmsSchemeHash),
    AE(TpmsEmpty),
}

#[derive(Debug, Clone)]
pub enum TpmsSignatureScheme {
    AX(TpmsSchemeHash),
    // AXN(TpmsSchemeEcdaa),
}

impl_to_tpm! {
    Tpm2BPublic(self) {
        if let Some(public) = &self.public_area {
            let v = public.to_tpm();
            [p16be(v.len() as u16).to_vec(), v].concat()
        } else {
            vec![]
        }
    }

    TpmtPublic(self) {
        [
            self.algorithm_type.to_tpm(),
            self.algorithm_name.to_tpm(),
            self.object_attributes.to_tpm(),
            self.auth_policy.to_tpm(),
            self.parameters.to_tpm(),
            self.unique.to_tpm(),
        ]
        .concat()
    }

    TpmuPublicParams(self) {
        match self {
            Self::SymDetail(params) => params.to_tpm(),
            Self::RsaDetail(params) => params.to_tpm(),
            Self::EccDetail(params) => params.to_tpm(),
        }
    }

    TpmtPublicParams(self) {
        [self.algorithm_type.to_tpm(), self.parameters.to_tpm()].concat()
    }

    TpmuPublicIdentifier(self) {
        match &self {
            TpmuPublicIdentifier::Sym(x) => x.to_tpm(),
            TpmuPublicIdentifier::Rsa(x) => x.to_tpm(),
            TpmuPublicIdentifier::Ecc(x) => x.to_tpm(),
        }
    }

    TpmsSchemeHash(self) {
        self.hash_algorithm.to_tpm()
    }

    TpmsEncryptionScheme(self) {
        match self {
            Self::AEH(sch) => sch.to_tpm(),
            Self::AE(sch) => sch.to_tpm(),
        }
    }

    TpmsSignatureScheme(self) {
        match self {
            Self::AX(sch) => sch.to_tpm(),
            // Self::AXN(sch) => sch.to_tpm(),
        }
    }

    TpmuAsymmetricScheme(self) {
        match self {
            Self::Kdf(sch) => sch.to_tpm(),
            Self::Signature(sch) => sch.to_tpm(),
            Self::Encryption(sch) => sch.to_tpm(),
            Self::AnySig(sch) => sch.to_tpm(),
            Self::Null => vec![],
        }
    }

    TpmsRsaParams(self) {
        [
            self.symmetric.to_tpm(),
            self.scheme.to_tpm(),
            self.key_bits.to_tpm(),
            self.exponent.to_tpm(),
        ].concat()
    }

    TpmsAsymmetricParams(self) {
        [
            self.symmetric.to_tpm(),
            self.scheme.to_tpm(),
        ].concat()
    }

    TpmtAsymmetricScheme(self) {
        [
            self.scheme.to_tpm(),
            self.details.to_tpm(),
        ].concat()
    }

    TpmsEccParams(self) {
        [
            self.symmetric.to_tpm(),
            self.scheme.to_tpm(),
            self.curve_id.to_tpm(),
            self.kdf.to_tpm(),
        ].concat()
    }
}

impl_from_tpm! {
    Tpm2BPublic(v) {
        if v.len() < 2 {
            return Err(TpmError::create_parse_error("Length mismatch").into());
        }
        let (len, v) = (u16be(&v[0..2]) as usize, &v[2..]);
        Ok(if len == 0 {
            (Tpm2BPublic {
                public_area: None
            }, v)
        } else {
            let (res, v) = TpmtPublic::from_tpm(v)?;
            (Tpm2BPublic { public_area: Some(res) }, v)
        })
    }

    TpmtPublic(v) {
        let (algorithm_type, v) = TpmiAlgorithmPublic::from_tpm(v)?;
        let (algorithm_name, v) = TpmiAlgorithmHash::from_tpm(v)?;
        let (object_attributes, v) = TpmAttrObject::from_tpm(v)?;
        let (auth_policy, v) = Tpm2BDigest::from_tpm(v)?;
        let (parameters, v) = TpmuPublicParams::from_tpm(v, &algorithm_type)?;
        let (unique, v) = TpmuPublicIdentifier::from_tpm(v, &algorithm_type)?;
        Ok((
            TpmtPublic {
                algorithm_type,
                algorithm_name,
                object_attributes,
                auth_policy,
                parameters,
                unique,
            },
            v,
        ))
    }

    TpmtPublicParams(v) {
        let (algorithm_type, v) = TpmiAlgorithmPublic::from_tpm(v)?;
        let (parameters, v) = TpmuPublicParams::from_tpm(v, &algorithm_type)?;
        Ok((
            TpmtPublicParams {
                algorithm_type,
                parameters,
            },
            v,
        ))
    }

    TpmsSchemeHash(v) {
        let (hash_algorithm, v) = TpmiAlgorithmHash::from_tpm(v)?;
        Ok((TpmsSchemeHash { hash_algorithm }, v))
    }

    TpmsRsaParams(v) {
        let (symmetric, v) = TpmtSymdefObject::from_tpm(v)?;
        let (scheme, v) = TpmtRsaScheme::from_tpm(v)?;
        let (key_bits, v) = TpmKeyBits::from_tpm(v)?;
        let (exponent, v) = u32::from_tpm(v)?;

        Ok((TpmsRsaParams {
            symmetric,
            scheme,
            key_bits,
            exponent,
        }, v))
    }

    TpmsEccParams(v) {
        let (symmetric, v) = TpmtSymdefObject::from_tpm(v)?;
        let (scheme, v) = TpmtEccScheme::from_tpm(v)?;
        let (curve_id, v) = TpmiEccCurve::from_tpm(v)?;
        let (kdf, v) = TpmtKdfScheme::from_tpm(v)?;

        Ok((TpmsEccParams {
            symmetric,
            scheme,
            curve_id,
            kdf
        }, v))
    }
}

impl_from_tpm_with_selector! {
    TpmuPublicParams<TpmiAlgorithmPublic>(v, selector) {
        let t = selector.get_type();
        if HashSet::from([TpmAlgorithmType::Symmetric]).is_subset(&t) {
            let (ret, v) = TpmsSymcipherParams::from_tpm(v)?;
            Ok((TpmuPublicParams::SymDetail(ret), v))
        } else if selector == &TpmiAlgorithmPublic::Rsa {
            let (ret, v) = TpmsRsaParams::from_tpm(v)?;
            Ok((TpmuPublicParams::RsaDetail(ret), v))
        } else if selector == &TpmiAlgorithmPublic::Ecc {
            let (ret, v) = TpmsEccParams::from_tpm(v)?;
            Ok((TpmuPublicParams::EccDetail(ret), v))
        } else {
            Err(TpmError::create_parse_error(&format!(
                "Invalid selector specified: {:?}",
                selector
            ))
            .into())
        }
    }

    TpmuPublicIdentifier<TpmiAlgorithmPublic>(v, selector) {
        Ok(match selector {
            TpmiAlgorithmPublic::Rsa => {
                let (res, v) = Tpm2BPublicKeyRsa::from_tpm(v)?;
                (TpmuPublicIdentifier::Rsa(res), v)
            }
            TpmiAlgorithmPublic::Ecc => {
                let (res, v) = TpmsEccPoint::from_tpm(v)?;
                (TpmuPublicIdentifier::Ecc(res), v)
            }
            TpmiAlgorithmPublic::SymCipher => {
                let (res, v) = Tpm2BDigest::from_tpm(v)?;
                (TpmuPublicIdentifier::Sym(res), v)
            }
            TpmiAlgorithmPublic::KeyedHash => {
                todo!();
            }
            TpmiAlgorithmPublic::Null => {
                return Err(TpmError::create_parse_error(&format!(
                    "Invalid selector specified: {:?}",
                    selector
                ))
                .into());
            }
        })
    }

    TpmsEncryptionScheme<TpmiAlgorithmAsymmetricScheme>(v, selector) {
        let types = selector.get_type();
        Ok(if selector == &TpmiAlgorithmAsymmetricScheme::Null {
            (TpmsEncryptionScheme::AE(TpmsEmpty::new()), v)
        } else if types
            == HashSet::from([
                TpmAlgorithmType::Asymmetric,
                TpmAlgorithmType::Encryption,
                TpmAlgorithmType::Hash,
            ])
        {
            let (res, v) = TpmsSchemeHash::from_tpm(v)?;
            (TpmsEncryptionScheme::AEH(res), v)
        } else {
            (TpmsEncryptionScheme::AE(TpmsEmpty::new()), v)
        })
    }

    TpmsSignatureScheme<TpmiAlgorithmAsymmetricScheme>(v, selector) {
        let types = selector.get_type();
        Ok(if selector == &TpmiAlgorithmAsymmetricScheme::Null {
            return Err(TpmError::create_parse_error(&format!(
                "Invalid selector specified: {:?}",
                selector
            ))
            .into());
        } else if types
            == HashSet::from([
                TpmAlgorithmType::Asymmetric,
                TpmAlgorithmType::Signing,
            ])
        {
            let (res, v) = TpmsSchemeHash::from_tpm(v)?;
            (TpmsSignatureScheme::AX(res), v)
        } else {
            todo!();
        })
    }

    TpmuAsymmetricScheme<TpmiAlgorithmAsymmetricScheme>(v, selector) {
        let types = selector.get_type();
        Ok(if selector == &TpmiAlgorithmAsymmetricScheme::Null {
            (TpmuAsymmetricScheme::Null, v)
        } else if types.contains(&TpmAlgorithmType::MaskGeneration) {
            let (res, v) = TpmsKeyScheme::from_tpm(v)?;
            (TpmuAsymmetricScheme::Kdf(res), v)
        } else if types.contains(&TpmAlgorithmType::Signing) {
            let (res, v) = TpmsSignatureScheme::from_tpm(v, selector)?;
            (TpmuAsymmetricScheme::Signature(res), v)
        } else if types.contains(&TpmAlgorithmType::Encryption) {
            let (res, v) = TpmsEncryptionScheme::from_tpm(v, selector)?;
            (TpmuAsymmetricScheme::Encryption(res), v)
        } else {
            return Err(TpmError::create_parse_error(&format!(
                "Invalid selector specified: {:?}",
                selector
            ))
            .into());
        })
    }
}

impl Tpm2BPublic {
    pub fn new(public_area: TpmtPublic) -> Self {
        Self {
            public_area: Some(public_area),
        }
    }

    pub fn empty() -> Self {
        Self { public_area: None }
    }
}
