use crate::tpm::structure::{
    Tpm2BDigest, Tpm2BPublicKeyRsa, TpmAlgorithm, TpmAlgorithmType, TpmAttrObject, TpmKeyBits,
    TpmiAlgorithmAsymmetricScheme, TpmiAlgorithmHash, TpmiAlgorithmPublic, TpmiAlgorithmRsaScheme,
    TpmsEccPoint, TpmsEmpty, TpmsSymcipherParams, TpmtSymdefObject,
};
use crate::tpm::{TpmData, TpmDataWithSelector, TpmError};
use crate::TpmResult;
use std::collections::HashSet;

#[derive(Debug)]
pub struct TpmtPublic {
    pub algorithm_type: TpmiAlgorithmPublic,
    pub algorithm_name: TpmiAlgorithmHash,
    pub object_attributes: TpmAttrObject,
    pub auth_policy: Tpm2BDigest,
    pub parameters: TpmuPublicParams,
    pub unique: TpmuPublicIdentifier,
}

impl TpmData for TpmtPublic {
    fn to_tpm(&self) -> Vec<u8> {
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

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
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
}

#[derive(Debug)]
pub enum TpmuPublicParams {
    // keydeHashDetail
    SymDetail(TpmsSymcipherParams),
    // RsaDetail(TpmsRsaParams, TpmsAsymParams),
    // EccDetail(TpmsEccParams, TpmsAsymParams),
}

impl TpmDataWithSelector<TpmiAlgorithmPublic> for TpmuPublicParams {
    fn to_tpm(&self) -> Vec<u8> {
        match &self {
            TpmuPublicParams::SymDetail(params) => params.to_tpm(),
        }
    }

    fn from_tpm<'a>(v: &'a [u8], selector: &TpmiAlgorithmPublic) -> TpmResult<(Self, &'a [u8])> {
        let t = selector.get_type();
        if t == HashSet::from([TpmAlgorithmType::Symmetric]) {
            let (ret, v) = TpmsSymcipherParams::from_tpm(v)?;
            Ok((TpmuPublicParams::SymDetail(ret), v))
        } else {
            Err(TpmError::create_parse_error(&format!(
                "Invalid selector specified: {:?}",
                selector
            ))
            .into())
        }
    }
}

#[derive(Debug)]
pub enum TpmuPublicIdentifier {
    Sym(Tpm2BDigest),
    Rsa(Tpm2BPublicKeyRsa),
    Ecc(TpmsEccPoint),
    // TODO: to be implement
    // KeyedHash(Tpm2BDigest),
    // Derive(TpmsDerive),
}

impl TpmDataWithSelector<TpmiAlgorithmPublic> for TpmuPublicIdentifier {
    fn to_tpm(&self) -> Vec<u8> {
        match &self {
            TpmuPublicIdentifier::Sym(v) => v.to_tpm(),
            TpmuPublicIdentifier::Rsa(v) => v.to_tpm(),
            TpmuPublicIdentifier::Ecc(v) => v.to_tpm(),
        }
    }

    fn from_tpm<'a>(v: &'a [u8], selector: &TpmiAlgorithmPublic) -> TpmResult<(Self, &'a [u8])> {
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
}

#[derive(Debug)]
pub struct TpmsRsaParams {
    pub symmetric: TpmtSymdefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmKeyBits,
    pub exponent: u32,
}

#[derive(Debug)]
pub struct TpmtRsaScheme {
    pub scheme: TpmiAlgorithmRsaScheme,
    pub details: TpmuAsymmetricScheme,
}

#[derive(Debug)]
pub struct TpmsSchemeHash {
    hash_algorithm: TpmiAlgorithmHash,
}

impl TpmData for TpmsSchemeHash {
    fn to_tpm(&self) -> Vec<u8> {
        self.hash_algorithm.to_tpm()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (hash_algorithm, v) = TpmiAlgorithmHash::from_tpm(v)?;
        Ok((TpmsSchemeHash { hash_algorithm }, v))
    }
}

pub type TpmsKeyScheme = TpmsSchemeHash;

#[derive(Debug)]
pub enum TpmuAsymmetricScheme {
    Kdf(TpmsKeyScheme),
    Signature(TpmsSignatureScheme),
    Encryption(TpmsEncryptionScheme),
    AnySig(TpmsSchemeHash),
    Null,
}

#[derive(Debug)]
pub enum TpmsEncryptionScheme {
    AEH(TpmsSchemeHash),
    AE(TpmsEmpty),
}

impl TpmDataWithSelector<TpmiAlgorithmAsymmetricScheme> for TpmsEncryptionScheme {
    fn to_tpm(&self) -> Vec<u8> {
        match self {
            Self::AEH(sch) => sch.to_tpm(),
            Self::AE(sch) => sch.to_tpm(),
        }
    }

    fn from_tpm<'a>(
        v: &'a [u8],
        selector: &TpmiAlgorithmAsymmetricScheme,
    ) -> TpmResult<(Self, &'a [u8])> {
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
}

#[derive(Debug)]
pub enum TpmsSignatureScheme {
    AX(TpmsSchemeHash),
    // AXN(TpmsSchemeEcdaa),
}

impl TpmDataWithSelector<TpmiAlgorithmAsymmetricScheme> for TpmsSignatureScheme {
    fn to_tpm(&self) -> Vec<u8> {
        match self {
            Self::AX(sch) => sch.to_tpm(),
            // Self::AXN(sch) => sch.to_tpm(),
        }
    }

    fn from_tpm<'a>(
        v: &'a [u8],
        selector: &TpmiAlgorithmAsymmetricScheme,
    ) -> TpmResult<(Self, &'a [u8])> {
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
                TpmAlgorithmType::Hash,
            ])
        {
            let (res, v) = TpmsSchemeHash::from_tpm(v)?;
            (TpmsSignatureScheme::AX(res), v)
        } else {
            todo!();
        })
    }
}

impl TpmDataWithSelector<TpmiAlgorithmAsymmetricScheme> for TpmuAsymmetricScheme {
    fn to_tpm(&self) -> Vec<u8> {
        match self {
            Self::Kdf(sch) => sch.to_tpm(),
            Self::Signature(sch) => sch.to_tpm(),
            Self::Encryption(sch) => sch.to_tpm(),
            Self::AnySig(sch) => sch.to_tpm(),
            Self::Null => vec![],
        }
    }

    fn from_tpm<'a>(
        v: &'a [u8],
        selector: &TpmiAlgorithmAsymmetricScheme,
    ) -> TpmResult<(Self, &'a [u8])> {
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
