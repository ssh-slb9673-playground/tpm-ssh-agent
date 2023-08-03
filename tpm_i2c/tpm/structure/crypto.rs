use crate::tpm::structure::{
    Tpm2BAuth, Tpm2BDigest, Tpm2BEccParameter, Tpm2BPublicKeyRsa, Tpm2BSensitiveData, TpmAlgorithm,
    TpmAlgorithmType, TpmAttrObject, TpmKeyBits, TpmiAlgorithmHash, TpmiAlgorithmPublic,
    TpmiAlgorithmSymMode, TpmiAlgorithmSymmetric,
};
use crate::tpm::{TpmData, TpmDataWithSelector, TpmError};
use crate::TpmResult;
use std::collections::HashSet;

#[derive(Debug)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2BAuth,
    pub data: Tpm2BSensitiveData,
}

#[derive(Debug)]
pub struct TpmtPublic {
    pub algorithm_type: TpmiAlgorithmPublic,
    pub algorithm_name: TpmiAlgorithmHash,
    pub object_attributes: TpmAttrObject,
    pub auth_policy: Tpm2BDigest,
    pub parameters: TpmuPublicParams,
    pub unique: TpmuPublicIdentifier,
}

#[derive(Debug)]
pub enum TpmuPublicParams {
    // keydeHashDetail
    SymDetail(TpmsSymcipherParams),
    // RsaDetail(TpmsRsaParams, TpmsAsymParams),
    // EccDetail(TpmsEccParams, TpmsAsymParams),
}

#[derive(Debug)]
pub struct TpmsSymcipherParams {
    pub sym: TpmtSymdefObject,
}

#[derive(Debug)]
pub struct TpmtSymdefObject {
    pub algorithm: TpmiAlgorithmSymmetric,
    pub key_bits: TpmuSymKeybits,
    pub mode: TpmuSymMode,
    // details: TpmuSymDetails, <- see [TPM 2.0 Library Part 2, Section 11.1.6] Table 140
}

#[derive(Debug)]
pub enum TpmuSymKeybits {
    SymmetricAlgo(TpmiAlgorithmSymmetric, TpmKeyBits),
    Xor(TpmiAlgorithmHash),
    Null,
}

#[derive(Debug)]
pub enum TpmuSymMode {
    SymmetricAlgo(TpmiAlgorithmSymmetric, TpmiAlgorithmSymMode),
    Xor,
    Null,
}

#[derive(Debug)]
pub enum TpmuSymDetails {
    SymmetricAlgo(TpmiAlgorithmSymmetric),
    Xor,
    Null,
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

#[derive(Debug)]
pub struct TpmsEccPoint {
    pub x: Tpm2BEccParameter,
    pub y: Tpm2BEccParameter,
}
impl TpmDataWithSelector<TpmiAlgorithmSymmetric> for TpmuSymMode {
    fn to_tpm(&self) -> Vec<u8> {
        match &self {
            TpmuSymMode::SymmetricAlgo(_, mode) => mode.to_tpm(),
            _ => vec![],
        }
    }

    fn from_tpm<'a>(v: &'a [u8], selector: &TpmiAlgorithmSymmetric) -> TpmResult<(Self, &'a [u8])> {
        Ok(if selector == &TpmiAlgorithmSymmetric::Null {
            (TpmuSymMode::Null, v)
        } else if selector == &TpmiAlgorithmSymmetric::Xor {
            (TpmuSymMode::Xor, v)
        } else if selector.get_type() == HashSet::from([TpmAlgorithmType::Symmetric]) {
            let (res, v) = TpmiAlgorithmSymMode::from_tpm(v)?;
            (TpmuSymMode::SymmetricAlgo(*selector, res), v)
        } else {
            unreachable!();
        })
    }
}

impl TpmDataWithSelector<TpmiAlgorithmSymmetric> for TpmuSymKeybits {
    fn to_tpm(&self) -> Vec<u8> {
        match &self {
            TpmuSymKeybits::SymmetricAlgo(_, bits) => bits.to_tpm(),
            TpmuSymKeybits::Xor(hash) => hash.to_tpm(),
            _ => vec![],
        }
    }

    fn from_tpm<'a>(v: &'a [u8], selector: &TpmiAlgorithmSymmetric) -> TpmResult<(Self, &'a [u8])> {
        Ok(if selector == &TpmiAlgorithmSymmetric::Null {
            return Err(TpmError::create_parse_error(&format!(
                "Invalid selector specified: {:?}",
                selector
            ))
            .into());
        } else if selector == &TpmiAlgorithmSymmetric::Xor {
            let (res, v) = TpmiAlgorithmHash::from_tpm(v)?;
            (TpmuSymKeybits::Xor(res), v)
        } else if selector.get_type() == HashSet::from([TpmAlgorithmType::Symmetric]) {
            let (res, v) = TpmKeyBits::from_tpm(v)?;
            (TpmuSymKeybits::SymmetricAlgo(*selector, res), v)
        } else {
            unreachable!();
        })
    }
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
        })
    }
}

impl TpmData for TpmsSensitiveCreate {
    fn to_tpm(&self) -> Vec<u8> {
        [self.user_auth.to_tpm(), self.data.to_tpm()].concat()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (user_auth, v) = Tpm2BAuth::from_tpm(v)?;
        let (data, v) = Tpm2BSensitiveData::from_tpm(v)?;
        Ok((TpmsSensitiveCreate { user_auth, data }, v))
    }
}

impl TpmData for TpmtSymdefObject {
    fn to_tpm(&self) -> Vec<u8> {
        [
            self.algorithm.to_tpm(),
            self.key_bits.to_tpm(),
            self.mode.to_tpm(),
        ]
        .concat()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (algorithm, v) = TpmiAlgorithmSymmetric::from_tpm(v)?;
        let (key_bits, v) = TpmuSymKeybits::from_tpm(v, &algorithm)?;
        let (mode, v) = TpmuSymMode::from_tpm(v, &algorithm)?;
        Ok((
            TpmtSymdefObject {
                algorithm,
                key_bits,
                mode,
            },
            v,
        ))
    }
}

impl TpmData for TpmsSymcipherParams {
    fn to_tpm(&self) -> Vec<u8> {
        self.sym.to_tpm()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (res, v) = TpmtSymdefObject::from_tpm(v)?;
        Ok((TpmsSymcipherParams { sym: res }, v))
    }
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
                "Invalid algorithm specified: {:?}",
                selector
            ))
            .into())
        }
    }
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
