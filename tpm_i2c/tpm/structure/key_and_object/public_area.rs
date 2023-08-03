use crate::tpm::structure::{
    Tpm2BDigest, Tpm2BPublicKeyRsa, TpmAlgorithm, TpmAlgorithmType, TpmAttrObject, TpmKeyBits,
    TpmiAlgorithmHash, TpmiAlgorithmPublic, TpmsEccPoint, TpmsSymcipherParams, TpmtSymdefObject,
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
    //RsaDetail(TpmsRsaParams, TpmsAsymParams),
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
                "Invalid algorithm specified: {:?}",
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
        })
    }
}

#[derive(Debug)]
pub struct TpmsRsaParams {
    symmetric: TpmtSymdefObject,
    // scheme: TpmtRsaScheme,
    key_bits: TpmKeyBits,
    exponent: u32,
}
