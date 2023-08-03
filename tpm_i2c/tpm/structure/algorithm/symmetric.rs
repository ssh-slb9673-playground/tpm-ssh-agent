use crate::tpm::structure::{
    Tpm2BAuth, Tpm2BSensitiveData, TpmAlgorithm, TpmAlgorithmType, TpmKeyBits, TpmiAlgorithmHash,
    TpmiAlgorithmSymMode, TpmiAlgorithmSymmetric,
};

use crate::tpm::{TpmData, TpmDataWithSelector, TpmError, TpmResult};
use std::collections::HashSet;

#[derive(Debug)]
pub struct TpmsSymcipherParams {
    pub sym: TpmtSymdefObject,
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

#[derive(Debug)]
pub struct TpmtSymdefObject {
    pub algorithm: TpmiAlgorithmSymmetric,
    pub key_bits: TpmuSymKeybits,
    pub mode: TpmuSymMode,
    // details: TpmuSymDetails, <- we must omit this; see [TPM 2.0 Library Part 2, Section 11.1.6] Table 140
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

#[derive(Debug)]
pub enum TpmuSymKeybits {
    SymmetricAlgo(TpmiAlgorithmSymmetric, TpmKeyBits),
    Xor(TpmiAlgorithmHash),
    Null,
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

#[derive(Debug)]
pub enum TpmuSymMode {
    SymmetricAlgo(TpmiAlgorithmSymmetric, TpmiAlgorithmSymMode),
    Xor,
    Null,
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

#[derive(Debug)]
pub enum TpmuSymDetails {
    SymmetricAlgo(TpmiAlgorithmSymmetric),
    Xor,
    Null,
}

#[derive(Debug)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2BAuth,
    pub data: Tpm2BSensitiveData,
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
