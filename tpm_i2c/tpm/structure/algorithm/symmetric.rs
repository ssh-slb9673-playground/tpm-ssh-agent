use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_from_tpm_with_selector, impl_to_tpm};
use crate::tpm::structure::{
    Tpm2BAuth, Tpm2BSensitiveData, TpmAlgorithm, TpmAlgorithmType, TpmKeyBits, TpmiAlgorithmHash,
    TpmiAlgorithmSymMode, TpmiAlgorithmSymObject, TpmiAlgorithmSymmetric, TpmsSchemeHash,
};
use crate::tpm::{FromTpm, FromTpmWithSelector, ToTpm, TpmError, TpmResult};
use crate::util::{p16be, u16be};
use std::collections::HashSet;

pub type TpmsSchemeHmac = TpmsSchemeHash;

#[derive(Debug, Clone)]
pub struct Tpm2BSensitiveCreate {
    pub sensitive: TpmsSensitiveCreate,
}

#[derive(Debug, Clone)]
pub struct TpmsSymcipherParams {
    pub sym: TpmtSymdefObject,
}

#[derive(Debug, Clone)]
pub struct TpmtSymdefObject {
    pub algorithm: TpmiAlgorithmSymObject,
    pub key_bits: TpmuSymKeybits,
    pub mode: TpmuSymMode,
    // details: TpmuSymDetails, <- we must omit this; see [TPM 2.0 Library Part 2, Section 11.1.6] Table 140
}

#[derive(Debug, Clone)]
pub struct TpmtSymdef {
    pub algorithm: TpmiAlgorithmSymmetric,
    pub key_bits: TpmuSymKeybits,
    pub mode: TpmuSymMode,
    // details: TpmuSymDetails, <- we must omit this; see [TPM 2.0 Library Part 2, Section 11.1.6] Table 140
}

#[derive(Debug, Clone)]
pub enum TpmuSymKeybits {
    SymmetricAlgo(TpmKeyBits),
    Xor(TpmiAlgorithmHash),
    Null,
}

#[derive(Debug, Clone)]
pub enum TpmuSymMode {
    SymmetricAlgo(TpmiAlgorithmSymMode),
    Xor,
    Null,
}

#[derive(Debug, Clone)]
pub enum TpmuSymDetails {
    SymmetricAlgo(TpmiAlgorithmSymmetric),
    Xor,
    Null,
}

#[derive(Debug, Clone)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2BAuth,
    pub data: Tpm2BSensitiveData,
}

impl_to_tpm! {
    TpmsSymcipherParams(self) {
        self.sym.to_tpm()
    }

    TpmtSymdef(self) {
        [
            self.algorithm.to_tpm(),
            self.key_bits.to_tpm(),
            self.mode.to_tpm(),
        ]
        .concat()
    }

    TpmtSymdefObject(self) {
        [
            self.algorithm.to_tpm(),
            self.key_bits.to_tpm(),
            self.mode.to_tpm(),
        ]
        .concat()
    }

    TpmuSymKeybits(self) {
        match &self {
            TpmuSymKeybits::SymmetricAlgo(bits) => bits.to_tpm(),
            TpmuSymKeybits::Xor(hash) => hash.to_tpm(),
            _ => vec![],
        }
    }

    TpmuSymMode(self) {
        match &self {
            TpmuSymMode::SymmetricAlgo(mode) => mode.to_tpm(),
            _ => vec![],
        }
    }

    TpmsSensitiveCreate(self) {
        [self.user_auth.to_tpm(), self.data.to_tpm()].concat()
    }

    Tpm2BSensitiveCreate(self) {
        let v = self.sensitive.to_tpm();
        [p16be(v.len() as u16).to_vec(), v].concat()
    }
}

impl_from_tpm! {
    TpmsSymcipherParams(v) {
        let (res, v) = TpmtSymdefObject::from_tpm(v)?;
        Ok((TpmsSymcipherParams { sym: res }, v))
    }

    TpmtSymdef(v) {
        let (algorithm, v) = TpmiAlgorithmSymmetric::from_tpm(v)?;
        let (key_bits, v) = TpmuSymKeybits::from_tpm(v, &algorithm)?;
        let (mode, v) = TpmuSymMode::from_tpm(v, &algorithm)?;
        Ok((
            TpmtSymdef {
                algorithm,
                key_bits,
                mode,
            },
            v,
        ))
    }

    TpmtSymdefObject(v) {
        use num_traits::{FromPrimitive, ToPrimitive};
        let (algorithm, v) = TpmiAlgorithmSymObject::from_tpm(v)?;
        let algorithm_sym = TpmiAlgorithmSymmetric::from_u32(algorithm.to_u32().unwrap()).unwrap();
        let (key_bits, v) = TpmuSymKeybits::from_tpm(v, &algorithm_sym)?;
        let (mode, v) = TpmuSymMode::from_tpm(v, &algorithm_sym)?;
        Ok((
            TpmtSymdefObject {
                algorithm,
                key_bits,
                mode,
            },
            v,
        ))
    }

    TpmsSensitiveCreate(v) {
        let (user_auth, v) = Tpm2BAuth::from_tpm(v)?;
        let (data, v) = Tpm2BSensitiveData::from_tpm(v)?;
        Ok((TpmsSensitiveCreate { user_auth, data }, v))
    }

    Tpm2BSensitiveCreate(v) {
        if v.len() < 2 {
            return Err(TpmError::create_parse_error("Length mismatch").into());
        }
        let (_len, v) = (u16be(&v[0..2]) as usize, &v[2..]);
        let (sensitive, v) = TpmsSensitiveCreate::from_tpm(v)?;
        Ok((Tpm2BSensitiveCreate {sensitive}, v))
    }
}

impl_from_tpm_with_selector! {
    TpmuSymKeybits<TpmiAlgorithmSymmetric>(v, selector) {
        Ok(if selector == &TpmiAlgorithmSymmetric::Null {
            (TpmuSymKeybits::Null, v)
        } else if selector == &TpmiAlgorithmSymmetric::Xor {
            let (res, v) = TpmiAlgorithmHash::from_tpm(v)?;
            (TpmuSymKeybits::Xor(res), v)
        } else if selector.get_type() == HashSet::from([TpmAlgorithmType::Symmetric]) {
            let (res, v) = TpmKeyBits::from_tpm(v)?;
            (TpmuSymKeybits::SymmetricAlgo(res), v)
        } else {
            unreachable!();
        })
    }

    TpmuSymMode<TpmiAlgorithmSymmetric>(v, selector) {
        Ok(if selector == &TpmiAlgorithmSymmetric::Null {
            (TpmuSymMode::Null, v)
        } else if selector == &TpmiAlgorithmSymmetric::Xor {
            (TpmuSymMode::Xor, v)
        } else if selector.get_type() == HashSet::from([TpmAlgorithmType::Symmetric]) {
            let (res, v) = TpmiAlgorithmSymMode::from_tpm(v)?;
            (TpmuSymMode::SymmetricAlgo(res), v)
        } else {
            unreachable!();
        })
    }
}
