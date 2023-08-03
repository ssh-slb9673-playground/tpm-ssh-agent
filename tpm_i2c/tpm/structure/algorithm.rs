use crate::tpm::structure::macro_defs::set_tpm_data_codec;
use crate::tpm::structure::{pack_enum_to_u32, unpack_u32_to_enum};
use crate::tpm::TpmData;
use crate::TpmResult;
use enum_iterator::Sequence;
use num_derive::{FromPrimitive, ToPrimitive};
use std::collections::HashSet;
use subenum::subenum;

// TPM_ALG_ID
#[subenum(
    TpmiAlgorithmAsymmetric, // !ALG.AO
    TpmiAlgorithmHash, // !ALG.H
    TpmiAlgorithmSymmetric, // !ALG.S + TPM_ALG_XOR
    TpmiAlgorithmSymObject, // !ALG.S
    TpmiAlgorithmSymMode, // !ALG.SE + !ALG.SX
    TpmiAlgorithmKdf, // !ALG.HM
    TpmiAlgorithmSigScheme, // !ALG.ax (<=> !ALG.AX + !ALG.ANX)
    TpmiAlgorithmEccKeyXchg, // !ALG.AM + TPM_ALG_SM2
    TpmiAlgorithmMacScheme, // !ALG.SX + !ALG.H
    TpmiAlgorithmCipherMode, // !ALG.SE
    TpmiAlgorithmPublic, // !ALG.o
)]
#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq, Hash, Clone, Copy, Sequence)]
#[repr(u16)]
pub enum TpmAlgorithmIdentifier {
    Error = 0x0000,
    #[subenum(TpmiAlgorithmAsymmetric, TpmiAlgorithmPublic)]
    Rsa = 0x0001,
    #[subenum(TpmiAlgorithmSymmetric, TpmiAlgorithmSymObject)]
    TripleDes = 0x0003,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sha1 = 0x0004,
    Hmac = 0x0005,
    #[subenum(TpmiAlgorithmSymmetric, TpmiAlgorithmSymObject)]
    Aes = 0x0006,
    #[subenum(TpmiAlgorithmKdf)]
    Mgf1 = 0x0007,
    #[subenum(TpmiAlgorithmPublic)]
    KeyedHash = 0x0008,
    #[subenum(TpmiAlgorithmSymmetric)]
    Xor = 0x000a,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sha256 = 0x000b,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sha384 = 0x000c,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sha512 = 0x000d,
    #[subenum(
        TpmiAlgorithmAsymmetric,
        TpmiAlgorithmHash,
        TpmiAlgorithmSymmetric,
        TpmiAlgorithmSymObject,
        TpmiAlgorithmSymMode,
        TpmiAlgorithmKdf,
        TpmiAlgorithmSigScheme,
        TpmiAlgorithmEccKeyXchg,
        TpmiAlgorithmMacScheme,
        TpmiAlgorithmCipherMode
    )]
    Null = 0x0010,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sm3_256 = 0x0012,
    #[subenum(TpmiAlgorithmSymmetric, TpmiAlgorithmSymObject)]
    Sm4 = 0x0013,
    #[subenum(TpmiAlgorithmSigScheme)]
    RsaSsa = 0x0014,
    RsaEs = 0x0015,
    #[subenum(TpmiAlgorithmSigScheme)]
    RsaPss = 0x0016,
    Oaep = 0x0017,
    #[subenum(TpmiAlgorithmSigScheme)]
    EcDsa = 0x0018,
    #[subenum(TpmiAlgorithmEccKeyXchg)]
    EcDh = 0x0019,
    #[subenum(TpmiAlgorithmSigScheme)]
    EcDaa = 0x001a,
    #[subenum(TpmiAlgorithmSigScheme, TpmiAlgorithmEccKeyXchg)]
    Sm2 = 0x001b,
    #[subenum(TpmiAlgorithmSigScheme)]
    EcSchnorr = 0x001c,
    #[subenum(TpmiAlgorithmEccKeyXchg)]
    EcMqv = 0x001d,
    #[subenum(TpmiAlgorithmKdf)]
    Kdf1Sp800_56a = 0x0020,
    #[subenum(TpmiAlgorithmKdf)]
    Kdf2 = 0x0021,
    #[subenum(TpmiAlgorithmKdf)]
    Kdf1Sp800_108 = 0x0022,
    #[subenum(TpmiAlgorithmAsymmetric, TpmiAlgorithmPublic)]
    Ecc = 0x0023,
    #[subenum(TpmiAlgorithmPublic)]
    SymCipher = 0x0025,
    #[subenum(TpmiAlgorithmSymmetric, TpmiAlgorithmSymObject)]
    Camellia = 0x0026,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sha3_256 = 0x0027,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sha3_384 = 0x0028,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sha3_512 = 0x0029,
    #[subenum(TpmiAlgorithmSymMode, TpmiAlgorithmCipherMode)]
    CTR = 0x0040,
    #[subenum(TpmiAlgorithmSymMode, TpmiAlgorithmCipherMode)]
    OFB = 0x0041,
    #[subenum(TpmiAlgorithmSymMode, TpmiAlgorithmCipherMode)]
    CBC = 0x0042,
    #[subenum(TpmiAlgorithmSymMode, TpmiAlgorithmCipherMode)]
    CFB = 0x0043,
    #[subenum(TpmiAlgorithmSymMode, TpmiAlgorithmCipherMode)]
    ECB = 0x0044,
}

set_tpm_data_codec!(TpmAlgorithmIdentifier, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmiAlgorithmHash, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(
    TpmiAlgorithmAsymmetric,
    pack_enum_to_u32,
    unpack_u32_to_enum
);
set_tpm_data_codec!(TpmiAlgorithmSymmetric, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmiAlgorithmSymObject, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmiAlgorithmSymMode, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmiAlgorithmKdf, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmiAlgorithmSigScheme, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(
    TpmiAlgorithmEccKeyXchg,
    pack_enum_to_u32,
    unpack_u32_to_enum
);
set_tpm_data_codec!(TpmiAlgorithmMacScheme, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(
    TpmiAlgorithmCipherMode,
    pack_enum_to_u32,
    unpack_u32_to_enum
);
set_tpm_data_codec!(TpmiAlgorithmPublic, pack_enum_to_u32, unpack_u32_to_enum);

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum TpmAlgorithmType {
    Asymmetric,
    Symmetric,
    Hash,
    Signing,
    AnonymousSigning,
    Encryption,
    MaskGeneration,
    Object,
}

pub trait TpmAlgorithm {
    fn get_type(&self) -> HashSet<TpmAlgorithmType>;
}

impl TpmAlgorithm for TpmAlgorithmIdentifier {
    fn get_type(&self) -> HashSet<TpmAlgorithmType> {
        use TpmAlgorithmIdentifier::*;
        use TpmAlgorithmType::*;

        HashSet::from_iter(
            match self {
                Error => vec![],
                Rsa => vec![Asymmetric, Object],
                TripleDes => vec![Symmetric],
                Sha1 => vec![Hash],
                Hmac => vec![Hash, Signing],
                Aes => vec![Symmetric],
                Mgf1 => vec![Hash, MaskGeneration],
                KeyedHash => vec![Hash, Object],
                Xor => vec![Hash, Symmetric],
                Sha256 => vec![Hash],
                Sha384 => vec![Hash],
                Sha512 => vec![Hash],
                Null => vec![],
                Sm3_256 => vec![Hash],
                Sm4 => vec![Symmetric],
                RsaSsa => vec![Asymmetric, Signing],
                RsaEs => vec![Asymmetric, Encryption],
                RsaPss => vec![Asymmetric, Signing],
                Oaep => vec![Asymmetric, Encryption, Hash],
                EcDsa => vec![Asymmetric, Signing],
                EcDh => vec![Asymmetric, MaskGeneration],
                EcDaa => vec![Asymmetric, Signing, AnonymousSigning],
                Sm2 => vec![Asymmetric, Signing],
                EcSchnorr => vec![Asymmetric, Signing],
                EcMqv => vec![Asymmetric, MaskGeneration],
                Kdf1Sp800_56a => vec![Hash, MaskGeneration],
                Kdf2 => vec![Hash, MaskGeneration],
                Kdf1Sp800_108 => vec![Hash, MaskGeneration],
                Ecc => vec![Asymmetric, Object],
                SymCipher => vec![Object, Symmetric],
                Camellia => vec![Symmetric],
                Sha3_256 => vec![Hash],
                Sha3_384 => vec![Hash],
                Sha3_512 => vec![Hash],
                CTR => vec![Symmetric, Encryption],
                OFB => vec![Symmetric, Encryption],
                CBC => vec![Symmetric, Encryption],
                CFB => vec![Symmetric, Encryption],
                ECB => vec![Symmetric, Encryption],
            }
            .into_iter(),
        )
    }
}

macro_rules! impl_subenums {
    ($name:ident) => {
        impl TpmAlgorithm for $name {
            fn get_type(&self) -> HashSet<TpmAlgorithmType> {
                TpmAlgorithmIdentifier::from(*self).get_type()
            }
        }
    };
}

impl_subenums!(TpmiAlgorithmHash);
impl_subenums!(TpmiAlgorithmAsymmetric);
impl_subenums!(TpmiAlgorithmSymmetric);
impl_subenums!(TpmiAlgorithmSymObject);
impl_subenums!(TpmiAlgorithmSymMode);
impl_subenums!(TpmiAlgorithmKdf);
impl_subenums!(TpmiAlgorithmSigScheme);
impl_subenums!(TpmiAlgorithmEccKeyXchg);
impl_subenums!(TpmiAlgorithmMacScheme);
impl_subenums!(TpmiAlgorithmCipherMode);
impl_subenums!(TpmiAlgorithmPublic);

#[cfg(test)]
mod test {
    use crate::tpm::structure::{
        TpmAlgorithm, TpmAlgorithmIdentifier, TpmAlgorithmType, TpmiAlgorithmAsymmetric,
        TpmiAlgorithmCipherMode, TpmiAlgorithmEccKeyXchg, TpmiAlgorithmHash, TpmiAlgorithmKdf,
        TpmiAlgorithmMacScheme, TpmiAlgorithmPublic, TpmiAlgorithmSigScheme, TpmiAlgorithmSymMode,
        TpmiAlgorithmSymObject, TpmiAlgorithmSymmetric,
    };
    use crate::tpm::TpmData;
    use enum_iterator::all;
    use num_traits::ToPrimitive;
    use std::collections::HashSet;

    fn test_algo_with_except<T>(
        target: &HashSet<TpmAlgorithmType>,
        except: &HashSet<TpmAlgorithmIdentifier>,
    ) where
        T: enum_iterator::Sequence + TpmData + TpmAlgorithm + ToPrimitive,
    {
        let algorithms = all::<T>()
            .into_iter()
            .map(|x| x.to_tpm())
            .collect::<Vec<_>>();
        let except_tpm: HashSet<Vec<u8>> =
            HashSet::from_iter(except.into_iter().map(|x| x.to_tpm()));
        for x in all::<TpmAlgorithmIdentifier>() {
            if x.to_u32().unwrap() == 0x10 {
                continue;
            }
            if &x.get_type() == target {
                assert!(algorithms.contains(&x.to_tpm()) || except_tpm.contains(&x.to_tpm()));
            }
        }

        for x in all::<T>() {
            if x.to_u32().unwrap() == 0x10 {
                continue;
            }
            assert!(&x.get_type() == target || except_tpm.contains(&x.to_tpm()));
        }
    }

    fn test_algo<T>(target: &HashSet<TpmAlgorithmType>)
    where
        T: enum_iterator::Sequence + TpmData + TpmAlgorithm + ToPrimitive,
    {
        test_algo_with_except::<T>(target, &HashSet::new())
    }

    fn test_algo_or<T>(target1: &HashSet<TpmAlgorithmType>, target2: &HashSet<TpmAlgorithmType>)
    where
        T: enum_iterator::Sequence + TpmData + TpmAlgorithm + ToPrimitive,
    {
        let algorithms = all::<T>()
            .into_iter()
            .map(|x| x.to_tpm())
            .collect::<Vec<_>>();

        for x in all::<TpmAlgorithmIdentifier>() {
            if x.to_u32().unwrap() == 0x10 {
                continue;
            }
            if &x.get_type() == target1 {
                assert!(algorithms.contains(&x.to_tpm()));
            } else if &x.get_type() == target2 {
                assert!(algorithms.contains(&x.to_tpm()));
            }
        }

        for x in all::<T>() {
            if x.to_u32().unwrap() == 0x10 {
                continue;
            }
            assert!(&x.get_type() == target1 || &x.get_type() == target2);
        }
    }

    fn test_algo_least<T>(target: &HashSet<TpmAlgorithmType>)
    where
        T: enum_iterator::Sequence + TpmData + TpmAlgorithm + ToPrimitive,
    {
        let algorithms = all::<T>()
            .into_iter()
            .map(|x| x.to_tpm())
            .collect::<Vec<_>>();
        for x in all::<TpmAlgorithmIdentifier>() {
            if x.to_u32().unwrap() == 0x10 {
                continue;
            }
            if target.is_subset(&x.get_type()) {
                assert!(algorithms.contains(&x.to_tpm()));
            }
        }

        for x in all::<T>() {
            if x.to_u32().unwrap() == 0x10 {
                continue;
            }
            assert!(target.is_subset(&x.get_type()));
        }
    }

    #[test]
    fn test_hash() {
        test_algo::<TpmiAlgorithmHash>(&HashSet::from([TpmAlgorithmType::Hash]));
    }

    #[test]
    fn test_assym() {
        test_algo::<TpmiAlgorithmAsymmetric>(&HashSet::from([
            TpmAlgorithmType::Asymmetric,
            TpmAlgorithmType::Object,
        ]));
    }

    #[test]
    fn test_symobj() {
        test_algo::<TpmiAlgorithmSymObject>(&HashSet::from([TpmAlgorithmType::Symmetric]));
    }

    #[test]
    fn test_kdf() {
        test_algo::<TpmiAlgorithmKdf>(&HashSet::from([
            TpmAlgorithmType::Hash,
            TpmAlgorithmType::MaskGeneration,
        ]));
    }

    #[test]
    fn test_ciphermode() {
        test_algo::<TpmiAlgorithmCipherMode>(&HashSet::from([
            TpmAlgorithmType::Symmetric,
            TpmAlgorithmType::Encryption,
        ]));
    }

    #[test]
    fn test_sym() {
        test_algo_with_except::<TpmiAlgorithmSymmetric>(
            &HashSet::from([TpmAlgorithmType::Symmetric]),
            &HashSet::from([TpmAlgorithmIdentifier::Xor]),
        );
    }

    #[test]
    fn test_ecckx() {
        test_algo_with_except::<TpmiAlgorithmEccKeyXchg>(
            &HashSet::from([
                TpmAlgorithmType::Asymmetric,
                TpmAlgorithmType::MaskGeneration,
            ]),
            &HashSet::from([TpmAlgorithmIdentifier::Sm2]),
        );
    }

    #[test]
    fn test_symmode() {
        test_algo_or::<TpmiAlgorithmSymMode>(
            &HashSet::from([TpmAlgorithmType::Symmetric, TpmAlgorithmType::Encryption]),
            &HashSet::from([TpmAlgorithmType::Symmetric, TpmAlgorithmType::Signing]),
        );
    }

    #[test]
    fn test_macsch() {
        test_algo_or::<TpmiAlgorithmMacScheme>(
            &HashSet::from([TpmAlgorithmType::Hash]),
            &HashSet::from([TpmAlgorithmType::Symmetric, TpmAlgorithmType::Signing]),
        );
    }

    #[test]
    fn test_sigsch() {
        test_algo_least::<TpmiAlgorithmSigScheme>(&HashSet::from([
            TpmAlgorithmType::Asymmetric,
            TpmAlgorithmType::Signing,
        ]));
    }

    #[test]
    fn test_public() {
        test_algo_least::<TpmiAlgorithmPublic>(&HashSet::from([TpmAlgorithmType::Object]));
    }
}
