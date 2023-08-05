use crate::tpm::structure::macro_defs::set_tpm_data_codec;
use crate::tpm::structure::{pack_enum_to_u16, unpack_u16_to_enum};
use crate::tpm::{FromTpm, ToTpm};
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
    TpmiAlgorithmAsymmetricScheme, // !ALG.am + !ALG.ax + !ALG.ae
    TpmiAlgorithmRsaScheme, // In specification: !ALG.ae + !ALG.ax but I used tpm2-tss's definition (RSA-related definition)
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
        TpmiAlgorithmCipherMode,
        TpmiAlgorithmPublic,
        TpmiAlgorithmAsymmetricScheme,
        TpmiAlgorithmRsaScheme
    )]
    Null = 0x0010,
    #[subenum(TpmiAlgorithmHash, TpmiAlgorithmMacScheme)]
    Sm3_256 = 0x0012,
    #[subenum(TpmiAlgorithmSymmetric, TpmiAlgorithmSymObject)]
    Sm4 = 0x0013,
    #[subenum(
        TpmiAlgorithmSigScheme,
        TpmiAlgorithmAsymmetricScheme,
        TpmiAlgorithmRsaScheme
    )]
    RsaSsa = 0x0014,
    #[subenum(TpmiAlgorithmAsymmetricScheme, TpmiAlgorithmRsaScheme)]
    RsaEs = 0x0015,
    #[subenum(
        TpmiAlgorithmSigScheme,
        TpmiAlgorithmAsymmetricScheme,
        TpmiAlgorithmRsaScheme
    )]
    RsaPss = 0x0016,
    #[subenum(TpmiAlgorithmAsymmetricScheme, TpmiAlgorithmRsaScheme)]
    Oaep = 0x0017,
    #[subenum(TpmiAlgorithmSigScheme, TpmiAlgorithmAsymmetricScheme)]
    EcDsa = 0x0018,
    #[subenum(TpmiAlgorithmEccKeyXchg, TpmiAlgorithmAsymmetricScheme)]
    EcDh = 0x0019,
    #[subenum(TpmiAlgorithmSigScheme, TpmiAlgorithmAsymmetricScheme)]
    EcDaa = 0x001a,
    #[subenum(
        TpmiAlgorithmSigScheme,
        TpmiAlgorithmEccKeyXchg,
        TpmiAlgorithmAsymmetricScheme
    )]
    Sm2 = 0x001b,
    #[subenum(TpmiAlgorithmSigScheme, TpmiAlgorithmAsymmetricScheme)]
    EcSchnorr = 0x001c,
    #[subenum(TpmiAlgorithmEccKeyXchg, TpmiAlgorithmAsymmetricScheme)]
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

set_tpm_data_codec!(TpmAlgorithmIdentifier, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(TpmiAlgorithmHash, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(
    TpmiAlgorithmAsymmetric,
    pack_enum_to_u16,
    unpack_u16_to_enum
);
set_tpm_data_codec!(TpmiAlgorithmSymmetric, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(TpmiAlgorithmSymObject, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(TpmiAlgorithmSymMode, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(TpmiAlgorithmKdf, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(TpmiAlgorithmSigScheme, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(
    TpmiAlgorithmEccKeyXchg,
    pack_enum_to_u16,
    unpack_u16_to_enum
);
set_tpm_data_codec!(TpmiAlgorithmMacScheme, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(
    TpmiAlgorithmCipherMode,
    pack_enum_to_u16,
    unpack_u16_to_enum
);
set_tpm_data_codec!(TpmiAlgorithmPublic, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(
    TpmiAlgorithmAsymmetricScheme,
    pack_enum_to_u16,
    unpack_u16_to_enum
);
set_tpm_data_codec!(TpmiAlgorithmRsaScheme, pack_enum_to_u16, unpack_u16_to_enum);

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
impl_subenums!(TpmiAlgorithmAsymmetricScheme);
impl_subenums!(TpmiAlgorithmRsaScheme);

impl TpmiAlgorithmHash {
    pub fn digest(&self, message: &[u8]) -> Vec<u8> {
        use digest::Digest;

        macro_rules! arm {
            ($new:path) => {{
                let mut hasher = $new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }};
        }

        match &self {
            Self::Sha1 => arm!(sha1::Sha1::new),
            Self::Sha256 => arm!(sha2::Sha256::new),
            Self::Sha384 => arm!(sha2::Sha384::new),
            Self::Sha512 => arm!(sha2::Sha512::new),
            Self::Sha3_256 => arm!(sha3::Sha3_256::new),
            Self::Sha3_384 => arm!(sha3::Sha3_384::new),
            Self::Sha3_512 => arm!(sha3::Sha3_512::new),
            Self::Sm3_256 => arm!(sm3::Sm3::new),
            _ => {
                unreachable!();
            }
        }
    }

    pub fn hmac(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};

        macro_rules! arm {
            ($type:path) => {{
                type ActualHmac = Hmac<$type>;
                let mut hasher = ActualHmac::new_from_slice(key).unwrap();
                hasher.update(message);
                hasher.finalize().into_bytes().to_vec()
            }};
        }

        match &self {
            Self::Sha1 => arm!(sha1::Sha1),
            Self::Sha256 => arm!(sha2::Sha256),
            Self::Sha384 => arm!(sha2::Sha384),
            Self::Sha512 => arm!(sha2::Sha512),
            Self::Sha3_256 => arm!(sha2::Sha256),
            Self::Sha3_384 => arm!(sha2::Sha384),
            Self::Sha3_512 => arm!(sha2::Sha512),
            Self::Sm3_256 => arm!(sm3::Sm3),
            _ => {
                unreachable!();
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::tpm::structure::{TpmAlgorithm, TpmAlgorithmIdentifier, TpmAlgorithmType};
    use enum_iterator::all;
    use num_traits::ToPrimitive;
    use std::collections::HashSet;

    fn to_set<T>() -> HashSet<TpmAlgorithmIdentifier>
    where
        T: enum_iterator::Sequence
            + TpmAlgorithm
            + ToPrimitive
            + std::hash::Hash
            + std::cmp::Eq
            + Into<TpmAlgorithmIdentifier>,
    {
        all::<T>()
            .map(|x| x.into())
            .filter(|x| x.to_u32().unwrap() != 0x10)
            .collect()
    }

    fn extract_equal<T>(target: &HashSet<TpmAlgorithmType>) -> HashSet<TpmAlgorithmIdentifier>
    where
        T: enum_iterator::Sequence
            + TpmAlgorithm
            + ToPrimitive
            + std::hash::Hash
            + std::cmp::Eq
            + Into<TpmAlgorithmIdentifier>,
    {
        all::<T>()
            .into_iter()
            .map(|x| x.into())
            .filter(|x| &x.get_type() == target && x.to_u32().unwrap() != 0x10)
            .collect::<HashSet<_>>()
    }

    fn extract_least<T>(target: &HashSet<TpmAlgorithmType>) -> HashSet<TpmAlgorithmIdentifier>
    where
        T: enum_iterator::Sequence
            + TpmAlgorithm
            + ToPrimitive
            + std::hash::Hash
            + std::cmp::Eq
            + Into<TpmAlgorithmIdentifier>,
    {
        all::<T>()
            .into_iter()
            .map(|x| x.into())
            .filter(|x| target.is_subset(&x.get_type()) && x.to_u32().unwrap() != 0x10)
            .collect::<HashSet<_>>()
    }

    fn test_algo_with_except<T>(
        target: &HashSet<TpmAlgorithmType>,
        except: &HashSet<TpmAlgorithmIdentifier>,
    ) where
        T: enum_iterator::Sequence
            + TpmAlgorithm
            + ToPrimitive
            + std::hash::Hash
            + std::cmp::Eq
            + Into<TpmAlgorithmIdentifier>,
    {
        assert_eq!(
            to_set::<T>(),
            extract_equal::<TpmAlgorithmIdentifier>(target)
                .union(&except)
                .map(|x| *x)
                .collect::<HashSet<_>>()
        );
    }

    fn test_algo<T>(target: &HashSet<TpmAlgorithmType>)
    where
        T: enum_iterator::Sequence
            + TpmAlgorithm
            + ToPrimitive
            + std::hash::Hash
            + std::cmp::Eq
            + Into<TpmAlgorithmIdentifier>,
    {
        assert_eq!(
            to_set::<T>(),
            extract_equal::<TpmAlgorithmIdentifier>(target)
        );
    }

    fn test_algo_least<T>(target: &HashSet<TpmAlgorithmType>)
    where
        T: enum_iterator::Sequence
            + TpmAlgorithm
            + ToPrimitive
            + std::hash::Hash
            + std::cmp::Eq
            + Into<TpmAlgorithmIdentifier>,
    {
        assert_eq!(
            to_set::<T>(),
            extract_least::<TpmAlgorithmIdentifier>(target)
        );
    }

    #[test]
    fn test_hash() {
        test_algo::<crate::tpm::structure::TpmiAlgorithmHash>(&HashSet::from([
            TpmAlgorithmType::Hash,
        ]));
    }

    #[test]
    fn test_assym() {
        test_algo::<crate::tpm::structure::TpmiAlgorithmAsymmetric>(&HashSet::from([
            TpmAlgorithmType::Asymmetric,
            TpmAlgorithmType::Object,
        ]));
    }

    #[test]
    fn test_symobj() {
        test_algo::<crate::tpm::structure::TpmiAlgorithmSymObject>(&HashSet::from([
            TpmAlgorithmType::Symmetric,
        ]));
    }

    #[test]
    fn test_kdf() {
        test_algo::<crate::tpm::structure::TpmiAlgorithmKdf>(&HashSet::from([
            TpmAlgorithmType::Hash,
            TpmAlgorithmType::MaskGeneration,
        ]));
    }

    #[test]
    fn test_ciphermode() {
        test_algo::<crate::tpm::structure::TpmiAlgorithmCipherMode>(&HashSet::from([
            TpmAlgorithmType::Symmetric,
            TpmAlgorithmType::Encryption,
        ]));
    }

    #[test]
    fn test_sym() {
        test_algo_with_except::<crate::tpm::structure::TpmiAlgorithmSymmetric>(
            &HashSet::from([TpmAlgorithmType::Symmetric]),
            &HashSet::from([TpmAlgorithmIdentifier::Xor]),
        );
    }

    #[test]
    fn test_ecckx() {
        test_algo_with_except::<crate::tpm::structure::TpmiAlgorithmEccKeyXchg>(
            &HashSet::from([
                TpmAlgorithmType::Asymmetric,
                TpmAlgorithmType::MaskGeneration,
            ]),
            &HashSet::from([TpmAlgorithmIdentifier::Sm2]),
        );
    }

    #[test]
    fn test_symmode() {
        let target1 = HashSet::from([TpmAlgorithmType::Symmetric, TpmAlgorithmType::Encryption]); // !ALG.SE
        let target2 = HashSet::from([TpmAlgorithmType::Symmetric, TpmAlgorithmType::Signing]); // !ALG.SX

        let extracted: HashSet<TpmAlgorithmIdentifier> =
            extract_equal::<TpmAlgorithmIdentifier>(&target1)
                .union(&extract_equal::<TpmAlgorithmIdentifier>(&target2))
                .map(|x| *x)
                .collect();

        assert_eq!(
            to_set::<crate::tpm::structure::TpmiAlgorithmSymMode>(),
            extracted
        );
    }

    #[test]
    fn test_mac_scheme() {
        let target1 = HashSet::from([TpmAlgorithmType::Hash]); // !ALG.H
        let target2 = HashSet::from([TpmAlgorithmType::Symmetric, TpmAlgorithmType::Signing]); // !ALG.SX

        let extracted: HashSet<TpmAlgorithmIdentifier> =
            extract_equal::<TpmAlgorithmIdentifier>(&target1)
                .union(&extract_equal::<TpmAlgorithmIdentifier>(&target2))
                .map(|x| *x)
                .collect();

        assert_eq!(
            to_set::<crate::tpm::structure::TpmiAlgorithmMacScheme>(),
            extracted
        );
    }

    #[test]
    fn test_sig_scheme() {
        test_algo_least::<crate::tpm::structure::TpmiAlgorithmSigScheme>(&HashSet::from([
            TpmAlgorithmType::Asymmetric,
            TpmAlgorithmType::Signing,
        ]));
    }

    #[test]
    fn test_public() {
        test_algo_least::<crate::tpm::structure::TpmiAlgorithmPublic>(&HashSet::from([
            TpmAlgorithmType::Object,
        ]));
    }

    #[test]
    fn test_assym_scheme() {
        let target1 = HashSet::from([
            TpmAlgorithmType::Asymmetric,
            TpmAlgorithmType::MaskGeneration,
        ]); // !ALG.am
        let target2 = HashSet::from([TpmAlgorithmType::Asymmetric, TpmAlgorithmType::Signing]); // !ALG.ax
        let target3 = HashSet::from([TpmAlgorithmType::Asymmetric, TpmAlgorithmType::Encryption]); // !ALG.ae

        let extracted: HashSet<TpmAlgorithmIdentifier> =
            extract_least::<TpmAlgorithmIdentifier>(&target1)
                .union(&extract_least::<TpmAlgorithmIdentifier>(&target2))
                .map(|x| *x)
                .collect::<HashSet<_>>()
                .union(&extract_least::<TpmAlgorithmIdentifier>(&target3))
                .map(|x| *x)
                .collect();

        assert_eq!(
            to_set::<crate::tpm::structure::TpmiAlgorithmAsymmetricScheme>(),
            extracted
        );
    }

    #[test]
    fn test_rsa_scheme() {
        assert_eq!(
            to_set::<crate::tpm::structure::TpmiAlgorithmRsaScheme>(),
            HashSet::from([
                TpmAlgorithmIdentifier::RsaEs,
                TpmAlgorithmIdentifier::Oaep,
                TpmAlgorithmIdentifier::RsaSsa,
                TpmAlgorithmIdentifier::RsaPss,
            ])
        );
    }
}
