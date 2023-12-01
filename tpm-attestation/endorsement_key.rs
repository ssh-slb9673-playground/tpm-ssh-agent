use crate::error::Result;
use crate::{create_primary, nv_read};
use tpm_i2c::tpm::commands::*;
use tpm_i2c::tpm::session::TpmSession;
use tpm_i2c::tpm::structure::*;
use tpm_i2c::tpm::Tpm;

pub enum EkType {
    // Currently Low-range EK only
    Ecc,
    Rsa,
}

impl EkType {
    pub fn get_index(&self) -> u32 {
        match self {
            // [TCG EK Credential Profile V2.5r2] Section 2.2.1.4. Low Range "ECC NIST P256 EK Certificate"
            Self::Ecc => 0x01c0000a,
            // [TCG EK Credential Profile V2.5r2] Section 2.2.1.4. Low Range "RSA 2048 EK Certificate"
            Self::Rsa => 0x01c00002,
        }
    }

    pub fn get_certificate(&self, tpm: &mut Tpm, session: &mut TpmSession) -> Result<Vec<u8>> {
        nv_read(tpm, session, self.get_index())
    }

    pub fn get_public(&self) -> TpmtPublic {
        match self {
            Self::Ecc => TpmtPublic {
                // [TCG EK Credential Profile v2.5r2] p.39 Table 3: Default EK Template (TPMT_PUBLIC) L-2: ECC NIST P256 (Storage)
                algorithm_type: TpmiAlgorithmPublic::Ecc,
                algorithm_name: TpmiAlgorithmHash::Sha256,
                object_attributes: TpmAttrObject::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_admin_with_policy(true)
                    .with_restricted(true)
                    .with_decrypt(true),
                auth_policy: Tpm2BDigest::new(&[
                    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46,
                    0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1,
                    0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
                ]), // TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
                parameters: TpmuPublicParams::EccDetail(TpmsEccParams {
                    symmetric: TpmtSymdefObject {
                        algorithm: TpmiAlgorithmSymObject::Aes,
                        key_bits: TpmuSymKeybits::SymmetricAlgo(128),
                        mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
                    },
                    scheme: TpmtEccScheme {
                        scheme: TpmiAlgorithmEccScheme::Null,
                        details: TpmuAsymmetricScheme::Null,
                    },
                    curve_id: TpmEccCurve::NistP256,
                    kdf: TpmtKdfScheme {
                        scheme: TpmiAlgorithmKdf::Null,
                        details: TpmuKdfScheme::Null,
                    },
                }),
                unique: TpmuPublicIdentifier::Ecc(TpmsEccPoint {
                    x: Tpm2BDigest::new(&[0; 32]),
                    y: Tpm2BDigest::new(&[0; 32]),
                }),
            },
            Self::Rsa => TpmtPublic {
                // [TCG EK Credential Profile v2.5r2] p.38 Table 3: Default EK Template (TPMT_PUBLIC) L-1: RSA 2048 (Storage)
                algorithm_type: TpmiAlgorithmPublic::Rsa,
                algorithm_name: TpmiAlgorithmHash::Sha256,
                object_attributes: TpmAttrObject::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_admin_with_policy(true)
                    .with_restricted(true)
                    .with_decrypt(true),
                auth_policy: Tpm2BDigest::new(&[
                    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46,
                    0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1,
                    0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
                ]), // TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
                parameters: TpmuPublicParams::RsaDetail(TpmsRsaParams {
                    symmetric: TpmtSymdefObject {
                        algorithm: TpmiAlgorithmSymObject::Aes,
                        key_bits: TpmuSymKeybits::SymmetricAlgo(128),
                        mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
                    },
                    scheme: TpmtRsaScheme {
                        scheme: TpmiAlgorithmRsaScheme::Null,
                        details: TpmuAsymmetricScheme::Null,
                    },
                    key_bits: 2048,
                    exponent: 0,
                }),
                unique: TpmuPublicIdentifier::Rsa(Tpm2BPublicKeyRsa::new(&[0; 256])),
            },
        }
    }

    pub fn create_endorsement_key(
        &self,
        tpm: &mut Tpm,
        session: &mut TpmSession,
    ) -> Result<Tpm2CreatePrimaryResponse> {
        create_primary(
            TpmPermanentHandle::Endorsement.into(),
            &[],
            tpm,
            session,
            Tpm2BPublic::new(self.get_public()),
        )
    }
}

pub fn decide_key_type(tpm: &mut Tpm) -> Result<EkType> {
    if let TpmuCapabilities::Handles(nv) = tpm
        .get_capability(
            TpmCapabilities::Handles,
            (TpmHandleType::NvIndex as u32) << 24,
            10,
        )?
        .1
        .data
    {
        let mut found_ecc = false;
        let mut found_rsa = false;
        for handle in &nv.handle {
            found_ecc |= *handle == EkType::Ecc.get_index();
            found_rsa |= *handle == EkType::Rsa.get_index();
        }
        Ok(if found_ecc {
            EkType::Ecc
        } else if found_rsa {
            EkType::Rsa
        } else {
            panic!("EK Certificate doesn't found on this TPM");
        })
    } else {
        panic!("EK Certificate doesn't found on this TPM");
    }
}
