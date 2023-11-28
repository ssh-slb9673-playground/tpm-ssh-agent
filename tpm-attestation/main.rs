#![allow(dead_code)]
mod driver;
mod error;
use rand::prelude::*;
use tpm_i2c::tpm::commands::*;
use tpm_i2c::tpm::session::TpmSession;
use tpm_i2c::tpm::structure::*;
use tpm_i2c::tpm::Tpm;

use crate::error::Result;

fn main() -> Result<()> {
    let mut tpm = Tpm::new(Box::new(driver::hidapi::MCP2221A::new(0x2e)?))?;
    if matches!(
        tpm.init(false),
        Err(tpm_i2c::Error::TpmError(
            tpm_i2c::tpm::TpmError::UnsuccessfulResponse(TpmResponseCode::ErrorForParam((
                _,
                TpmResponseCodeFormat1::Value
            )),)
        ))
    ) {
        println!("[*] Startup without all data");
        tpm.init(true)?;
    }

    remove_handles(&mut tpm, TpmHandleType::HmacOrLoadedSession)?;
    remove_handles(&mut tpm, TpmHandleType::Transient)?;

    tpm.print_info()?;
    let mut session = open_session(&mut tpm)?;
    println!("Session Opened: {:08x}", session.handle);

    println!("[+] NV indexes:");
    if let TpmuCapabilities::Handles(nv) = tpm
        .get_capability(
            TpmCapabilities::Handles,
            (TpmHandleType::NvIndex as u32) << 24,
            10,
        )?
        .1
        .data
    {
        for handle in &nv.handle {
            println!("  - 0x{:08x}", handle);
        }
    }

    println!("[+] Persistent Keys:");
    if let TpmuCapabilities::Handles(handles) = tpm
        .get_capability(
            TpmCapabilities::Handles,
            (TpmHandleType::Persistent as u32) << 24,
            10,
        )?
        .1
        .data
    {
        for handle in &handles.handle {
            println!("  - 0x{:08x}", handle);
        }
    }

    println!("Generate: EK");
    let _endorsement_key = create_endorsement_key(&mut tpm, &mut session)?;
    println!("Generate: AK");
    let attestation_key = create_signing_key("password".as_bytes(), &mut tpm, &mut session)?;
    dbg!(&attestation_key);

    println!("Generate: MK");
    session.set_entity_auth_value("password".as_bytes());
    let main_key = create_main_key(
        attestation_key.handle,
        "password".as_bytes(),
        &mut tpm,
        &mut session,
    )?;

    dbg!(&main_key);

    let _ek_certificate = nv_read(&mut tpm, &mut session, 0x01c0000a)?;

    tpm.flush_context(session.handle)?;
    tpm.shutdown(false)?;

    Ok(())
}

fn nv_read(tpm: &mut Tpm, session: &mut TpmSession, nv_index: TpmHandle) -> Result<Vec<u8>> {
    let res = tpm.nv_read_public(&TpmiHandleNvIndex::NvIndex(nv_index))?;
    dbg!(&res.0.nv_public.as_ref().unwrap());
    let mut size = res.0.nv_public.unwrap().data_size;
    let mut res = vec![];

    loop {
        let data = tpm.nv_read(
            session,
            &TpmiHandleNvAuth::Owner,
            &TpmiHandleNvIndex::NvIndex(nv_index),
            size.min(NV_BUFFER_MAX),
            0,
        )?;
        res.extend(data);
        if size < NV_BUFFER_MAX {
            break;
        }
        size -= NV_BUFFER_MAX;
    }
    Ok(res)
}

fn remove_handles(tpm: &mut Tpm, ht: TpmHandleType) -> Result<()> {
    use tpm_i2c::tpm::structure::*;
    if let TpmuCapabilities::Handles(x) = &tpm
        .get_capability(TpmCapabilities::Handles, (ht as u32) << 24, 5)?
        .1
        .data
    {
        for handle in &x.handle {
            println!("[+] Flush 0x{:08x}", handle);
            let _ = &tpm.flush_context(*handle);
        }
    }
    Ok(())
}

fn create_endorsement_key(
    tpm: &mut Tpm,
    session: &mut TpmSession,
) -> Result<tpm_i2c::tpm::commands::Tpm2CreatePrimaryResponse> {
    create_primary(
        TpmPermanentHandle::Endorsement.into(),
        &[],
        tpm,
        session,
        Tpm2BPublic::new(TpmtPublic {
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
                131, 113, 151, 103, 68, 132, 179, 248, 26, 144, 204, 141, 70, 165, 215, 36, 253,
                82, 215, 110, 6, 82, 11, 100, 242, 161, 218, 27, 51, 20, 105, 170,
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
        }),
    )
}

fn create_main_key(
    parent_handle: TpmHandle,
    auth_value: &[u8],
    tpm: &mut Tpm,
    session: &mut TpmSession,
) -> Result<tpm_i2c::tpm::commands::Tpm2CreateResponse> {
    create(
        parent_handle,
        auth_value,
        tpm,
        session,
        Tpm2BPublic::new(TpmtPublic {
            algorithm_type: TpmiAlgorithmPublic::Rsa,
            algorithm_name: TpmiAlgorithmHash::Sha256,
            object_attributes: TpmAttrObject::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_decrypt(true),
            auth_policy: Tpm2BDigest::new(&[]),
            parameters: TpmuPublicParams::RsaDetail(TpmsRsaParams {
                key_bits: 2048,
                exponent: 65537,
                symmetric: TpmtSymdefObject {
                    algorithm: TpmiAlgorithmSymObject::Null,
                    key_bits: TpmuSymKeybits::Null,
                    mode: TpmuSymMode::Null,
                },
                scheme: TpmtRsaScheme {
                    scheme: TpmiAlgorithmRsaScheme::Oaep,
                    details: TpmuAsymmetricScheme::Encryption(TpmsEncryptionScheme::AEH(
                        TpmsSchemeHash {
                            hash_algorithm: TpmiAlgorithmHash::Sha256,
                        },
                    )),
                },
            }),
            unique: TpmuPublicIdentifier::Rsa(Tpm2BPublicKeyRsa::new(&[0; 256])),
        }),
    )
}

fn create_signing_key(
    auth_value: &[u8],
    tpm: &mut Tpm,
    session: &mut TpmSession,
) -> Result<tpm_i2c::tpm::commands::Tpm2CreatePrimaryResponse> {
    create_primary(
        TpmPermanentHandle::Owner.into(),
        auth_value,
        tpm,
        session,
        Tpm2BPublic::new(TpmtPublic {
            algorithm_type: TpmiAlgorithmPublic::Ecc,
            algorithm_name: TpmiAlgorithmHash::Sha256,
            object_attributes: TpmAttrObject::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_sign_or_encrypt(true),
            auth_policy: Tpm2BDigest::new(&[]),
            parameters: TpmuPublicParams::EccDetail(TpmsEccParams {
                symmetric: TpmtSymdefObject {
                    algorithm: TpmiAlgorithmSymObject::Null,
                    key_bits: TpmuSymKeybits::Null,
                    mode: TpmuSymMode::Null,
                },
                scheme: TpmtEccScheme {
                    scheme: TpmiAlgorithmEccScheme::EcDsa,
                    details: TpmuAsymmetricScheme::Signature(TpmsSignatureScheme::AX(
                        TpmsSchemeHash {
                            hash_algorithm: TpmiAlgorithmHash::Sha256,
                        },
                    )),
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
        }),
    )
}

fn create_primary(
    primary_handle: TpmHandle,
    auth_value: &[u8],
    tpm: &mut Tpm,
    session: &mut TpmSession,
    public_area: Tpm2BPublic,
) -> Result<tpm_i2c::tpm::commands::Tpm2CreatePrimaryResponse> {
    tpm.create_primary(
        primary_handle,
        session,
        Tpm2CreateParameters {
            in_sensitive: Tpm2BSensitiveCreate {
                sensitive: TpmsSensitiveCreate {
                    user_auth: Tpm2BAuth::new(auth_value),
                    data: Tpm2BSensitiveData::new(&[]),
                },
            },
            in_public: public_area,
            outside_info: Tpm2BData::new(&[]),
            creation_pcr: TpmlPcrSelection {
                pcr_selections: vec![],
            },
        },
    )
    .map_err(|err| err.into())
}

fn create(
    parent_handle: TpmHandle,
    auth_value: &[u8],
    tpm: &mut Tpm,
    session: &mut TpmSession,
    public_area: Tpm2BPublic,
) -> Result<tpm_i2c::tpm::commands::Tpm2CreateResponse> {
    tpm.create(
        parent_handle,
        session,
        Tpm2CreateParameters {
            in_sensitive: Tpm2BSensitiveCreate {
                sensitive: TpmsSensitiveCreate {
                    user_auth: Tpm2BAuth::new(auth_value),
                    data: Tpm2BSensitiveData::new(&[]),
                },
            },
            in_public: public_area,
            outside_info: Tpm2BData::new(&[]),
            creation_pcr: TpmlPcrSelection {
                pcr_selections: vec![],
            },
        },
    )
    .map_err(|err| err.into())
}

fn open_session(tpm: &mut Tpm) -> Result<TpmSession> {
    let mut session = tpm.start_auth_session(
        TpmiDhObject::Null,
        TpmiDhEntity::Null,
        Tpm2BNonce::new(&next_nonce()),
        Tpm2BEncryptedSecret::new(&[]),
        TpmSessionType::Hmac,
        TpmtSymdef {
            algorithm: TpmiAlgorithmSymmetric::Null,
            key_bits: TpmuSymKeybits::Null,
            mode: TpmuSymMode::Null,
        },
        TpmiAlgorithmHash::Sha256,
    )?;
    session.attributes.set_continue_session(true);

    Ok(session)
}

fn next_nonce() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut ret = [0u8; 16];
    rng.fill_bytes(&mut ret);
    ret
}
