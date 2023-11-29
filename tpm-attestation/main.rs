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

    println!("Generate: SRK");

    let storage_root_key =
        create_storage_root_key("srk_authvalue".as_bytes(), &mut tpm, &mut session)?;

    println!("Generate: AK");
    session.set_entity_auth_value("srk_authvalue".as_bytes());
    let attestation_key = create_attestation_key(
        storage_root_key.handle,
        "attestation_key_authvalue".as_bytes(),
        &mut tpm,
        &mut session,
    )?;

    let (ak_handle, ak_name) = tpm.load(
        storage_root_key.handle,
        &mut session,
        attestation_key.out_private.clone(),
        attestation_key.out_public.clone(),
    )?;

    println!("ak_handle: {:08x}", ak_handle);
    println!("ak_name: {:?}", ak_name);

    println!("Generate: EK");
    session.set_entity_auth_value(&[]);
    let endorsement_key = create_endorsement_key(&mut tpm, &mut session)?;
    let _ek_certificate = nv_read(&mut tpm, &mut session, 0x01c0000a)?;

    let credential = Tpm2BDigest::new("test data".as_bytes());
    let (credential_blob, secret) =
        tpm.make_credential(endorsement_key.handle, credential.clone(), ak_name)?;

    println!("credential_blob: {:?}", credential_blob);
    println!("secret: {:?}", secret);

    let mut ek_session = tpm.start_auth_session(
        TpmiDhObject::Null,
        TpmiDhEntity::Null,
        Tpm2BNonce::new(&next_nonce()),
        Tpm2BEncryptedSecret::new(&[]),
        TpmSessionType::Policy,
        TpmtSymdef {
            algorithm: TpmiAlgorithmSymmetric::Null,
            key_bits: TpmuSymKeybits::Null,
            mode: TpmuSymMode::Null,
        },
        TpmiAlgorithmHash::Sha256,
    )?;
    ek_session.attributes.set_continue_session(true);
    println!("ek_session: {:08x}", ek_session.handle);

    println!("PolicySecret");
    tpm.policy_secret(
        TpmPermanentHandle::Endorsement.into(),
        ek_session.handle,
        &mut session,
        PolicySecretParameters {
            nonce_tpm: Tpm2BDigest::new(&[]),
            cphash_a: Tpm2BDigest::new(&[]),
            policy_reference: Tpm2BDigest::new(&[]),
            expiration: 0,
        },
    )?;

    println!("ActivateCredential");
    session.set_entity_auth_value("attestation_key_authvalue".as_bytes());
    let generated_credential = tpm.activate_credential(
        ak_handle,
        endorsement_key.handle,
        (&mut session, &mut ek_session),
        credential_blob,
        secret,
    )?;

    assert_eq!(credential.buffer, generated_credential.buffer);
    println!("Remote Attestation Successed!");

    tpm.flush_context(ek_session.handle)?;
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
                0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5,
                0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B,
                0x33, 0x14, 0x69, 0xAA,
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
                x: Tpm2BDigest::new(&[]),
                y: Tpm2BDigest::new(&[]),
            }),
        }),
    )
}

fn create_attestation_key(
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
                x: Tpm2BDigest::new(&[]),
                y: Tpm2BDigest::new(&[]),
            }),
        }),
    )
}

fn create_storage_root_key(
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
            algorithm_type: TpmiAlgorithmPublic::SymCipher,
            algorithm_name: TpmiAlgorithmHash::Sha256,
            object_attributes: TpmAttrObject::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_decrypt(true)
                .with_restricted(true),
            auth_policy: Tpm2BDigest::new(&[]),
            parameters: TpmuPublicParams::SymDetail(TpmsSymcipherParams {
                sym: TpmtSymdefObject {
                    algorithm: TpmiAlgorithmSymObject::Aes,
                    key_bits: TpmuSymKeybits::SymmetricAlgo(256),
                    mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
                },
            }),
            unique: TpmuPublicIdentifier::Sym(Tpm2BDigest::new(&[])),
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
