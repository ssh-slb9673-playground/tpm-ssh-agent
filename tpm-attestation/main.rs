#![allow(dead_code)]
mod driver;
mod error;
use rand::prelude::*;
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
    let session = open_session(&mut tpm)?;
    println!("Session Opened: {:08x}", session.handle);

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
            println!("[+] 0x{:08x}", handle);
        }
    }

    let (data, session) = nv_read(&mut tpm, session, 0x01c00016)?;
    println!("{:?}", data);

    tpm.flush_context(session.handle)?;
    tpm.shutdown(false)?;

    Ok(())
}

fn nv_read(
    tpm: &mut Tpm,
    session: TpmSession,
    nv_index: TpmHandle,
) -> Result<(Vec<u8>, TpmSession)> {
    let res = tpm.nv_read_public(&TpmiHandleNvIndex::NvIndex(nv_index))?;
    let mut new_session = session.clone();
    let mut size = res.0.nv_public.unwrap().data_size;
    let mut res = vec![];

    loop {
        let data = tpm.nv_read(
            &mut new_session,
            vec![],
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
    Ok((res, new_session))
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

fn create_primary_key(
    tpm: &mut Tpm,
    auth_value: &[u8],
    session: &mut TpmSession,
) -> Result<tpm_i2c::tpm::commands::Tpm2CreatePrimaryResponse> {
    tpm.create_primary(
        TpmPermanentHandle::Owner.into(),
        session,
        vec![],
        Tpm2BSensitiveCreate {
            sensitive: TpmsSensitiveCreate {
                user_auth: Tpm2BAuth::new(auth_value),
                data: Tpm2BSensitiveData::new(&[]),
            },
        },
        Tpm2BPublic::new(TpmtPublic {
            algorithm_type: TpmiAlgorithmPublic::Ecc,
            algorithm_name: TpmiAlgorithmHash::Sha256,
            object_attributes: TpmAttrObject::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_sign_or_encrypt(true)
                .with_user_with_auth(true),
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
        Tpm2BData::new(&[]),
        TpmlPcrSelection {
            pcr_selections: vec![],
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
        vec![],
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
