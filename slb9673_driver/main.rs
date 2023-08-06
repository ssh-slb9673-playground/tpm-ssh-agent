mod driver;
use tpm_i2c::tpm::session::TpmSession;
use tpm_i2c::tpm::structure::*;
use tpm_i2c::tpm::Tpm;

fn remove_handles(
    tpm: &mut Tpm<driver::hidapi::MCP2221A>,
    ht: tpm_i2c::tpm::structure::TpmHandleType,
) -> tpm_i2c::TpmResult<()> {
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

fn get_rsa_public_template(bits: u16, symmetric: TpmtSymdefObject) -> TpmuPublicParams {
    TpmuPublicParams::RsaDetail(TpmsRsaParams {
        symmetric,
        scheme: TpmtRsaScheme {
            scheme: TpmiAlgorithmRsaScheme::RsaEs,
            details: TpmuAsymmetricScheme::Encryption(TpmsEncryptionScheme::AE(TpmsEmpty::new())),
        },
        key_bits: bits,
        exponent: 65537,
    })
}

fn get_aes_symdefobj() -> TpmtSymdefObject {
    TpmtSymdefObject {
        algorithm: TpmiAlgorithmSymObject::Aes,
        key_bits: TpmuSymKeybits::SymmetricAlgo(128),
        mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
    }
}

fn get_null_symdefobj() -> TpmtSymdefObject {
    TpmtSymdefObject {
        algorithm: TpmiAlgorithmSymObject::Null,
        key_bits: TpmuSymKeybits::Null,
        mode: TpmuSymMode::Null,
    }
}

fn create_primary_key<T: tpm_i2c::tpm::I2CTpmAccessor>(
    tpm: &mut Tpm<T>,
    session: TpmSession,
    auth_value: &[u8],
) -> tpm_i2c::TpmResult<tpm_i2c::tpm::commands::Tpm2CreatePrimaryResponse> {
    tpm.create_primary(
        TpmPermanentHandle::Platform.into(),
        session.clone(),
        Tpm2BSensitiveCreate {
            sensitive: TpmsSensitiveCreate {
                user_auth: Tpm2BAuth::new(auth_value),
                data: Tpm2BSensitiveData::new(&[]),
            },
        },
        Tpm2BPublic::new(TpmtPublic {
            algorithm_type: TpmiAlgorithmPublic::Rsa,
            algorithm_name: TpmiAlgorithmHash::Sha256,
            object_attributes: TpmAttrObject::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_no_dictionary_attack(true)
                .with_decrypt(true)
                .with_user_with_auth(true),
            auth_policy: Tpm2BDigest::new(&[]),
            parameters: get_rsa_public_template(2048, get_null_symdefobj()),
            unique: TpmuPublicIdentifier::Rsa(Tpm2BDigest::new(&[])),
        }),
        Tpm2BData::new(&[]),
        TpmlPcrSelection {
            pcr_selections: vec![],
        },
    )
}

#[allow(unused_must_use)]
fn main() -> tpm_i2c::TpmResult<()> {
    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut tpm = Tpm::new(&mut device)?;
    tpm.init(true)?;

    remove_handles(&mut tpm, TpmHandleType::HmacOrLoadedSession)?;
    remove_handles(&mut tpm, TpmHandleType::Transient)?;

    tpm.print_info()?;

    let caller_nonce_first = tpm.get_random(16)?;
    let mut session = tpm.start_auth_session(
        TpmiDhObject::Null,
        TpmiDhEntity::Null,
        Tpm2BNonce::new(&caller_nonce_first),
        Tpm2BEncryptedSecret::new(&[]),
        TpmSessionType::Hmac,
        TpmtSymdef {
            algorithm: TpmiAlgorithmSymmetric::Null,
            key_bits: TpmuSymKeybits::Null,
            mode: TpmuSymMode::Null,
        },
        TpmiAlgorithmHash::Sha256,
    )?;

    session.set_caller_nonce([0u8; 16].to_vec());

    println!("Session handle: {:08x}", &session.handle);

    let res = create_primary_key(&mut tpm, session.clone(), "password".as_bytes())?;

    println!("Key handle: {:08x}", res.handle);

    let e = if let TpmuPublicParams::RsaDetail(params) =
        &res.out_public.public_area.as_ref().unwrap().parameters
    {
        params.exponent
    } else {
        unreachable!()
    };

    let n = if let TpmuPublicIdentifier::Rsa(data) =
        &res.out_public.public_area.as_ref().unwrap().unique
    {
        &data.buffer
    } else {
        unreachable!();
    };

    println!("e = {:x?}", &e);
    println!("n = {:x?}", &n);

    tpm.flush_context(res.handle)?;

    tpm.shutdown(true)?;

    Ok(())
}
