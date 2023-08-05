mod driver;
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
            let x = &tpm.flush_context(*handle);
            dbg!(x);
        }
    }
    Ok(())
}

#[allow(unused_must_use)]
fn main() -> tpm_i2c::TpmResult<()> {
    use tpm_i2c::tpm::session::TpmSession;
    use tpm_i2c::tpm::structure::*;

    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut tpm = Tpm::new(&mut device)?;
    tpm.init(true)?;

    remove_handles(&mut tpm, TpmHandleType::HmacOrLoadedSession)?;
    remove_handles(&mut tpm, TpmHandleType::Transient)?;

    tpm.print_info()?;

    let caller_nonce_first = tpm.get_random(16)?;

    tpm.test_params(TpmtPublicParams {
        algorithm_type: TpmiAlgorithmPublic::Rsa,
        parameters: TpmuPublicParams::RsaDetail(TpmsRsaParams {
            symmetric: TpmtSymdefObject {
                algorithm: TpmiAlgorithmSymObject::Aes,
                key_bits: TpmuSymKeybits::SymmetricAlgo(128),
                mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
            },
            scheme: TpmtRsaScheme {
                scheme: TpmiAlgorithmRsaScheme::RsaEs,
                details: TpmuAsymmetricScheme::Encryption(TpmsEncryptionScheme::AE(
                    TpmsEmpty::new(),
                )),
            },
            key_bits: 2048,
            exponent: 65537,
        }),
    })?;

    println!("Test OK");

    let (_res, handle, tpm_nonce) = tpm.start_auth_session(
        TpmiDhObject::Null,
        TpmiDhEntity::Null,
        Tpm2BNonce::new(&caller_nonce_first),
        Tpm2BEncryptedSecret::new(&[]),
        TpmSessionType::Hmac,
        TpmtSymdef {
            algorithm: TpmiAlgorithmSymmetric::Aes,
            key_bits: TpmuSymKeybits::SymmetricAlgo(128),
            mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
        },
        TpmiAlgorithmHash::Sha256,
    )?;

    let mut session = TpmSession::new(
        TpmiAlgorithmHash::Sha256,
        handle,
        TpmAttrSession::new().with_continue_session(true),
        TpmPermanentHandle::Null,
        TpmPermanentHandle::Null,
    );

    let _aes_template = Tpm2BPublic::new(TpmtPublic {
        algorithm_type: TpmiAlgorithmPublic::SymCipher,
        algorithm_name: TpmiAlgorithmHash::Sha256,
        object_attributes: TpmAttrObject::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_no_dictionary_attack(true)
            .with_decrypt(true),
        auth_policy: Tpm2BDigest::new(&[]),
        parameters: TpmuPublicParams::SymDetail(TpmsSymcipherParams {
            sym: TpmtSymdefObject {
                algorithm: TpmiAlgorithmSymObject::Aes,
                key_bits: TpmuSymKeybits::SymmetricAlgo(128),
                mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
            },
        }),
        unique: TpmuPublicIdentifier::Sym(Tpm2BDigest::new(&[])),
    });

    let _rsa_template = Tpm2BPublic::new(TpmtPublic {
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
        parameters: TpmuPublicParams::RsaDetail(TpmsRsaParams {
            symmetric: TpmtSymdefObject {
                algorithm: TpmiAlgorithmSymObject::Null,
                key_bits: TpmuSymKeybits::Null,
                mode: TpmuSymMode::Null,
            },
            scheme: TpmtRsaScheme {
                scheme: TpmiAlgorithmRsaScheme::RsaEs,
                details: TpmuAsymmetricScheme::Encryption(TpmsEncryptionScheme::AE(
                    TpmsEmpty::new(),
                )),
            },
            key_bits: 2048,
            exponent: 65537,
        }),
        unique: TpmuPublicIdentifier::Sym(Tpm2BDigest::new(&[])),
    });

    session.set_caller_nonce(caller_nonce_first);
    session.set_tpm_nonce(tpm_nonce.buffer);
    session.set_caller_nonce([0u8; 16].to_vec());

    println!("Session handle: {:08x}", handle);

    let res = tpm.create_primary(
        TpmPermanentHandle::Platform.into(),
        session.clone(),
        Tpm2BSensitiveCreate {
            sensitive: TpmsSensitiveCreate {
                user_auth: Tpm2BAuth::new("initial auth value".as_bytes()),
                data: Tpm2BSensitiveData::new(&[]),
            },
        },
        _rsa_template,
        Tpm2BData::new(&[]),
        TpmlPcrSelection {
            pcr_selections: vec![],
        },
    );
    dbg!(res);

    // println!("{:?}", tpm.read_status()?);

    tpm.flush_context(handle)?;

    tpm.shutdown(true)?;

    Ok(())
}
