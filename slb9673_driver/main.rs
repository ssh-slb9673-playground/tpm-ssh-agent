mod driver;

#[allow(unused_must_use)]
fn main() -> tpm_i2c::TpmResult<()> {
    use tpm_i2c::tpm::session::TpmSession;
    use tpm_i2c::tpm::structure::*;
    use tpm_i2c::tpm::Tpm;

    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut tpm = Tpm::new(&mut device)?;
    tpm.init(true)?;

    tpm.print_info()?;

    if let TpmuCapabilities::Handles(x) = tpm
        .get_capability(
            TpmCapabilities::Handles,
            (TpmHandleType::HmacOrLoadedSession as u32) << 24,
            5,
        )?
        .1
        .data
    {
        for handle in x.handle {
            println!("[+] Flush 0x{:08x}", handle);
            let x = tpm.flush_context(handle);
            dbg!(x);
        }
    }

    let caller_nonce_first = tpm.get_random(16)?;

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

    session.set_caller_nonce(caller_nonce_first);
    session.set_tpm_nonce(tpm_nonce.buffer);

    println!("Session handle: {:08x}", handle);

    let res = tpm.create_primary(
        TpmPermanentHandle::Owner.into(),
        session.clone(),
        Tpm2BSensitiveCreate {
            sensitive: TpmsSensitiveCreate {
                user_auth: Tpm2BAuth::new("initial auth value".as_bytes()),
                data: Tpm2BSensitiveData::new(&[]),
            },
        },
        Tpm2BPublic::new(TpmtPublic {
            algorithm_type: TpmiAlgorithmPublic::SymCipher,
            algorithm_name: TpmiAlgorithmHash::Sha512,
            object_attributes: TpmAttrObject::new(),
            auth_policy: Tpm2BDigest::new(&[]),
            parameters: TpmuPublicParams::SymDetail(TpmsSymcipherParams {
                sym: TpmtSymdefObject {
                    algorithm: TpmiAlgorithmSymObject::Aes,
                    key_bits: TpmuSymKeybits::SymmetricAlgo(128),
                    mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
                },
            }),
            unique: TpmuPublicIdentifier::Sym(Tpm2BDigest::new(&[])),
        }),
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
