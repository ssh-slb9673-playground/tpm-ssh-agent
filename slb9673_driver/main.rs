mod driver;

fn main() -> tpm_i2c::TpmResult<()> {
    use tpm_i2c::tpm::structure::*;
    use tpm_i2c::tpm::Tpm;

    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut tpm = Tpm::new(&mut device)?;
    tpm.init(true)?;

    tpm.print_info()?;

    dbg!(tpm.get_capability(TpmCapabilities::Algs, 0, 1)?);

    dbg!(tpm.test_params(TpmtPublicParams {
        algorithm_type: TpmiAlgorithmPublic::SymCipher,
        parameters: TpmuPublicParams::SymDetail(TpmsSymcipherParams {
            sym: TpmtSymdefObject {
                algorithm: TpmiAlgorithmSymmetric::Aes,
                key_bits: TpmuSymKeybits::SymmetricAlgo(128),
                mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
            },
        }),
    })?);

    let password = "password".as_bytes();

    let session = TpmAuthCommand {
        session_handle: TpmPermanentHandle::Password as u32,
        nonce: Tpm2BNonce::new(&[]),
        session_attributes: TpmAttrSession::new(),
        hmac: Tpm2BAuth::new(password),
    };

    tpm.create_primary(
        TpmPermanentHandle::Null.into(),
        session.clone(),
        Tpm2BSensitiveCreate {
            sensitive: TpmsSensitiveCreate {
                user_auth: Tpm2BAuth::new(password),
                data: Tpm2BSensitiveData::new("test".as_bytes()),
            },
        },
        Tpm2BPublic::new(TpmtPublic {
            algorithm_type: TpmiAlgorithmPublic::SymCipher,
            algorithm_name: TpmiAlgorithmHash::Sha512,
            object_attributes: TpmAttrObject::new(),
            auth_policy: Tpm2BDigest::new(&[]),
            parameters: TpmuPublicParams::SymDetail(TpmsSymcipherParams {
                sym: TpmtSymdefObject {
                    algorithm: TpmiAlgorithmSymmetric::Aes,
                    key_bits: TpmuSymKeybits::SymmetricAlgo(128),
                    mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
                },
            }),
            unique: TpmuPublicIdentifier::Sym(Tpm2BDigest::new(&[])),
        }),
        Tpm2BData::new(&[]),
        TpmlPcrSelection {
            algorithm_hash: TpmiAlgorithmHash::Sha1,
            pcr_select: vec![],
        },
    )?;

    // println!("{:?}", tpm.read_status()?);

    tpm.shutdown(false)?;

    Ok(())
}
