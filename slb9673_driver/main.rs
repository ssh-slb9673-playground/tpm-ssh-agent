mod driver;

fn main() -> tpm_i2c::TpmResult<()> {
    use tpm_i2c::tpm::structure::{
        TpmCapabilities, TpmiAlgorithmPublic, TpmiAlgorithmSymMode, TpmiAlgorithmSymmetric,
        TpmsSymcipherParams, TpmtPublicParams, TpmtSymdefObject, TpmuPublicParams, TpmuSymKeybits,
        TpmuSymMode,
    };
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

    // println!("{:?}", tpm.read_status()?);

    tpm.shutdown(false)?;

    Ok(())
}
