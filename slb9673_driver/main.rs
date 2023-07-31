mod driver;

fn main() -> tpm_i2c::TpmResult<()> {
    use tpm_i2c::tpm::structure::{TpmAttrSession, TpmAuthCommand, TpmPermanentHandle};
    use tpm_i2c::tpm::Tpm;

    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut tpm = Tpm::new(&mut device)?;
    tpm.init(false)?;

    tpm.print_info()?;

    let _auth = TpmAuthCommand::new(
        TpmPermanentHandle::Password.into(),
        &[],
        TpmAttrSession::new().with_continue_session(true),
        &[0x41, 0x42, 0x43],
    );

    // println!("{:?}", tpm.read_status()?);

    tpm.shutdown(false)?;

    Ok(())
}
