mod driver;

fn main() -> tpm_i2c::TpmResult<()> {
    use tpm_i2c::tpm::structure::{TpmAttrSession, TpmAuthCommand, TpmPermanentHandle};
    use tpm_i2c::tpm::Tpm;

    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut tpm = Tpm::new(&mut device)?;
    tpm.init()?;

    tpm.print_info()?;

    let auth = TpmAuthCommand::new(
        TpmPermanentHandle::Password.into(),
        &[],
        TpmAttrSession::new().with_continue_session(true),
        &[0x41, 0x42, 0x43],
    );

    dbg!(tpm.get_random_with_session(32, auth)?);

    // println!("{:?}", tpm.read_status()?);

    Ok(())
}
