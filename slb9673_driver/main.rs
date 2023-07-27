mod driver;

fn main() -> tpm_i2c::TpmResult<()> {
    use tpm_i2c::tpm::Tpm;

    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut tpm = Tpm::new(&mut device)?;
    tpm.init()?;

    tpm.print_info()?;

    dbg!(tpm.get_random(20)?);

    // println!("{:?}", tpm.read_status()?);

    Ok(())
}
