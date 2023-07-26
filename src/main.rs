extern crate tpm_i2c;

fn main() -> tpm_i2c::TpmResult<()> {
    use tpm_i2c::tpm::Tpm;

    let device = hidapi::HidApi::new()?.open(0x04d8, 0x00dd)?;
    // let mut tpm = Tpm::new(Box::new(LinuxI2CDevice::new("/dev/i2c-9", 0x2e)?))?;
    let mut tpm = Tpm::new(Box::new(device))?;
    tpm.init()?;

    tpm.print_info()?;

    dbg!(tpm.get_random(20)?);

    // println!("{:?}", tpm.read_status()?);

    Ok(())
}
