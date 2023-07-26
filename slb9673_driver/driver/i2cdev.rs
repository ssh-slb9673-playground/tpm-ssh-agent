extern crate i2cdev;
use i2cdev::core::*;
use i2cdev::linux::LinuxI2CDevice;
use tpm_i2c::tpm::I2CTpmAccessor;
use tpm_i2c::TpmResult;

struct I2CDev {
    device: LinuxI2CDevice,
}

impl I2CTpmAccessor for I2CDev {
    fn initialize(&mut self) -> TpmResult<()> {
        Ok(())
    }

    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TpmResult<()> {
        self.device.read(read_buf)?;
        Ok(())
    }

    fn i2c_write(&mut self, write_buf: &[u8]) -> TpmResult<()> {
        self.device.write(write_buf)?;
        Ok(())
    }
}
