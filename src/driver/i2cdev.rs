extern crate i2cdev;
use crate::tpm::I2CTPMAccessor;
use crate::TPMResult;
use i2cdev::core::*;
use i2cdev::linux::LinuxI2CDevice;

impl I2CTPMAccessor for LinuxI2CDevice {
    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TPMResult<()> {
        self.read(read_buf)?;
        Ok(())
    }

    fn i2c_write(&mut self, write_buf: &[u8]) -> TPMResult<()> {
        self.write(write_buf)?;
        Ok(())
    }
}
