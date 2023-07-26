extern crate i2cdev;
use crate::tpm::I2CTpmAccessor;
use crate::{Error, TpmResult};
use i2cdev::core::*;
use i2cdev::linux::LinuxI2CDevice;

impl std::convert::From<i2cdev::linux::LinuxI2CError> for Error {
    fn from(err: i2cdev::linux::LinuxI2CError) -> Error {
        Error::LinuxI2CError(err)
    }
}

impl I2CTpmAccessor for LinuxI2CDevice {
    fn initialize(&mut self) -> TpmResult<()> {
        Ok(())
    }

    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TpmResult<()> {
        self.read(read_buf)?;
        Ok(())
    }

    fn i2c_write(&mut self, write_buf: &[u8]) -> TpmResult<()> {
        self.write(write_buf)?;
        Ok(())
    }
}
