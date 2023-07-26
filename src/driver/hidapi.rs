extern crate hidapi;

use crate::tpm::I2CTpmAccessor;
use crate::{Error, TpmResult};
use std::thread::sleep;
use std::time::Duration;

const TPM_ADDR: u8 = 0x2e;
const TPM_ADDR_W: u8 = (TPM_ADDR << 1) | 1;
const TPM_ADDR_R: u8 = TPM_ADDR << 1;

impl std::convert::From<hidapi::HidError> for Error {
    fn from(err: hidapi::HidError) -> Error {
        Error::HidApiError(err)
    }
}

pub fn wait_busy(device: &hidapi::HidDevice) -> TpmResult<()> {
    loop {
        device.write(&[0x10u8, 0, 0, 0, 0])?;
        let mut buf = [0u8; 65];
        device.read(&mut buf)?;
        if buf[8] == 0 {
            break;
        }
        sleep(Duration::from_millis(50));
    }
    Ok(())
}

pub fn setup_i2c(device: &hidapi::HidDevice) -> TpmResult<()> {
    device.write(&[0x10u8, 0, 0, 0, 0])?;
    let mut buf = [0u8; 65];
    device.read(&mut buf)?;
    if buf[8] != 0 {
        // need to cancel current transport
        device.write(&[0x10u8, 0, 0x10, 0, 0])?;
        let mut buf = [0u8; 65];
        device.read(&mut buf)?;

        sleep(Duration::from_millis(250));
    }
    loop {
        device.write(&[0x10u8, 0, 0, 0x20, 22])?; // 500kHz
        let mut buf = [0u8; 65];
        device.read(&mut buf)?;
        if buf[3] == 0x20 {
            // changing success
            break;
        }
        sleep(Duration::from_millis(250));
    }
    Ok(())
}

impl I2CTpmAccessor for hidapi::HidDevice {
    fn initialize(&mut self) -> TpmResult<()> {
        setup_i2c(self)
    }

    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TpmResult<()> {
        wait_busy(self)?;
        let read_size = read_buf.len();
        self.write(&[
            0x91u8,
            (read_size & 255) as u8,
            ((read_size >> 8) & 255) as u8,
            TPM_ADDR_R,
        ])?;
        let mut res_buf = [0u8; 3];
        self.read(&mut res_buf)?;
        assert_eq!(res_buf[0], 0x91u8);
        if res_buf[1] == 1 {
            return Err(Error::Hardware);
        }
        let mut offset = 0;
        while offset < read_size {
            self.write(&[0x40u8, 0, 0, 0])?;
            let mut tmp = [0u8; 65];
            self.read(&mut tmp)?;
            assert_eq!(tmp[0], 0x40u8);
            let l = tmp[3] as usize;
            if tmp[1] == 0x41 || tmp[3] == 127 {
                return Err(Error::Unknown);
            }
            if l == 0 {
                break;
            }
            read_buf[offset..(l + offset)].copy_from_slice(&tmp[4..(l + 4)]);
            offset += l;
            wait_busy(self)?;
        }
        Ok(())
    }

    fn i2c_write(&mut self, write_buf: &[u8]) -> TpmResult<()> {
        let size = write_buf.len();
        let mut offset = 0;
        wait_busy(self)?;
        while offset < size {
            let write_size = (size - offset).min(60);
            self.write(
                &[
                    &[
                        0x90u8,
                        (write_size & 255) as u8,
                        ((write_size >> 8) & 255) as u8,
                        TPM_ADDR_W,
                    ],
                    &write_buf[offset..(offset + write_size)],
                ]
                .concat(),
            )?;
            let mut read_buf = [0u8; 64];
            self.read(&mut read_buf)?;
            assert_eq!(read_buf[0], 0x90u8);
            if read_buf[1] == 1 {
                setup_i2c(self)?;
                return Err(Error::Hardware);
            }
            wait_busy(self)?;
            offset += write_size;
        }

        Ok(())
    }
}
