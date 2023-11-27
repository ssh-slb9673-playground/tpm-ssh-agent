use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use tpm_i2c::tpm::I2CTpmAccessor;
use tpm_i2c::{Error, TpmResult};

pub struct MCP2221A {
    device: Arc<Mutex<hidapi::HidDevice>>,
    i2c_addr_write: u8,
    i2c_addr_read: u8,
}

impl MCP2221A {
    pub fn new(i2c_addr: u8) -> TpmResult<MCP2221A> {
        let device = hidapi::HidApi::new()?.open(0x04d8, 0x00dd)?;
        Ok(MCP2221A {
            device: Arc::new(Mutex::new(device)),
            i2c_addr_write: (i2c_addr << 1) | 1,
            i2c_addr_read: i2c_addr << 1,
        })
    }

    pub fn wait_busy(&self) -> TpmResult<()> {
        let mut count = 0;
        loop {
            self.device.lock().unwrap().write(&[0x10u8, 0, 0, 0, 0])?;
            let mut buf = [0u8; 65];
            self.device.lock().unwrap().read(&mut buf)?;
            if buf[8] == 0 {
                break;
            }
            sleep(Duration::from_millis(50));
            if count < 1000 {
                return Err(Error::Hardware);
            }
            count += 1;
        }
        Ok(())
    }

    pub fn setup_i2c(&self) -> TpmResult<()> {
        self.device.lock().unwrap().write(&[0x10u8, 0, 0, 0, 0])?;
        let mut buf = [0u8; 65];
        self.device.lock().unwrap().read(&mut buf)?;
        if buf[8] != 0 {
            // need to cancel current transport
            self.device
                .lock()
                .unwrap()
                .write(&[0x10u8, 0, 0x10, 0, 0])?;
            let mut buf = [0u8; 65];
            self.device.lock().unwrap().read(&mut buf)?;

            sleep(Duration::from_millis(250));
        }
        loop {
            self.device
                .lock()
                .unwrap()
                .write(&[0x10u8, 0, 0, 0x20, 26])?;
            let mut buf = [0u8; 65];
            self.device.lock().unwrap().read(&mut buf)?;
            if buf[3] == 0x20 {
                // changing success
                break;
            }
            sleep(Duration::from_millis(250));
        }
        Ok(())
    }
}

impl I2CTpmAccessor for MCP2221A {
    fn initialize(&mut self) -> TpmResult<()> {
        self.setup_i2c()
    }

    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TpmResult<()> {
        self.wait_busy()?;
        let read_size = read_buf.len();
        self.device.lock().unwrap().write(&[
            0x91u8,
            (read_size & 255) as u8,
            ((read_size >> 8) & 255) as u8,
            self.i2c_addr_read,
        ])?;
        let mut res_buf = [0u8; 3];
        self.device.lock().unwrap().read(&mut res_buf)?;
        assert_eq!(res_buf[0], 0x91u8);
        // From Microchip's datasheet p.42:
        // res_buf[1] == 1 <=> "I2C engine is busy (command not completed)."
        if res_buf[1] == 1 {
            return Err(Error::Hardware);
        }
        let mut offset = 0;
        let mut retry = 0;
        let retry_max = (read_size * 5 / 60).max(5);
        while offset < read_size {
            self.device.lock().unwrap().write(&[0x40u8, 0, 0, 0])?;
            let mut tmp = [0u8; 65];
            self.device.lock().unwrap().read(&mut tmp)?;
            assert_eq!(tmp[0], 0x40u8);
            let l = tmp[3] as usize;
            // From Microchip's datasheet p.44:
            // tmp[1] == 0x41 <=> "Error reading the I2C client data from the I2C engine"
            // tmp[3] == 127 <=> "This value is signaled when an error has occurred and the following data should not be taken into account"
            if tmp[1] == 0x41 || tmp[3] == 127 {
                retry += 1;
                if retry >= retry_max {
                    return Err(Error::Hardware);
                }
                sleep(Duration::from_millis(5));
                continue;
            }
            if l == 0 {
                break;
            }
            read_buf[offset..(l + offset)].copy_from_slice(&tmp[4..(l + 4)]);
            offset += l;
        }
        self.wait_busy()?;
        Ok(())
    }

    fn i2c_write(&mut self, write_buf: &[u8]) -> TpmResult<()> {
        let size = write_buf.len();
        let mut offset = 0;
        self.wait_busy()?;
        let mut retry = 0;
        while offset < size {
            let write_size = (size - offset).min(60);
            let cmd = 0x90;
            self.device.lock().unwrap().write(
                &[
                    &[
                        cmd,
                        (size & 255) as u8,
                        ((size >> 8) & 255) as u8,
                        self.i2c_addr_write,
                    ],
                    &write_buf[offset..(offset + write_size)],
                ]
                .concat(),
            )?;
            let mut read_buf = [0u8; 64];
            self.device.lock().unwrap().read(&mut read_buf)?;
            assert_eq!(read_buf[0], cmd);
            // From Microchip's datasheet p.39:
            // read_buf[1] == 1 <=> "I2C engine is busy (command not completed)."
            if read_buf[1] == 1 {
                retry += 1;
                if retry > 5 {
                    self.setup_i2c()?;
                    return Err(Error::Hardware);
                }
                sleep(Duration::from_millis(1));
                continue;
            }
            offset += write_size;
        }
        self.wait_busy()?;

        Ok(())
    }
}
