use crate::tpm::command::{Tpm2Command, Tpm2Response};
use crate::tpm::{Tpm, TpmError, TpmInterfaceCaps};
use crate::tpm::{TpmAccess, TpmStatus};
use crate::util::{p32le, u16le, u32le};
use crate::TpmResult;
use std::thread::sleep;
use std::time::Duration;

impl Tpm {
    pub(in crate::tpm) fn read_identifiers(&mut self) -> TpmResult<(u16, u16, u8)> {
        let mut read_vid_and_did_buf = [0u8; 4];
        let mut read_rid_buf = [0u8; 1];

        self.device.i2c_write(&[0x48])?;
        self.device.i2c_read(&mut read_vid_and_did_buf)?;
        self.device.i2c_write(&[0x4c])?;
        self.device.i2c_read(&mut read_rid_buf)?;

        let (tpm_vendor_id, tpm_device_id) = {
            (
                u16le(&read_vid_and_did_buf[0..2]),
                u16le(&read_vid_and_did_buf[2..4]),
            )
        };

        let tpm_revision_id = read_rid_buf[0];

        Ok((tpm_vendor_id, tpm_device_id, tpm_revision_id))
    }

    pub(in crate::tpm) fn read_capabilities(&mut self) -> TpmResult<TpmInterfaceCaps> {
        let mut read_cap_buf = [0u8; 4];
        self.write_locality(self.current_locality)?;
        self.device.i2c_write(&[0x30])?;
        sleep(Duration::from_millis(5));
        self.device.i2c_read(&mut read_cap_buf)?;
        Ok(TpmInterfaceCaps::from(u32le(&read_cap_buf)))
    }

    pub(in crate::tpm) fn write_access_for_locality(
        &mut self,
        loc: u8,
        access: &TpmAccess,
    ) -> TpmResult<()> {
        let v: u8 = (*access).into();
        self.write_locality(loc)?;
        self.device.i2c_write(&[0x04, v])?;
        Ok(())
    }

    pub(in crate::tpm) fn read_access_for_locality(&mut self, loc: u8) -> TpmResult<TpmAccess> {
        let mut read_buf = [0u8; 1];
        self.write_locality(loc)?;
        self.device.i2c_write(&[0x04])?;
        sleep(Duration::from_millis(5));
        self.device.i2c_read(&mut read_buf)?;
        Ok(TpmAccess::from(read_buf[0]))
    }

    pub(in crate::tpm) fn write_access(&mut self, access: &TpmAccess) -> TpmResult<()> {
        self.write_access_for_locality(self.current_locality, access)
    }

    pub(in crate::tpm) fn read_access(&mut self) -> TpmResult<TpmAccess> {
        self.read_access_for_locality(self.current_locality)
    }

    pub(in crate::tpm) fn read_status(&mut self) -> TpmResult<TpmStatus> {
        let mut read_sts_buf = [0u8; 4];
        self.write_locality(self.current_locality)?;
        self.device.i2c_write(&[0x18])?;
        sleep(Duration::from_millis(5));
        self.device.i2c_read(&mut read_sts_buf)?;
        Ok(TpmStatus::from(u32le(&read_sts_buf)))
    }

    pub(in crate::tpm) fn write_status(&mut self, status: &TpmStatus) -> TpmResult<()> {
        let x: u32 = (*status).into();
        let v = p32le(x);
        self.write_locality(self.current_locality)?;
        self.device.i2c_write(&[0x18, v[0], v[1], v[2], v[3]])?;
        Ok(())
    }

    pub(in crate::tpm) fn write_fifo(&mut self, data: &[u8]) -> TpmResult<()> {
        self.wait_command_ready()?;
        self.write_locality(self.current_locality)?;
        for x in data {
            let burst_count = self.read_status()?.burst_count() as usize;
            if burst_count >= 0x8000 {
                return Err(TpmError::Busy.into());
            }
            if burst_count == 0 {
                return Err(TpmError::Unreadable.into());
            }
            self.device.i2c_write(&[0x24, *x])?;
            sleep(Duration::from_millis(5));
            self.wait_status_valid()?;
            if !self.read_status()?.expect() {
                break;
            }
        }
        Ok(())
    }

    pub(in crate::tpm) fn read_fifo(&mut self) -> TpmResult<Vec<u8>> {
        self.wait_data()?;
        let n = self.read_status()?.burst_count() as usize;
        let mut v = vec![0u8; n];

        self.write_locality(self.current_locality)?;
        self.device.i2c_write(&[0x24u8])?;
        sleep(Duration::from_millis(5));
        self.device.i2c_read(&mut v)?;

        Ok(v)
    }

    pub(in crate::tpm) fn wait_command_ready(&mut self) -> TpmResult<()> {
        loop {
            let status = self.read_status()?;
            if status.command_ready() {
                break;
            }
            self.write_status(&TpmStatus::new().with_command_ready(true))?;
            sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    pub(in crate::tpm) fn wait_status_valid(&mut self) -> TpmResult<()> {
        loop {
            let status = self.read_status()?;
            if status.status_valid() {
                break;
            }
            sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    pub(in crate::tpm) fn wait_data(&mut self) -> TpmResult<()> {
        loop {
            self.wait_status_valid()?;
            if self.read_status()?.data_available() {
                break;
            }
            sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    pub(in crate::tpm) fn check_and_set_locality(&mut self, loc: u8) -> TpmResult<bool> {
        if self
            .read_access_for_locality(self.current_locality)?
            .active_locality()
        {
            return Ok(true);
        }

        Ok(if self.read_access_for_locality(loc)?.active_locality() {
            self.current_locality = loc;
            true
        } else {
            false
        })
    }

    pub(in crate::tpm) fn request_locality(&mut self, loc: u8) -> TpmResult<bool> {
        let is_active = self.read_access()?.active_locality();
        if self.current_locality == loc && is_active {
            return Ok(true);
        }

        if is_active {
            self.release_locality_force(self.current_locality)?;
        }

        self.write_access_for_locality(loc, &TpmAccess::new().with_request_use(true))?;
        sleep(Duration::from_millis(5));
        self.check_and_set_locality(loc)
    }

    pub(in crate::tpm) fn release_locality(&mut self) -> TpmResult<()> {
        let ac = self.read_access()?;
        if ac.pending_request() && ac.tpm_reg_valid_status() {
            self.write_access(&TpmAccess::new().with_active_locality(true))?;
        }
        Ok(())
    }

    pub(in crate::tpm) fn release_locality_force(&mut self, loc: u8) -> TpmResult<()> {
        self.write_access_for_locality(loc, &TpmAccess::new().with_active_locality(true))?;
        Ok(())
    }

    pub(in crate::tpm) fn read_locality(&mut self) -> TpmResult<u8> {
        let mut read_buf = [0u8; 1];
        self.device.i2c_write(&[0x00])?;
        sleep(Duration::from_millis(5));
        self.device.i2c_read(&mut read_buf)?;
        Ok(read_buf[0])
    }

    pub(in crate::tpm) fn write_locality(&mut self, locality: u8) -> TpmResult<()> {
        self.device.i2c_write(&[0x00, locality])?;
        Ok(())
    }

    pub(in crate::tpm) fn execute(&mut self, cmd: &Tpm2Command) -> TpmResult<Tpm2Response> {
        self.request_locality(0)?;
        self.write_fifo(cmd.to_tpm().as_slice())?;
        sleep(Duration::from_millis(5));
        self.write_status(&TpmStatus::new().with_tpm_go(true))?;
        Tpm2Response::from_tpm(self.read_fifo()?.as_slice())
    }

    pub fn current_locality(&self) -> u8 {
        self.current_locality
    }
}
