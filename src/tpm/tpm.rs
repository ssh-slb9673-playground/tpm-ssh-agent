use crate::{Error, TpmResult};
use bitfield_struct::bitfield;
use std::thread::sleep;
use std::time::Duration;

#[bitfield(u32)]
pub struct TpmStatus {
    _reserverd_0: bool,
    pub response_retry: bool,
    pub self_test_done: bool,
    pub expect: bool,
    pub data_available: bool,
    pub tpm_go: bool,
    pub command_ready: bool,
    pub status_valid: bool,
    pub burst_count: u16,
    pub command_cancel: bool,
    pub reset_establishment_bit: bool,
    #[bits(6)]
    _reserved: u8,
}

#[bitfield(u8)]
pub struct TpmAccess {
    pub tpm_establishment: bool,
    pub request_use: bool,
    pub pending_request: bool,
    pub seize: bool,
    pub been_seized: bool,
    pub active_locality: bool,
    _reserved: bool,
    pub tpm_reg_valid_status: bool,
}

#[bitfield(u32)]
pub struct TpmInterfaceCaps {
    #[bits(4)]
    pub interface_type: u8,
    #[bits(3)]
    pub interface_version: u8,
    #[bits(2)]
    pub tpm_family: u8,
    pub guard_time_usec: u8,
    pub need_guard_write_write: bool,
    pub need_guard_write_read: bool,
    pub need_guard_read_write: bool,
    pub need_guard_read_read: bool,
    pub sm_support: bool,
    pub fm_support: bool,
    pub fmplus_support: bool,
    pub hsmode_support: bool,
    #[bits(2)]
    pub cap_locality: u8,
    #[bits(2)]
    pub device_address_change: u8,
    pub burst_count_static: bool,
    pub guard_time_repeated_start: bool,
    _reserved: bool,
}

fn u16le(arr: &[u8]) -> u16 {
    arr[0] as u16 + ((arr[1] as u16) << 8)
}

fn u32le(arr: &[u8]) -> u32 {
    arr[0] as u32 + ((arr[1] as u32) << 8) + ((arr[2] as u32) << 16) + ((arr[3] as u32) << 24)
}

fn p32le(x: u32) -> [u8; 4] {
    [
        (x & 255) as u8,
        ((x >> 8) & 255) as u8,
        ((x >> 16) & 255) as u8,
        ((x >> 24) & 255) as u8,
    ]
}

pub trait I2CTpmAccessor {
    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TpmResult<()>;
    fn i2c_write(&mut self, write_buf: &[u8]) -> TpmResult<()>;
}

pub struct Tpm {
    device: Box<dyn I2CTpmAccessor>,
    current_locality: u8,
}

impl Tpm {
    pub fn new(mut device: Box<dyn I2CTpmAccessor>) -> TpmResult<Tpm> {
        let mut read_buf = [0u8; 1];
        device.i2c_write(&[0x00])?;
        device.i2c_read(&mut read_buf)?;
        Ok(Tpm {
            device,
            current_locality: read_buf[0],
        })
    }

    pub fn read_identifiers(&mut self) -> TpmResult<(u16, u16, u8)> {
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

    pub fn read_capabilities(&mut self) -> TpmResult<TpmInterfaceCaps> {
        let mut read_cap_buf = [0u8; 4];
        self.write_locality(self.current_locality)?;
        self.device.i2c_write(&[0x30])?;
        self.device.i2c_read(&mut read_cap_buf)?;
        Ok(TpmInterfaceCaps::from(u32le(&read_cap_buf)))
    }

    pub fn write_access_for_locality(&mut self, loc: u8, access: &TpmAccess) -> TpmResult<()> {
        let v: u8 = (*access).into();
        self.write_locality(loc)?;
        self.device.i2c_write(&[0x04, v])?;
        Ok(())
    }

    pub fn read_access_for_locality(&mut self, loc: u8) -> TpmResult<TpmAccess> {
        let mut read_buf = [0u8; 1];
        self.write_locality(loc)?;
        self.device.i2c_write(&[0x04])?;
        self.device.i2c_read(&mut read_buf)?;
        Ok(TpmAccess::from(read_buf[0]))
    }

    pub fn write_access(&mut self, access: &TpmAccess) -> TpmResult<()> {
        self.write_access_for_locality(self.current_locality, access)
    }

    pub fn read_access(&mut self) -> TpmResult<TpmAccess> {
        self.read_access_for_locality(self.current_locality)
    }

    pub fn read_status(&mut self) -> TpmResult<TpmStatus> {
        let mut read_sts_buf = [0u8; 4];
        self.write_locality(self.current_locality)?;
        self.device.i2c_write(&[0x18])?;
        self.device.i2c_read(&mut read_sts_buf)?;
        Ok(TpmStatus::from(u32le(&read_sts_buf)))
    }

    pub fn write_status(&mut self, status: &TpmStatus) -> TpmResult<()> {
        let x: u32 = (*status).into();
        let v = p32le(x);
        self.write_locality(self.current_locality)?;
        self.device.i2c_write(&[0x18, v[0], v[1], v[2], v[3]])?;
        Ok(())
    }

    pub fn write_fifo(&mut self, data: &[u8]) -> TpmResult<()> {
        self.wait_command_ready()?;
        self.write_locality(self.current_locality)?;
        for x in data {
            let burst_count = self.read_status()?.burst_count() as usize;
            if burst_count >= 0x8000 {
                return Err(Error::TpmBusy);
            }
            if burst_count == 0 {
                return Err(Error::Unknown);
            }
            self.device.i2c_write(&[0x24, *x])?;
            self.wait_status_valid()?;
            if !self.read_status()?.expect() {
                break;
            }
        }
        Ok(())
    }

    pub fn read_fifo(&mut self) -> TpmResult<Vec<u8>> {
        self.wait_data()?;
        let n = self.read_status()?.burst_count() as usize;
        let mut v = vec![0u8; n];

        self.write_locality(self.current_locality)?;
        self.device.i2c_write(&[0x24u8])?;
        self.device.i2c_read(&mut v)?;

        Ok(v)
    }

    pub fn wait_command_ready(&mut self) -> TpmResult<()> {
        loop {
            let status = self.read_status()?;
            if status.command_ready() {
                break;
            }
            self.write_status(&TpmStatus::new().with_command_ready(true))?;
            sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    pub fn wait_status_valid(&mut self) -> TpmResult<()> {
        loop {
            let status = self.read_status()?;
            if status.status_valid() {
                break;
            }
            sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    pub fn wait_data(&mut self) -> TpmResult<()> {
        loop {
            self.wait_status_valid()?;
            if self.read_status()?.data_available() {
                break;
            }
            sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    pub fn check_and_set_locality(&mut self, loc: u8) -> TpmResult<bool> {
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

    pub fn request_locality(&mut self, loc: u8) -> TpmResult<bool> {
        if self.current_locality == loc {
            return Ok(true);
        }

        if self.read_access()?.active_locality() {
            self.release_locality_force(self.current_locality)?;
        }

        self.write_access_for_locality(loc, &TpmAccess::new().with_request_use(true))?;
        sleep(Duration::from_millis(5));
        self.check_and_set_locality(loc)
    }

    pub fn release_locality(&mut self) -> TpmResult<()> {
        let ac = self.read_access()?;
        if ac.pending_request() && ac.tpm_reg_valid_status() {
            self.write_access(&TpmAccess::new().with_active_locality(true))?;
        }
        Ok(())
    }

    pub fn release_locality_force(&mut self, loc: u8) -> TpmResult<()> {
        self.write_access_for_locality(loc, &TpmAccess::new().with_active_locality(true))?;
        Ok(())
    }

    pub fn read_locality(&mut self) -> TpmResult<u8> {
        let mut read_buf = [0u8; 1];
        self.device.i2c_write(&[0x00])?;
        self.device.i2c_read(&mut read_buf)?;
        Ok(read_buf[0])
    }

    pub fn write_locality(&mut self, locality: u8) -> TpmResult<()> {
        self.device.i2c_write(&[0x00, locality])?;
        Ok(())
    }

    pub fn execute(&mut self) -> TpmResult<()> {
        self.write_status(&TpmStatus::new().with_tpm_go(true))
    }

    pub fn current_locality(&self) -> u8 {
        self.current_locality
    }
}
