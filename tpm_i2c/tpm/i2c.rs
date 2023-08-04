use crate::tpm::{I2CTpmAccessor, Tpm, TpmError};
use crate::util::{p32le, u16le, u32le};
use crate::TpmResult;
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

impl<T: I2CTpmAccessor> Tpm<'_, T> {
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
        self.write_status(&TpmStatus::new().with_command_ready(true))?;
        self.wait_command_ready()?;
        self.write_locality(self.current_locality)?;
        let mut remain = data.clone();
        loop {
            let burst_count = self.read_status()?.burst_count() as usize;
            if burst_count >= 0x8000 {
                return Err(TpmError::Busy.into());
            }
            let write_len = remain.len().min(burst_count);
            self.device
                .i2c_write(&[[0x24].to_vec(), remain[0..write_len].to_vec()].concat())?;
            if write_len == remain.len() {
                break;
            }
            remain = &remain[write_len..];
        }
        loop {
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

    #[allow(unused)]
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

    pub fn current_locality(&self) -> u8 {
        self.current_locality
    }

    pub fn print_info(&mut self) -> TpmResult<()> {
        let caps = self.read_capabilities()?;
        println!("### TPM Information ###");
        let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = self.read_identifiers()?;

        println!("* Vendor ID: {:04x}", tpm_vendor_id);
        println!("* Device ID: {:04x}", tpm_device_id);
        println!("* Revision ID: {:04x}", tpm_revision_id);

        print!("* Interface Type: ");
        if caps.interface_type() == 0b0010 {
            println!("FIFO over I2C");
        } else {
            println!("Unknown({})", caps.interface_type());
        }

        print!("* Interface Version: ");
        if caps.interface_version() == 0b000 {
            println!("TCG I2C Interface 1.0");
        } else {
            println!("Unknown({})", caps.interface_version());
        }

        print!("* TPM Family: ");
        match caps.tpm_family() {
            0b00 => println!("TPM 1.2"),
            0b01 => println!("TPM 2.0"),
            x => println!("Unknown({})", x),
        }

        println!("* Guard time: {} usec", caps.guard_time_usec());
        println!("* Need Guard time?");
        println!("  - Write after Write: {}", caps.need_guard_write_write());
        println!("  - Write after Read: {}", caps.need_guard_write_read());
        println!("  - Read after Write: {}", caps.need_guard_read_write());
        println!("  - Read after Read: {}", caps.need_guard_read_read());
        println!(
            "  - ACK/NACK to repeated START: {}",
            caps.guard_time_repeated_start()
        );

        let sup_bool = |x: bool| if x { "Supported" } else { "Unsupported" };
        println!("* I2C Bus Speed Capabilities");
        println!("  - Standard Mode: {}", sup_bool(caps.sm_support()));
        println!("  - Fast Mode: {}", sup_bool(caps.fm_support()));
        println!("  - Fast Mode Plus: {}", sup_bool(caps.fmplus_support()));
        println!("  - High-Speed Mode: {}", sup_bool(caps.hsmode_support()));

        print!("* Supported locality: ");

        match caps.cap_locality() {
            0b00 => println!("[0]"),
            0b01 => println!("[0, 1, 2, 3, 4]"),
            0b10 => println!("[0, 1, 2, ..., 255]"),
            x => println!("Unknown({})", x),
        }

        print!("* Changing I2C Address: ");
        match caps.device_address_change() {
            0b00 => println!("Unupported"),
            0b01 => println!("Supported (by vendor specific mechanism)"),
            0b10 => println!("Reserved (bug?)"),
            0b11 => println!("Supported (by TCG-defined mechanism)"),
            _ => println!("Invalid"),
        }

        println!(
            "* Burst count: {}",
            if caps.burst_count_static() {
                "Static"
            } else {
                "Dynamic"
            }
        );

        Ok(())
    }
}
