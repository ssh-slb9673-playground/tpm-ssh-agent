use crate::{Error, TpmResult};
use bitfield_struct::bitfield;

use crate::tpm::command::{
    Tpm2Command, Tpm2CommandCode, TpmResponseCode, TpmStartupType, TpmStructureTag, TpmUint16,
    TpmiYesNo,
};

pub mod command;
pub mod core_impl;

#[derive(Debug)]
pub enum TpmError {
    UnsuccessfulResponse(command::TpmResponseCode),
    Parse,
    Busy,
    Unreadable,
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            TpmError::UnsuccessfulResponse(rc) => write!(f, "Unsuccessful Result: RC = {:?}", rc),
            TpmError::Parse => write!(f, "TPM Parse"),
            TpmError::Busy => write!(f, "TPM Busy"),
            TpmError::Unreadable => write!(f, "TPM Unreadable"),
        }
    }
}

impl std::error::Error for TpmError {}

impl std::convert::From<TpmError> for Error {
    fn from(err: TpmError) -> Error {
        Error::TpmError(err)
    }
}

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

pub trait I2CTpmAccessor {
    fn initialize(&mut self) -> TpmResult<()>;
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
        device.initialize()?;
        device.i2c_write(&[0x00])?;
        device.i2c_read(&mut read_buf)?;
        Ok(Tpm {
            device,
            current_locality: read_buf[0],
        })
    }

    pub fn init(&mut self) -> TpmResult<()> {
        let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = self.read_identifiers()?;
        // For Infineon SLB9673 only
        assert_eq!(tpm_vendor_id, 0x15d1);
        assert_eq!(tpm_device_id, 0x001c);
        assert_eq!(tpm_revision_id, 0x16);
        if !self.request_locality(0)? {
            println!("[-] Failed to get locality control");
            return Err(Error::Unknown);
        }
        let res = self.startup(TpmStartupType::Clear);
        if let Err(Error::TpmError(TpmError::UnsuccessfulResponse(TpmResponseCode::Initialize))) =
            res
        {
            println!("[*] TPM was already initialied");
        } else if res.is_err() {
            return res;
        }
        self.selftest(TpmiYesNo::No)?;
        self.release_locality()?;
        Ok(())
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

    fn startup(&mut self, st: TpmStartupType) -> TpmResult<()> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::Startup,
            vec![Box::new(st)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(())
        }
    }

    fn selftest(&mut self, full_test: TpmiYesNo) -> TpmResult<()> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::SelfTest,
            vec![Box::new(full_test)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(())
        }
    }

    pub fn get_random(&mut self, len: u16) -> TpmResult<Vec<u8>> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::GetRandom,
            vec![Box::new(TpmUint16::new(len))],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(res.params)
        }
    }
}
