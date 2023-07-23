use crate::TpmResult;
use bitfield_struct::bitfield;

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct TpmStatus {
    pub burstCount: u16,
    pub stsValid: bool,
    pub commandReady: bool,
    pub dataAvail: bool,
    pub Expect: bool,
    pub selfTestDone: bool,
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
    pub _reserved: bool,
}

fn u16le(arr: &[u8]) -> u16 {
    arr[0] as u16 + ((arr[1] as u16) << 8)
}

fn u32le(arr: &[u8]) -> u32 {
    arr[0] as u32 + ((arr[1] as u32) << 8) + ((arr[2] as u32) << 16) + ((arr[3] as u32) << 24)
}

pub trait I2CTpmAccessor {
    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TpmResult<()>;
    fn i2c_write(&mut self, write_buf: &[u8]) -> TpmResult<()>;
}

pub struct Tpm {
    device: Box<dyn I2CTpmAccessor>,
}

impl Tpm {
    pub fn new(device: Box<dyn I2CTpmAccessor>) -> Tpm {
        Tpm { device }
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
        self.device.i2c_write(&[0x30])?;
        self.device.i2c_read(&mut read_cap_buf)?;
        Ok(TpmInterfaceCaps::from(u32le(&read_cap_buf)))
    }

    pub fn write_access(&mut self, access: &TpmAccess) -> TpmResult<()> {
        let v: u8 = (*access).into();
        assert!(v.count_ones() == 1);
        self.device.i2c_write(&[0x04, v])?;
        Ok(())
    }
    pub fn read_access(&mut self) -> TpmResult<TpmAccess> {
        let mut read_buf = [0u8; 1];
        self.device.i2c_write(&[0x04])?;
        self.device.i2c_read(&mut read_buf)?;
        Ok(TpmAccess::from(read_buf[0]))
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

    pub fn read_status(&mut self) -> TpmResult<TpmStatus> {
        let mut read_sts_buf = [0u8; 4];
        self.device.i2c_write(&[0x18])?;
        self.device.i2c_read(&mut read_sts_buf)?;
        let sts = u32le(&read_sts_buf);
        println!("{:08x}", sts);
        Ok(TpmStatus {
            burstCount: ((sts >> 8) & 0xffff) as u16,
            stsValid: 1 == (sts >> 7) & 1,
            commandReady: 1 == (sts >> 6) & 1,
            dataAvail: 1 == (sts >> 4) & 1,
            Expect: 1 == (sts >> 3) & 1,
            selfTestDone: 1 == (sts >> 2) & 1,
        })
    }
}
