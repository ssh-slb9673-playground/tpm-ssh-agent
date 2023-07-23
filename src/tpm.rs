use crate::{bit, TPMResult};

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct TPMStatus {
    pub burstCount: u16,
    pub stsValid: bool,
    pub commandReady: bool,
    pub dataAvail: bool,
    pub Expect: bool,
    pub selfTestDone: bool,
}

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct TPMAccess {
    pub tpmRegValidSts: bool,
    pub activeLocality: bool,
    pub beenSeized: bool,
    pub Seize: bool,
    pub pendingRequest: bool,
    pub requestUse: bool,
    pub tpmEstablishment: bool,
}

pub trait I2CTPMAccessor {
    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TPMResult<()>;
    fn i2c_write(&mut self, write_buf: &[u8]) -> TPMResult<()>;
}

#[allow(non_snake_case)]
pub struct TPM {
    device: Box<dyn I2CTPMAccessor>,
}

impl TPM {
    pub fn new(device: Box<dyn I2CTPMAccessor>) -> TPM {
        TPM { device }
    }

    pub fn read_identifiers(&mut self) -> TPMResult<(u16, u16, u8)> {
        let mut read_vid_and_did_buf = [0u8; 4];
        let mut read_rid_buf = [0u8; 1];

        self.device.i2c_write(&[0x48])?;
        self.device.i2c_read(&mut read_vid_and_did_buf)?;
        self.device.i2c_write(&[0x4c])?;
        self.device.i2c_read(&mut read_rid_buf)?;

        let (tpm_vendor_id, tpm_device_id) = {
            (
                read_vid_and_did_buf[1] as u16 * 256 + read_vid_and_did_buf[0] as u16,
                read_vid_and_did_buf[3] as u16 * 256 + read_vid_and_did_buf[2] as u16,
            )
        };

        let tpm_revision_id = read_rid_buf[0];

        Ok((tpm_vendor_id, tpm_device_id, tpm_revision_id))
    }

    pub fn read_capabilities(&mut self) -> TPMResult<[u8; 4]> {
        let mut read_cap_buf = [0u8; 4];
        self.device.i2c_write(&[0x30])?;
        self.device.i2c_read(&mut read_cap_buf)?;
        Ok(read_cap_buf)
    }

    pub fn read_access(&mut self) -> TPMResult<TPMAccess> {
        let mut read_buf = [0u8; 1];
        self.device.i2c_write(&[0x04])?;
        self.device.i2c_read(&mut read_buf)?;
        Ok(TPMAccess {
            tpmRegValidSts: bit!(read_buf[0], 7, bool),
            activeLocality: bit!(read_buf[0], 5, bool),
            beenSeized: bit!(read_buf[0], 4, bool),
            Seize: bit!(read_buf[0], 3, bool),
            pendingRequest: bit!(read_buf[0], 2, bool),
            requestUse: bit!(read_buf[0], 1, bool),
            tpmEstablishment: bit!(read_buf[0], 0, bool),
        })
    }

    pub fn read_locality(&mut self) -> TPMResult<u8> {
        let mut read_buf = [0u8; 1];
        self.device.i2c_write(&[0x00])?;
        self.device.i2c_read(&mut read_buf)?;
        Ok(read_buf[0])
    }

    pub fn write_locality(&mut self, locality: u8) -> TPMResult<()> {
        self.device.i2c_write(&[0x00, locality])?;
        Ok(())
    }

    pub fn read_status(&mut self) -> TPMResult<TPMStatus> {
        let mut read_sts_buf = [0u8; 4];
        self.device.i2c_write(&[0x18])?;
        self.device.i2c_read(&mut read_sts_buf)?;
        let sts = read_sts_buf[0] as u32
            + ((read_sts_buf[1] as u32) << 8)
            + ((read_sts_buf[2] as u32) << 16)
            + ((read_sts_buf[3] as u32) << 24);
        println!("{:08x}", sts);
        Ok(TPMStatus {
            burstCount: ((sts >> 8) & 0xffff) as u16,
            stsValid: 1 == (sts >> 7) & 1,
            commandReady: 1 == (sts >> 6) & 1,
            dataAvail: 1 == (sts >> 4) & 1,
            Expect: 1 == (sts >> 3) & 1,
            selfTestDone: 1 == (sts >> 2) & 1,
        })
    }
}
