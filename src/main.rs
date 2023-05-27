use mcp2221::AvailableDevice;
use mcp2221::Config;
use mcp2221::Error;
use mcp2221::Handle;

fn tpm_read_identifiers(device: &mut Handle) -> Result<(u16, u16, u8), Error> {
    let mut vid_did_read_buf: [u8; 4] = [0; 4];
    let vid_did_write_buf: [u8; 1] = [0x48];
    device.write_read_address(0x2e, &vid_did_write_buf, &mut vid_did_read_buf)?;
    let tpm_vendor_id = vid_did_read_buf[1] as u16 * 256 + vid_did_read_buf[0] as u16;
    let tpm_device_id = vid_did_read_buf[3] as u16 * 256 + vid_did_read_buf[2] as u16;

    let mut rid_read_buf: [u8; 1] = [0; 1];
    let rid_write_buf: [u8; 1] = [0x4c];
    device.write_read_address(0x2e, &rid_write_buf, &mut rid_read_buf)?;
    Ok((tpm_vendor_id, tpm_device_id, rid_read_buf[0]))
}

fn main() -> Result<(), Error> {
    let cfg: Config = Config::default();
    let mut device = AvailableDevice::list().unwrap()[0].open(&cfg)?;

    let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = tpm_read_identifiers(&mut device)?;
    assert_eq!(tpm_vendor_id, 0x15d1);
    assert_eq!(tpm_device_id, 0x001c);
    assert_eq!(tpm_revision_id, 0x16);
    println!("[+] Vendor ID: {:04x}", tpm_vendor_id);
    println!("[+] Device ID: {:04x}", tpm_device_id);
    println!("[+] Revision ID: {:01x}", tpm_revision_id);

    Ok(())
}
