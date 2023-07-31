use crate::tpm::structure::macro_defs::{def_decoder, def_encoder, set_tpm_data_codec};
use crate::tpm::TpmData;
use crate::tpm::TpmError;
use crate::util::{p16be, p32be, u16be, u32be};
use crate::TpmResult;
use num_derive::{FromPrimitive, ToPrimitive};

pub type TpmHandle = u32;

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmStructureTag {
    RspCommand = 0xc4,
    Null = 0x8000,
    NoSessions = 0x8001,
    Sessions = 0x8002,
    Reserved8003 = 0x8003,
    Reserved8004 = 0x8004,
    AttestNv = 0x8014,
    AttestCommandAudit = 0x8015,
    AttestSessionAudit = 0x8016,
    AttestCertify = 0x8017,
    AttestQuote = 0x8018,
    AttestTime = 0x8019,
    AttestCreation = 0x801a,
    Reserved801B = 0x801b,
    AttestNvDigest = 0x801c,
    Creation = 0x8021,
    Verified = 0x8022,
    AuthSecret = 0x8023,
    HashCheck = 0x8024,
    AuthSigned = 0x8025,
    FuManifest = 0x8029,
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u32)]
pub enum Tpm2CommandCode {
    Startup = 0x0144,
    SelfTest = 0x0143,
    GetRandom = 0x017B,
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u16)]
pub enum TpmStartupType {
    Clear = 0,
    State = 1,
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u8)]
pub enum TpmiYesNo {
    No = 0,
    Yes = 1,
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u32)]
pub enum TpmPermanentHandle {
    Password = 0x40000009,
}

fn encode_u8<T>(_self: &T) -> Vec<u8>
where
    T: num_traits::ToPrimitive,
{
    vec![num_traits::ToPrimitive::to_u8(_self).unwrap()]
}

def_decoder!(decode_u8, num_traits::FromPrimitive::from_u8, 1);
def_encoder!(encode_u16, num_traits::ToPrimitive::to_u16, p16be);
def_decoder!(decode_u16, num_traits::FromPrimitive::from_u16, u16be, 2);
def_encoder!(encode_u32, num_traits::ToPrimitive::to_u32, p32be);
def_decoder!(decode_u32, num_traits::FromPrimitive::from_u32, u32be, 4);

set_tpm_data_codec!(TpmStructureTag, encode_u16, decode_u16);
set_tpm_data_codec!(Tpm2CommandCode, encode_u32, decode_u32);
set_tpm_data_codec!(TpmStartupType, encode_u16, decode_u16);
set_tpm_data_codec!(TpmiYesNo, encode_u8, decode_u8);
set_tpm_data_codec!(TpmPermanentHandle, encode_u32, decode_u32);

impl From<TpmPermanentHandle> for TpmHandle {
    fn from(handle: TpmPermanentHandle) -> TpmHandle {
        handle as TpmHandle
    }
}
