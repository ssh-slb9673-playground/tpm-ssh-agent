use crate::tpm::structure::macro_defs::{def_decoder, def_encoder, set_tpm_data_codec};
use crate::tpm::TpmError;
use crate::tpm::{FromTpm, ToTpm};
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

// TPM_CC
#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u32)]
pub enum Tpm2CommandCode {
    SelfTest = 0x0143,
    Startup = 0x0144,
    Shutdown = 0x145,
    GetRandom = 0x017B,
    CreatePrimary = 0x00000131,
    TestParms = 0x0000018a,
    GetCapability = 0x0000017a,
}

// TPM_SU
#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u16)]
pub enum TpmStartupType {
    Clear = 0,
    State = 1,
}

// TPM_RC
#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u32)]
pub enum TpmPermanentHandle {
    Password = 0x40000009,
    Null = 0x40000007,
    Owner = 0x40000001,
    Endorsement = 0x4000000b,
    Platform = 0x4000000c,
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u32)]
pub enum TpmHandleType {
    Pcr = 0,
    NvIndex = 1,
    HmacOrLoadedSession = 2,
    PolicyOrSavedSession = 3,
    Permanent = 0x40,
    Transient = 0x80,
    Persistent = 0x81,
    AttachedComponent = 0x90,
}

const HR_SHIFT: u32 = 24;

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u32)]
pub enum TpmHandleConstants {
    TransientFirst = (TpmHandleType::Transient as u32) << HR_SHIFT,
    TransientLast = ((TpmHandleType::Transient as u32) << HR_SHIFT) + MAX_LOADED_OBJECTS - 1,
    PersistentFirst = ((TpmHandleType::Persistent as u32) << HR_SHIFT) + MAX_LOADED_OBJECTS - 1,
    PersistentLast = ((TpmHandleType::Persistent as u32) << HR_SHIFT) + 0x00FFFFFF,
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u8)]
pub enum TpmSessionType {
    Hmac = 0,
    Policy = 1,
    Trial = 3,
}

pub const MAX_LOADED_OBJECTS: u32 = 3;
pub const MAX_ACTIVE_SESSIONS: u32 = 64;
pub const MAX_SESSION_NUM: u32 = 3;

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmCapabilities {
    Algs = 0,
    Handles = 1,
    Commands = 2,
    PpCommands = 3,
    AuditCommands = 4,
    Pcrs = 5,
    TpmProperties = 6,
    PcrProperties = 7,
    EccCurves = 8,
    AuthPolicies = 9,
    Act = 10,
}

pub(super) fn pack_enum_to_u8<T>(_self: &T) -> Vec<u8>
where
    T: num_traits::ToPrimitive,
{
    vec![num_traits::ToPrimitive::to_u8(_self).unwrap()]
}

def_decoder!(unpack_u8_to_enum, num_traits::FromPrimitive::from_u8, 1);
def_encoder!(pack_enum_to_u16, num_traits::ToPrimitive::to_u16, p16be);
def_decoder!(
    unpack_u16_to_enum,
    num_traits::FromPrimitive::from_u16,
    u16be,
    2
);
def_encoder!(pack_enum_to_u32, num_traits::ToPrimitive::to_u32, p32be);
def_decoder!(
    unpack_u32_to_enum,
    num_traits::FromPrimitive::from_u32,
    u32be,
    4
);

set_tpm_data_codec!(TpmStructureTag, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(Tpm2CommandCode, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmStartupType, pack_enum_to_u16, unpack_u16_to_enum);
set_tpm_data_codec!(TpmPermanentHandle, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmHandleType, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmHandleConstants, pack_enum_to_u32, unpack_u32_to_enum);
set_tpm_data_codec!(TpmSessionType, pack_enum_to_u8, unpack_u8_to_enum);
set_tpm_data_codec!(TpmCapabilities, pack_enum_to_u32, unpack_u32_to_enum);
