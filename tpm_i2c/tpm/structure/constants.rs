use crate::tpm::TpmData;
use crate::tpm::TpmError;
use crate::util::{p16be, p32be, u16be, u32be};
use crate::TpmResult;
use num_derive::{FromPrimitive, ToPrimitive};

pub type TpmHandle = u32;

macro_rules! set_tpm_data_codec {
    ($type:ty, $enc:ident, $dec:ident) => {
        impl TpmData for $type {
            fn to_tpm(&self) -> Vec<u8> {
                $enc(self)
            }

            fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
                $dec(v)
            }
        }
    };
}

macro_rules! def_encoder {
    ($name: ident, $enum_to_num: path, $num_to_vec: path) => {
        fn $name<T>(_self: &T) -> Vec<u8>
        where
            T: num_traits::ToPrimitive,
        {
            $num_to_vec($enum_to_num(_self).unwrap()).to_vec()
        }
    };
}

macro_rules! def_decoder {
    ($name: ident, $num_to_enum: path, $vec_to_num: path, $len: expr) => {
        fn $name<T>(v: &[u8]) -> TpmResult<(T, &[u8])>
        where
            T: num_traits::FromPrimitive,
        {
            if v.len() < $len {
                return Err(TpmError::Parse.into());
            }

            if let Some(x) = $num_to_enum($vec_to_num(&v[0..$len])) {
                Ok((x, &v[$len..]))
            } else {
                Err(TpmError::Parse.into())
            }
        }
    };

    ($name: ident, $num_to_enum: path, 1) => {
        fn $name<T>(v: &[u8]) -> TpmResult<(T, &[u8])>
        where
            T: num_traits::FromPrimitive,
        {
            if v.is_empty() {
                return Err(TpmError::Parse.into());
            }

            if let Some(x) = $num_to_enum(v[0]) {
                Ok((x, &v[1..]))
            } else {
                Err(TpmError::Parse.into())
            }
        }
    };
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
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

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmResponseCode {
    Success = 0,
    BadTag = 0x1e,
    /* Format 0 (0x100 + n) */
    Initialize = 0x100,
    Failure = 0x101,
    Sequence = 0x103,
    Private = 0x10b,
    Hmac = 0x119,
    Disabled = 0x120,
    Exclusive = 0x121,
    AuthType = 0x124,
    AuthMissing = 0x125,
    Policy = 0x126,
    Pcr = 0x127,
    PcrChanged = 0x128,
    Upgrade = 0x12d,
    TooManyContexts = 0x12e,
    AuthUnavailable = 0x12f,
    Reboot = 0x130,
    Unbalanced = 0x131,
    CommandSize = 0x142,
    CommandCode = 0x143,
    AuthSize = 0x144,
    AuthContext = 0x145,
    NvRange = 0x146,
    NvSize = 0x147,
    NvLocked = 0x148,
    NvAuthorization = 0x149,
    NvUninitialized = 0x14a,
    NvSpace = 0x14b,
    NvDefined = 0x14c,
    BadContext = 0x150,
    Cphash = 0x151,
    Parent = 0x152,
    NeedsTest = 0x153,
    NoResult = 0x154,
    Sensitive = 0x155,
    // MaxFM0 = 0x17f,
    /* Format 1 (0x80 + n) */
    Asymmetric = 0x81,
    Attributes = 0x82,
    Hash = 0x83,
    Value = 0x84,
    Hierarchy = 0x85,
    KeySize = 0x87,
    Mgf = 0x88,
    Mode = 0x89,
    Type = 0x8a,
    Handle = 0x8b,
    Kdf = 0x8c,
    Range = 0x8d,
    AuthFail = 0x8e,
    Nonce = 0x8f,
    Pp = 0x90,
    Scheme = 0x92,
    Size = 0x95,
    Symmetric = 0x96,
    Tag = 0x97,
    Selector = 0x98,
    Insufficient = 0x9a,
    Signature = 0x9b,
    Key = 0x9c,
    PolicyFail = 0x9d,
    Integrity = 0x9f,
    Ticket = 0xa0,
    ReservedBits = 0xa1,
    BadAuth = 0xa2,
    Expired = 0xa3,
    PolicyCC = 0xa4,
    Binding = 0xa5,
    Curve = 0xa6,
    EccPoint = 0xa7,
    /* Warning (0x900 + n) */
    ContextGap = 0x901,
    ObjectMemory = 0x902,
    SessionMemory = 0x903,
    Memory = 0x904,
    SessionHandles = 0x905,
    ObjectHandles = 0x906,
    Locality = 0x907,
    Yielded = 0x908,
    Canceled = 0x909,
    Testing = 0x90a,
    ReferenceH0 = 0x910,
    ReferenceH1 = 0x911,
    ReferenceH2 = 0x912,
    ReferenceH3 = 0x913,
    ReferenceH4 = 0x914,
    ReferenceH5 = 0x915,
    ReferenceH6 = 0x916,
    ReferenceS0 = 0x918,
    ReferenceS1 = 0x919,
    ReferenceS2 = 0x91a,
    ReferenceS3 = 0x91b,
    ReferenceS4 = 0x91c,
    ReferenceS5 = 0x91d,
    ReferenceS6 = 0x91e,
    NvRate = 0x920,
    Lockout = 0x921,
    Retry = 0x922,
    NvUnavailable = 0x923,
    NotUsed = 0x97f,
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
set_tpm_data_codec!(TpmResponseCode, encode_u32, decode_u32);
set_tpm_data_codec!(Tpm2CommandCode, encode_u32, decode_u32);
set_tpm_data_codec!(TpmStartupType, encode_u16, decode_u16);
set_tpm_data_codec!(TpmiYesNo, encode_u8, decode_u8);
set_tpm_data_codec!(TpmPermanentHandle, encode_u32, decode_u32);
set_tpm_data_codec!(TpmHandle, encode_u32, decode_u32);
