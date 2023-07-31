use crate::tpm::{TpmData, TpmError};
use crate::TpmResult;

use crate::tpm::structure::{TpmAuthResponse, TpmHandle, TpmStructureTag};

use num_derive::{FromPrimitive, ToPrimitive};

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmResponseCodeFormat0 {
    Initialize = 0x00,
    Failure = 0x01,
    Sequence = 0x03,
    Private = 0x0b,
    Hmac = 0x19,
    Disabled = 0x20,
    Exclusive = 0x21,
    AuthType = 0x24,
    AuthMissing = 0x25,
    Policy = 0x26,
    Pcr = 0x27,
    PcrChanged = 0x28,
    Upgrade = 0x2d,
    TooManyContexts = 0x2e,
    AuthUnavailable = 0x2f,
    Reboot = 0x30,
    Unbalanced = 0x31,
    CommandSize = 0x42,
    CommandCode = 0x43,
    AuthSize = 0x44,
    AuthContext = 0x45,
    NvRange = 0x46,
    NvSize = 0x47,
    NvLocked = 0x48,
    NvAuthorization = 0x49,
    NvUninitialized = 0x4a,
    NvSpace = 0x4b,
    NvDefined = 0x4c,
    BadContext = 0x50,
    Cphash = 0x51,
    Parent = 0x52,
    NeedsTest = 0x53,
    NoResult = 0x54,
    Sensitive = 0x55,
}

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmResponseCodeFormat1 {
    Asymmetric = 0x01,
    Attributes = 0x02,
    Hash = 0x03,
    Value = 0x04,
    Hierarchy = 0x05,
    KeySize = 0x07,
    Mgf = 0x08,
    Mode = 0x09,
    Type = 0x0a,
    Handle = 0x0b,
    Kdf = 0x0c,
    Range = 0x0d,
    AuthFail = 0x0e,
    Nonce = 0x0f,
    Pp = 0x10,
    Scheme = 0x12,
    Size = 0x15,
    Symmetric = 0x16,
    Tag = 0x17,
    Selector = 0x18,
    Insufficient = 0x1a,
    Signature = 0x1b,
    Key = 0x1c,
    PolicyFail = 0x1d,
    Integrity = 0x1f,
    Ticket = 0x20,
    ReservedBits = 0x21,
    BadAuth = 0x22,
    Expired = 0x23,
    PolicyCC = 0x24,
    Binding = 0x25,
    Curve = 0x26,
    EccPoint = 0x27,
}

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmResponseCodeWarning {
    ContextGap = 0x01,
    ObjectMemory = 0x02,
    SessionMemory = 0x03,
    Memory = 0x04,
    SessionHandles = 0x05,
    ObjectHandles = 0x06,
    Locality = 0x07,
    Yielded = 0x08,
    Canceled = 0x09,
    Testing = 0x0a,
    ReferenceH0 = 0x10,
    ReferenceH1 = 0x11,
    ReferenceH2 = 0x12,
    ReferenceH3 = 0x13,
    ReferenceH4 = 0x14,
    ReferenceH5 = 0x15,
    ReferenceH6 = 0x16,
    ReferenceS0 = 0x18,
    ReferenceS1 = 0x19,
    ReferenceS2 = 0x1a,
    ReferenceS3 = 0x1b,
    ReferenceS4 = 0x1c,
    ReferenceS5 = 0x1d,
    ReferenceS6 = 0x1e,
    NvRate = 0x20,
    Lockout = 0x21,
    Retry = 0x22,
    NvUnavailable = 0x23,
    NotUsed = 0x7f,
}

fn enum_from_u32<T>(v: u32) -> TpmResult<T>
where
    T: num_traits::FromPrimitive,
{
    if let Some(x) = num_traits::FromPrimitive::from_u32(v) {
        Ok(x)
    } else {
        Err(TpmError::Parse.into())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TpmResponseCode {
    Success,
    BadTag,
    TPM12(u32),
    Error(TpmResponseCodeFormat0),
    Format1(TpmResponseCodeFormat1),
    Warning(TpmResponseCodeWarning),
    VendorSpecific(u32),
    ErrorForParam((u8, TpmResponseCodeFormat0)),
    ErrorForHandle((u8, TpmResponseCodeFormat0)),
    ErrorForSession((u8, TpmResponseCodeFormat0)),
}

impl TpmData for TpmResponseCode {
    fn to_tpm(&self) -> Vec<u8> {
        panic!();
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        // Reference: TPM 2.0 Specification Part 1: Figure 27
        if v.len() < 4 {
            Err(TpmError::Parse.into())
        } else {
            let (code, v) = u32::from_tpm(v)?;
            Ok((
                if (code >> 7) & 0b11 == 0 {
                    // TPM 1.2 Response Code
                    TpmResponseCode::TPM12(code)
                } else if (code >> 7) & 1 == 0 {
                    if (code >> 10) & 1 == 1 {
                        // Vendor Defined Code
                        TpmResponseCode::VendorSpecific(code)
                    } else if (code >> 11) & 1 == 1 {
                        // Warning Code in Bits[06:00]
                        TpmResponseCode::Warning(enum_from_u32(code & 0b1111111)?)
                    } else {
                        // Error Code in Bits[06:00]
                        TpmResponseCode::Error(enum_from_u32(code & 0b1111111)?)
                    }
                } else if (code >> 6) & 1 == 1 {
                    // Error Code in Bits[05:00]
                    // Parameter Number in Bits[11:08]
                    let param = ((code >> 8) & 0b1111) as u8;
                    TpmResponseCode::ErrorForParam((param, enum_from_u32(code & 0b111111)?))
                } else if (code >> 11) & 1 == 0 {
                    // Error Code in Bits[05:00]
                    // Handle Number in Bits[10:08]
                    let handle = ((code >> 8) & 0b111) as u8;
                    TpmResponseCode::ErrorForHandle((handle, enum_from_u32(code & 0b111111)?))
                } else {
                    // Error Code in Bits[05:00]
                    // Session Number in Bits[10:08]
                    let session = ((code >> 8) & 0b111) as u8;
                    TpmResponseCode::ErrorForSession((session, enum_from_u32(code & 0b111111)?))
                },
                v,
            ))
        }
    }
}

#[derive(Debug)]
pub struct Tpm2Response {
    pub tag: TpmStructureTag,
    pub response_code: TpmResponseCode,
    pub params: Vec<u8>,
    pub auth_area: Vec<TpmAuthResponse>,
}

impl Tpm2Response {
    pub fn from_tpm(v: &[u8], handles_count: usize) -> TpmResult<Tpm2Response> {
        // len(v) must be larger than len(tag + response_size + response_code)
        if v.len() < 10 {
            return Err(TpmError::Parse.into());
        }
        let len = v.len() as u32;
        let (tag, v) = TpmStructureTag::from_tpm(v)?;
        let (size, v) = u32::from_tpm(v)?;
        let (response_code, v) = TpmResponseCode::from_tpm(v)?;

        println!("{:?}", response_code);

        if len != size {
            return Err(TpmError::Parse.into());
        }

        if tag == TpmStructureTag::Sessions {
            let mut handles = vec![];
            for _ in 1..handles_count {
                #[allow(unused)]
                let (handle, v) = TpmHandle::from_tpm(v)?;
                handles.push(handle);
            }
            let (parameter_size, v) = u32::from_tpm(v)?;
            let (params, v) = (&v[..parameter_size as usize], &v[parameter_size as usize..]);
            let mut auth_area = vec![];
            loop {
                let (auth, v) = TpmAuthResponse::from_tpm(v)?;
                if v.is_empty() {
                    break;
                }
                auth_area.push(auth);
            }
            Ok(Tpm2Response {
                tag,
                response_code,
                params: params.to_vec(),
                auth_area,
            })
        } else if tag == TpmStructureTag::NoSessions {
            Ok(Tpm2Response {
                tag,
                response_code,
                auth_area: vec![],
                params: v.to_vec(),
            })
        } else {
            unreachable!();
        }
    }
}
