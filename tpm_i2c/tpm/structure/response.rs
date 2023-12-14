use crate::tpm::{FromTpm, ToTpm, TpmError};
use crate::TpmResult;

use crate::tpm::structure::{
    Tpm2CommandCode, TpmAuthResponse, TpmHandle, TpmStructureTag, TpmiAlgorithmHash,
};

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
        Err(TpmError::create_parse_error(&format!("invalid value specified: {}", v)).into())
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
    ErrorForParam((u8, TpmResponseCodeFormat1)),
    ErrorForHandle((u8, TpmResponseCodeFormat1)),
    ErrorForSession((u8, TpmResponseCodeFormat1)),
}

impl FromTpm for TpmResponseCode {
    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        // Reference: TPM 2.0 Specification Part 1: Figure 27
        if v.len() < 4 {
            Err(TpmError::create_parse_error("length mismatch").into())
        } else {
            let (code, v) = u32::from_tpm(v)?;
            Ok((
                if code == 0 {
                    TpmResponseCode::Success
                } else if code == 0x1e {
                    TpmResponseCode::BadTag
                } else if (code >> 7) & 0b11 == 0 {
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
    pub handles: Vec<TpmHandle>,
    pub params: Vec<u8>,
    pub auth_area: Vec<TpmAuthResponse>,
    rphash_raw: Vec<u8>,
}

impl Tpm2Response {
    pub fn from_tpm(
        _v: &[u8],
        handles_count: usize,
        command_code: &Tpm2CommandCode,
    ) -> TpmResult<Tpm2Response> {
        let mut v = _v;
        let mut rphash_raw = vec![];

        // len(v) must be larger than len(tag + response_size + response_code)
        if v.len() < 10 {
            return Err(TpmError::create_parse_error("length mismatch").into());
        }
        let len = v.len() as u32;
        let (tag, tmp) = TpmStructureTag::from_tpm(v)?;
        v = tmp;
        let (size, tmp) = u32::from_tpm(v)?;
        v = tmp;
        rphash_raw.extend_from_slice(&v[0..4]);
        rphash_raw.extend_from_slice(&command_code.to_tpm());
        let (response_code, tmp) = TpmResponseCode::from_tpm(v)?;
        v = tmp;

        if len != size {
            return Err(TpmError::create_parse_error("length mismatch").into());
        }

        let mut handles = vec![];
        if response_code == TpmResponseCode::Success {
            for _ in 0..handles_count {
                let (handle, tmp) = TpmHandle::from_tpm(v)?;
                v = tmp;
                handles.push(handle);
            }
        }

        if tag == TpmStructureTag::Sessions {
            let (parameter_size, tmp) = u32::from_tpm(v)?;
            v = tmp;
            let (params, tmp) = (&v[..parameter_size as usize], &v[parameter_size as usize..]);
            v = tmp;

            let mut auth_area = vec![];
            loop {
                let (auth, tmp) = TpmAuthResponse::from_tpm(v)?;
                auth_area.push(auth);
                v = tmp;
                if v.is_empty() {
                    break;
                }
            }
            rphash_raw.extend_from_slice(params);
            Ok(Tpm2Response {
                tag,
                response_code,
                handles,
                params: params.to_vec(),
                auth_area,
                rphash_raw,
            })
        } else if tag == TpmStructureTag::NoSessions {
            rphash_raw.extend_from_slice(v);
            Ok(Tpm2Response {
                tag,
                response_code,
                handles,
                auth_area: vec![],
                params: v.to_vec(),
                rphash_raw,
            })
        } else {
            unreachable!();
        }
    }

    pub fn rphash(&self, algorithm: TpmiAlgorithmHash) -> Vec<u8> {
        algorithm.digest(&self.rphash_raw)
    }
}
