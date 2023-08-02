use crate::tpm::{TpmData, TpmError};
use crate::util::{p32be, u32be};
use crate::TpmResult;
use bitfield_struct::bitfield;

#[bitfield(u8)]
pub struct TpmAttrSession {
    pub continue_session: bool,
    pub audit_exclusive: bool,
    pub audit_reset: bool,
    #[bits(2)]
    _reserved: u8,
    pub decrypt: bool,
    pub encrypt: bool,
    pub audit: bool,
}

#[bitfield(u32)]
pub struct TpmAttrAlgorithm {
    pub asymmetric: bool,
    pub symmetric: bool,
    pub hash: bool,
    pub object: bool,
    #[bits(4)]
    _reserved_1: u8,
    pub signing: bool,
    pub encrypting: bool,
    pub method: bool,
    #[bits(21)]
    _reserved_2: u32,
}

#[bitfield(u32)]
pub struct TpmAttrObject {
    _reserved_1: bool,
    pub fixed_tpm: bool,
    pub st_clear: bool,
    _reserved_2: bool,
    pub fixed_parent: bool,
    pub sensitive_data_origin: bool,
    pub user_with_auth: bool,
    pub admin_with_policy: bool,
    #[bits(2)]
    _reserved_3: u8,
    pub no_dictionary_attack: bool,
    pub encrypted_duplication: bool,
    #[bits(4)]
    _reserved_4: u8,
    pub restricted: bool,
    pub decrypt: bool,
    pub sign_or_encrypt: bool,
    pub x509_sign: bool,
    #[bits(12)]
    _reserved_5: u16,
}

impl TpmData for TpmAttrSession {
    fn to_tpm(&self) -> Vec<u8> {
        vec![self.0]
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        if v.is_empty() {
            Err(TpmError::create_parse_error("length mismatch").into())
        } else {
            Ok((TpmAttrSession::from(v[0]), &v[1..]))
        }
    }
}

impl TpmData for TpmAttrAlgorithm {
    fn to_tpm(&self) -> Vec<u8> {
        p32be(self.0).to_vec()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        if v.is_empty() {
            Err(TpmError::create_parse_error("length mismatch").into())
        } else {
            Ok((TpmAttrAlgorithm::from(u32be(&v[0..4])), &v[4..]))
        }
    }
}
