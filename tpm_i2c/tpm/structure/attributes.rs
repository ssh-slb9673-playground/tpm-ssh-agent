use crate::tpm::{TpmData, TpmError};
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

impl TpmData for TpmAttrSession {
    fn to_tpm(&self) -> Vec<u8> {
        vec![self.0]
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        if v.is_empty() {
            Err(TpmError::Parse.into())
        } else {
            Ok((TpmAttrSession::from(v[0]), &v[1..]))
        }
    }
}
