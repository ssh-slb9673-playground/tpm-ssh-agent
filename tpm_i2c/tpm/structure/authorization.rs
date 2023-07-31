use crate::tpm::structure::{Tpm2BAuth, Tpm2BNonce, TpmAttrSession, TpmHandle};
use crate::tpm::TpmData;
use crate::TpmResult;

#[derive(Debug, Clone)]
pub struct TpmAuthCommand {
    pub session_handle: TpmHandle,
    pub nonce: Tpm2BNonce,
    pub session_attributes: TpmAttrSession,
    pub hmac: Tpm2BAuth,
}

#[derive(Debug, Clone)]
pub struct TpmAuthResponse {
    pub nonce: Tpm2BNonce,
    pub session_attributes: TpmAttrSession,
    pub hmac: Tpm2BAuth,
}

impl TpmAuthCommand {
    pub fn new(
        session_handle: TpmHandle,
        nonce: &[u8],
        session_attributes: TpmAttrSession,
        hmac: &[u8],
    ) -> TpmAuthCommand {
        TpmAuthCommand {
            session_handle,
            nonce: Tpm2BNonce::new(nonce),
            session_attributes,
            hmac: Tpm2BAuth::new(hmac),
        }
    }
}

impl TpmData for TpmAuthCommand {
    fn to_tpm(&self) -> Vec<u8> {
        [
            self.session_handle.to_tpm(),
            self.nonce.to_tpm(),
            self.session_attributes.to_tpm(),
            self.hmac.to_tpm(),
        ]
        .concat()
        .to_vec()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (session_handle, v) = TpmHandle::from_tpm(v)?;
        let (nonce, v) = Tpm2BNonce::from_tpm(v)?;
        let (session_attributes, v) = TpmAttrSession::from_tpm(v)?;
        let (hmac, v) = Tpm2BAuth::from_tpm(v)?;
        Ok((
            TpmAuthCommand {
                session_handle,
                nonce,
                session_attributes,
                hmac,
            },
            v,
        ))
    }
}

impl TpmData for TpmAuthResponse {
    fn to_tpm(&self) -> Vec<u8> {
        [
            self.nonce.to_tpm(),
            self.session_attributes.to_tpm(),
            self.hmac.to_tpm(),
        ]
        .concat()
        .to_vec()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (nonce, v) = Tpm2BNonce::from_tpm(v)?;
        let (session_attributes, v) = TpmAttrSession::from_tpm(v)?;
        let (hmac, v) = Tpm2BAuth::from_tpm(v)?;
        Ok((
            TpmAuthResponse {
                nonce,
                session_attributes,
                hmac,
            },
            v,
        ))
    }
}
