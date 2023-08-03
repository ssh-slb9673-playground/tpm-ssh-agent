use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::{Tpm2BAuth, Tpm2BNonce, TpmAttrSession, TpmHandle};
use crate::tpm::{FromTpm, ToTpm};
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

impl_to_tpm! {
    TpmAuthCommand(self) {
        [
            self.session_handle.to_tpm(),
            self.nonce.to_tpm(),
            self.session_attributes.to_tpm(),
            self.hmac.to_tpm(),
        ]
        .concat()
        .to_vec()
    }

    TpmAuthResponse(self) {
        [
            self.nonce.to_tpm(),
            self.session_attributes.to_tpm(),
            self.hmac.to_tpm(),
        ]
        .concat()
        .to_vec()
    }
}

impl_from_tpm! {
    TpmAuthCommand(v) {
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

    TpmAuthResponse(v) {
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
