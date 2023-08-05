use crate::tpm::structure::{
    Tpm2Command, TpmAttrSession, TpmAuthCommand, TpmHandle, TpmPermanentHandle, TpmiAlgorithmHash,
};

use crate::tpm::crypto::kdf_a;
use crate::tpm::ToTpm;

#[derive(Debug, Clone)]
pub struct TpmSession {
    pub algorithm: TpmiAlgorithmHash,
    pub handle: TpmHandle,
    pub nonce_caller: TpmSessionNonce,
    pub nonce_tpm: TpmSessionNonce,
    pub attributes: TpmAttrSession,
    pub bind: TpmPermanentHandle,
    pub tpm_key: TpmPermanentHandle,
}

#[derive(Debug, Clone)]
pub struct TpmSessionNonce {
    current_nonce: Vec<u8>,
    prev_nonce: Vec<u8>,
}

impl TpmSessionNonce {
    pub fn new(current_nonce: Vec<u8>, prev_nonce: Vec<u8>) -> TpmSessionNonce {
        TpmSessionNonce {
            current_nonce,
            prev_nonce,
        }
    }
}

impl TpmSession {
    pub fn new(
        algorithm: TpmiAlgorithmHash,
        handle: TpmHandle,
        attributes: TpmAttrSession,
        bind: TpmPermanentHandle,
        tpm_key: TpmPermanentHandle,
    ) -> TpmSession {
        TpmSession {
            algorithm,
            handle,
            nonce_caller: TpmSessionNonce::new(vec![], vec![]),
            nonce_tpm: TpmSessionNonce::new(vec![], vec![]),
            attributes,
            bind,
            tpm_key,
        }
    }

    pub fn set_caller_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce_caller = TpmSessionNonce::new(nonce, self.nonce_caller.current_nonce.clone());
    }

    pub fn set_tpm_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce_tpm = TpmSessionNonce::new(nonce, self.nonce_tpm.current_nonce.clone());
    }

    pub fn generate(&self, cmd: &Tpm2Command) -> TpmAuthCommand {
        let cphash = cmd.cphash(self.algorithm);
        let nonce = &self.nonce_caller;
        // 19.6.8 "the number of bits returned is the size of the digest produced by sessionAlg"
        // cphash.len() == the number of bytes sessionAlg's output
        let bits = cphash.len() as u32 * 8;
        let target_data = [
            cphash,
            [nonce.current_nonce.as_slice(), nonce.prev_nonce.as_slice()].concat(),
            self.attributes.to_tpm(),
        ]
        .concat();
        let _hmac = self.algorithm.hmac(
            &self.generate_session_key(vec![], vec![], bits),
            &target_data,
        );
        let hmac = vec![];
        TpmAuthCommand::new(
            self.handle,
            &self.nonce_caller.current_nonce,
            self.attributes,
            &hmac,
        )
    }

    pub fn generate_session_key(&self, auth_value: Vec<u8>, salt: Vec<u8>, bits: u32) -> Vec<u8> {
        // [TCG TPM Specification Part 1] 19.6.8 "sessionKey Creation"
        if self.bind == TpmPermanentHandle::Null && self.tpm_key == TpmPermanentHandle::Null {
            return vec![];
        }

        let data = [
            if self.bind == TpmPermanentHandle::Null {
                vec![]
            } else {
                auth_value
            },
            if self.tpm_key == TpmPermanentHandle::Null {
                vec![]
            } else {
                salt
            },
        ]
        .concat();
        kdf_a(
            &self.algorithm,
            &data,
            &[0x41, 0x54, 0x48, 0x00],
            &self.nonce_tpm.current_nonce,
            &self.nonce_caller.current_nonce,
            bits,
        )
    }
}
