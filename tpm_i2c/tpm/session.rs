use crate::tpm::crypto::kdf_a;
use crate::tpm::structure::{
    Tpm2Command, Tpm2Response, TpmAttrSession, TpmAuthCommand, TpmHandle, TpmiAlgorithmHash,
    TpmiDhEntity, TpmiDhObject,
};
use crate::tpm::ToTpm;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TpmSession {
    pub algorithm: TpmiAlgorithmHash,
    pub handle: TpmHandle,
    pub nonce: (Vec<u8>, Vec<u8>),
    pub nonce_caller: Vec<u8>,
    pub nonce_tpm: Vec<u8>,
    pub attributes: TpmAttrSession,
    pub bind: TpmiDhEntity,
    pub tpm_key: TpmiDhObject,
}

impl TpmSession {
    pub fn new(
        algorithm: TpmiAlgorithmHash,
        handle: TpmHandle,
        attributes: TpmAttrSession,
        bind: TpmiDhEntity,
        tpm_key: TpmiDhObject,
        nonce_caller: Vec<u8>,
        nonce_tpm: Vec<u8>,
    ) -> TpmSession {
        TpmSession {
            algorithm,
            handle,
            nonce: (nonce_tpm.clone(), nonce_caller.clone()),
            nonce_caller,
            nonce_tpm,
            attributes,
            bind,
            tpm_key,
        }
    }

    pub fn set_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce = (nonce, self.nonce.0.clone());
    }

    pub fn generate(&self, cmd: &Tpm2Command) -> TpmAuthCommand {
        let cphash = cmd.cphash(self.algorithm);
        let hmac = self.compute_hmac(cphash, cmd.auth_value.clone());
        TpmAuthCommand::new(self.handle, &self.nonce.0, self.attributes, &hmac)
    }

    pub fn validate(&self, res: &Tpm2Response, auth_value: Vec<u8>, expected: &Vec<u8>) -> bool {
        let rphash = res.rphash(self.algorithm);
        &self.compute_hmac(rphash, auth_value) == expected
    }

    fn compute_hmac(&self, phash: Vec<u8>, auth_value: Vec<u8>) -> Vec<u8> {
        let nonce_newer = &self.nonce.0;
        let nonce_older = &self.nonce.1;
        // 19.6.8 "the number of bits returned is the size of the digest produced by sessionAlg"
        // phash.len() == the number of bytes sessionAlg's output
        let bits = phash.len() as u32 * 8;
        let target_data = [
            phash,
            nonce_newer.to_vec(),
            nonce_older.to_vec(),
            self.attributes.to_tpm(),
        ]
        .concat();
        self.algorithm.hmac(
            &[self.generate_session_key(vec![], vec![], bits), auth_value].concat(),
            &target_data,
        )
    }

    pub fn generate_session_key(&self, auth_value: Vec<u8>, salt: Vec<u8>, bits: u32) -> Vec<u8> {
        // [TCG TPM Specification Part 1] 19.6.8 "sessionKey Creation"
        if self.bind == TpmiDhEntity::Null && self.tpm_key == TpmiDhObject::Null {
            return vec![];
        }

        let data = [
            if self.bind == TpmiDhEntity::Null {
                vec![]
            } else {
                auth_value
            },
            if self.tpm_key == TpmiDhObject::Null {
                vec![]
            } else {
                salt
            },
        ]
        .concat();
        kdf_a(
            &self.algorithm,
            &data,
            "ATH".as_bytes(),
            &self.nonce_tpm,
            &self.nonce_caller,
            bits,
        )
    }
}
