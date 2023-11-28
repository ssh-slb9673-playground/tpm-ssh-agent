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
    pub nonce_new: Option<Vec<u8>>,
    pub nonce: (Vec<u8>, Vec<u8>),
    pub nonce_caller: Vec<u8>,
    pub nonce_tpm: Vec<u8>,
    pub attributes: TpmAttrSession,
    pub bind: TpmiDhEntity,
    pub tpm_key: TpmiDhObject,
    pub binded_auth_value: Vec<u8>,
    pub entity_auth_value: Vec<u8>,
}

fn gen_nonce() -> [u8; 16] {
    use rand::prelude::*;
    let mut rng = rand::thread_rng();
    let mut ret = [0u8; 16];
    rng.fill_bytes(&mut ret);
    ret
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
            nonce_new: None,
            nonce: (nonce_tpm.clone(), nonce_caller.clone()),
            nonce_caller,
            nonce_tpm,
            attributes,
            bind,
            tpm_key,
            binded_auth_value: vec![],
            entity_auth_value: vec![],
        }
    }

    pub fn rotate_nonce(&mut self) {
        if let Some(x) = self.nonce_new.take() {
            self.nonce = (x, self.nonce.0.clone());
        }
    }

    pub fn refresh_nonce(&mut self) {
        self.nonce_new = Some(gen_nonce().to_vec());
    }

    pub fn revert_nonce(&mut self) {
        self.nonce_new = None;
    }

    pub fn set_tpm_nonce(&mut self, nonce: Vec<u8>) {
        self.rotate_nonce();
        self.nonce_new = Some(nonce);
        self.rotate_nonce();
    }

    pub fn set_binded_auth_value(&mut self, auth_value: &[u8]) {
        self.entity_auth_value = auth_value.clone().to_vec();
        self.binded_auth_value = auth_value.clone().to_vec();
    }

    pub fn get_binded_auth_value(&self) -> Vec<u8> {
        self.binded_auth_value.clone()
    }

    pub fn set_entity_auth_value(&mut self, auth_value: &[u8]) {
        self.entity_auth_value = auth_value.clone().to_vec();
    }

    pub fn get_entity_auth_value(&self) -> Vec<u8> {
        self.entity_auth_value.clone()
    }

    pub fn generate(&self, cmd: &Tpm2Command) -> TpmAuthCommand {
        let cphash = cmd.cphash(self.algorithm);
        let hmac = self.compute_hmac(cphash);
        TpmAuthCommand::new(
            self.handle,
            self.nonce_new.as_ref().unwrap_or(&self.nonce.0),
            self.attributes,
            &hmac,
        )
    }

    pub fn validate(&self, res: &Tpm2Response, expected: &Vec<u8>) -> bool {
        let rphash = res.rphash(self.algorithm);
        &self.compute_hmac(rphash) == expected
    }

    fn compute_hmac(&self, phash: Vec<u8>) -> Vec<u8> {
        let (nonce_newer, nonce_older) = if let Some(x) = self.nonce_new.as_ref() {
            (x, &self.nonce.0)
        } else {
            (&self.nonce.0, &self.nonce.1)
        };
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
        let session_key = [
            self.generate_session_key(vec![], bits),
            if self.binded_auth_value != self.entity_auth_value {
                self.entity_auth_value.clone()
            } else {
                vec![]
            },
        ]
        .concat();
        self.algorithm.hmac(&session_key, &target_data)
    }

    pub fn generate_session_key(&self, salt: Vec<u8>, bits: u32) -> Vec<u8> {
        // [TCG TPM Specification Part 1] 19.6.8 "sessionKey Creation"
        if self.bind == TpmiDhEntity::Null && self.tpm_key == TpmiDhObject::Null {
            return vec![];
        }

        let data = [
            if self.bind == TpmiDhEntity::Null {
                vec![]
            } else {
                self.binded_auth_value.clone()
            },
            if self.tpm_key == TpmiDhObject::Null {
                vec![]
            } else {
                dbg!(salt);
                unimplemented!();
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
