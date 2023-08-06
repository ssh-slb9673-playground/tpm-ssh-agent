use crate::tpm::crypto::get_name_of_handle;
use crate::tpm::session::TpmSession;
use crate::tpm::structure::{
    Tpm2CommandCode, TpmHandle, TpmStructureTag, TpmiAlgorithmHash, TpmtPublic,
};
use crate::tpm::{ToTpm, TpmDataVec};
use crate::util::p32be;

#[derive(Debug)]
pub struct Tpm2Command {
    pub tag: TpmStructureTag,
    pub command_code: Tpm2CommandCode,
    pub handles: Vec<TpmHandle>,
    pub auth_area: Vec<TpmSession>,
    pub params: Vec<Box<dyn ToTpm>>,
    cphash_raw: Vec<u8>,
}

impl Tpm2Command {
    pub fn new(
        tag: TpmStructureTag,
        command_code: Tpm2CommandCode,
        params: Vec<Box<dyn ToTpm>>,
    ) -> Self {
        let mut cphash_raw = vec![];
        cphash_raw.extend_from_slice(&command_code.to_tpm());
        cphash_raw.extend_from_slice(&params.to_tpm());
        Tpm2Command {
            tag,
            command_code,
            handles: vec![],
            auth_area: vec![],
            params,
            cphash_raw,
        }
    }

    pub fn new_with_session<F>(
        tag: TpmStructureTag,
        command_code: Tpm2CommandCode,
        handles: Vec<TpmHandle>,
        auth_area: Vec<TpmSession>,
        params: Vec<Box<dyn ToTpm>>,
        handle_to_public: F,
    ) -> Self
    where
        F: Fn(TpmHandle) -> TpmtPublic,
    {
        let mut cphash_raw = vec![];
        cphash_raw.extend_from_slice(&command_code.to_tpm());
        for handle in &handles {
            cphash_raw.extend_from_slice(&get_name_of_handle(*handle, &handle_to_public));
        }
        cphash_raw.extend_from_slice(&params.to_tpm());
        Tpm2Command {
            tag,
            command_code,
            handles,
            auth_area,
            params,
            cphash_raw,
        }
    }

    pub fn cphash(&self, algorithm: TpmiAlgorithmHash) -> Vec<u8> {
        dbg!(&self.cphash_raw);
        algorithm.digest(&self.cphash_raw)
    }
}

impl ToTpm for Tpm2Command {
    fn to_tpm(&self) -> Vec<u8> {
        let tag = self.tag.to_tpm();
        let cc = self.command_code.to_tpm();
        let params: Vec<u8> = self.params.to_tpm();
        let handles = self.handles.to_tpm();
        let mut auth_area = vec![];
        for session in &self.auth_area {
            auth_area.push(session.generate(self));
        }
        let auth_area = auth_area.to_tpm();
        let auth_size = auth_area.len();
        let size: u32 = (tag.len() + cc.len() + handles.len() + auth_size + params.len()) as u32
            + 4
            + if self.auth_area.is_empty() { 0 } else { 4 };
        [
            tag,
            p32be(size).to_vec(),
            cc,
            handles,
            if !self.auth_area.is_empty() {
                p32be(auth_size as u32).to_vec()
            } else {
                vec![]
            },
            auth_area,
            params,
        ]
        .concat()
    }
}
