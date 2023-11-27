use crate::tpm::crypto::{get_name_of_handle, PublicData};
use crate::tpm::session::TpmSession;
use crate::tpm::structure::{
    Tpm2CommandCode, TpmHandle, TpmStructureTag, TpmiAlgorithmHash, TpmsNvPublic, TpmtPublic,
};
use crate::tpm::{ToTpm, TpmDataVec};
use crate::util::p32be;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Tpm2Command {
    pub tag: TpmStructureTag,
    pub command_code: Tpm2CommandCode,
    pub handles: Vec<TpmHandle>,
    pub auth_area: Vec<TpmSession>,
    pub params: Vec<Box<dyn ToTpm>>,
    pub auth_value: Vec<u8>,
    handle_public_map: HashMap<TpmHandle, PublicData>,
}

impl Tpm2Command {
    pub fn new(
        tag: TpmStructureTag,
        command_code: Tpm2CommandCode,
        params: Vec<Box<dyn ToTpm>>,
    ) -> Self {
        Tpm2Command {
            tag,
            command_code,
            handles: vec![],
            auth_area: vec![],
            auth_value: vec![],
            params,
            handle_public_map: HashMap::new(),
        }
    }

    pub fn new_with_session(
        tag: TpmStructureTag,
        command_code: Tpm2CommandCode,
        handles: Vec<TpmHandle>,
        auth_area: Vec<TpmSession>,
        auth_value: Vec<u8>,
        params: Vec<Box<dyn ToTpm>>,
    ) -> Self {
        Tpm2Command {
            tag,
            command_code,
            handles,
            auth_area,
            auth_value,
            params,
            handle_public_map: HashMap::new(),
        }
    }

    pub fn set_public_data_for_object_handle(&mut self, handle: TpmHandle, public: TpmtPublic) {
        let _ = self
            .handle_public_map
            .insert(handle, PublicData::Object(public));
    }

    pub fn set_public_data_for_nv_index(&mut self, nv_index: TpmHandle, public: TpmsNvPublic) {
        let _ = self
            .handle_public_map
            .insert(nv_index, PublicData::NvIndex(public));
    }

    pub fn cphash(&self, algorithm: TpmiAlgorithmHash) -> Vec<u8> {
        let mut cphash_raw = vec![];
        cphash_raw.extend_from_slice(&self.command_code.to_tpm());
        for handle in &self.handles {
            cphash_raw.extend_from_slice(&get_name_of_handle(*handle, |h| {
                self.handle_public_map
                    .get(&h)
                    .expect("Invalid handle specified")
            }));
        }
        cphash_raw.extend_from_slice(&self.params.to_tpm());
        algorithm.digest(&cphash_raw)
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
