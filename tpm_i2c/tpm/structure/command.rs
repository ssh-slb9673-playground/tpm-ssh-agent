use crate::tpm::{ToTpm, TpmDataVec};
use crate::util::p32be;

use crate::tpm::structure::{Tpm2CommandCode, TpmAuthCommand, TpmHandle, TpmStructureTag};

#[derive(Debug)]
pub struct Tpm2Command {
    pub tag: TpmStructureTag,
    pub command_code: Tpm2CommandCode,
    pub handles: Vec<TpmHandle>,
    pub auth_area: Vec<TpmAuthCommand>,
    pub params: Vec<Box<dyn ToTpm>>,
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
            params,
        }
    }

    pub fn new_with_session(
        tag: TpmStructureTag,
        command_code: Tpm2CommandCode,
        handles: Vec<TpmHandle>,
        auth_area: Vec<TpmAuthCommand>,
        params: Vec<Box<dyn ToTpm>>,
    ) -> Self {
        Tpm2Command {
            tag,
            command_code,
            handles,
            auth_area,
            params,
        }
    }
}

impl ToTpm for Tpm2Command {
    fn to_tpm(&self) -> Vec<u8> {
        let tag = self.tag.to_tpm();
        let cc = self.command_code.to_tpm();
        let params: Vec<u8> = self.params.to_tpm();
        // if self.tag == TpmStructureTag::Sessions {
        let handles = self.handles.to_tpm();
        let auth_area = self.auth_area.to_tpm();
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
        /*} else if self.tag == TpmStructureTag::NoSessions {
            let size: u32 = (tag.len() + cc.len() + params.len()) as u32 + 4;
            [tag, p32be(size).to_vec(), cc, params].concat()
        } else {
            unreachable!();
        }*/
    }
}
