use crate::tpm::{TpmData, TpmError};
use crate::util::{p32be, u32be};
use crate::TpmResult;

use crate::tpm::structure::constants::{Tpm2CommandCode, TpmResponseCode, TpmStructureTag};

pub struct Tpm2Command {
    pub tag: TpmStructureTag,
    pub command_code: Tpm2CommandCode,
    pub params: Vec<Box<dyn TpmData>>,
}

#[derive(Debug)]
pub struct Tpm2Response {
    pub tag: TpmStructureTag,
    pub response_code: TpmResponseCode,
    pub params: Vec<u8>,
}

impl Tpm2Command {
    pub fn new(
        tag: TpmStructureTag,
        command_code: Tpm2CommandCode,
        params: Vec<Box<dyn TpmData>>,
    ) -> Self {
        Tpm2Command {
            tag,
            command_code,
            params,
        }
    }

    pub fn to_tpm(&self) -> Vec<u8> {
        let tag = self.tag.to_tpm();
        let cc = self.command_code.to_tpm();
        let params: Vec<u8> = self
            .params
            .iter()
            .map(|x| x.to_tpm())
            .fold(vec![], |acc, x| [acc, x].concat());
        let size: u32 = (tag.len() + cc.len() + params.len()) as u32 + 4;
        [tag, p32be(size).to_vec(), cc, params].concat()
    }
}

impl Tpm2Response {
    pub fn from_tpm(v: &[u8]) -> TpmResult<Tpm2Response> {
        // len(v) must be larger than len(tag + response_size + response_code)
        if v.len() < 10 {
            return Err(TpmError::Parse.into());
        }
        let len = v.len() as u32;
        let (tag, v) = TpmStructureTag::from_tpm(v)?;
        let (size, v) = (u32be(&v[0..4]), &v[4..]);

        if len != size {
            return Err(TpmError::Parse.into());
        }

        let (response_code, params) = TpmResponseCode::from_tpm(v)?;
        Ok(Tpm2Response {
            tag,
            response_code,
            params: params.to_vec(),
        })
    }
}
