use crate::tpm::{TpmData, TpmDataVec, TpmError};
use crate::util::{p32be, u32be};
use crate::TpmResult;

use crate::tpm::structure::{
    Tpm2CommandCode, TpmAuthCommand, TpmAuthResponse, TpmHandle, TpmResponseCode, TpmStructureTag,
};

#[derive(Debug)]
pub struct Tpm2Command {
    pub tag: TpmStructureTag,
    pub command_code: Tpm2CommandCode,
    pub handles: Vec<TpmHandle>,
    pub auth_area: Vec<TpmAuthCommand>,
    pub params: Vec<Box<dyn TpmData>>,
}

#[derive(Debug)]
pub struct Tpm2Response {
    pub tag: TpmStructureTag,
    pub response_code: TpmResponseCode,
    pub params: Vec<u8>,
    pub auth_area: Vec<TpmAuthResponse>,
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
        params: Vec<Box<dyn TpmData>>,
    ) -> Self {
        Tpm2Command {
            tag,
            command_code,
            handles,
            auth_area,
            params,
        }
    }

    pub fn to_tpm(&self) -> Vec<u8> {
        let tag = self.tag.to_tpm();
        let cc = self.command_code.to_tpm();
        let params: Vec<u8> = self.params.to_tpm();
        if self.tag == TpmStructureTag::Sessions {
            let handles = self.handles.to_tpm();
            let auth_area = self.auth_area.to_tpm();
            let auth_size = auth_area.len();
            let size: u32 =
                (tag.len() + cc.len() + handles.len() + auth_size + params.len()) as u32 + 4 + 4;
            [
                tag,
                p32be(size).to_vec(),
                cc,
                handles,
                p32be(auth_size as u32).to_vec(),
                auth_area,
                params,
            ]
            .concat()
        } else if self.tag == TpmStructureTag::NoSessions {
            let size: u32 = (tag.len() + cc.len() + params.len()) as u32 + 4;
            [tag, p32be(size).to_vec(), cc, params].concat()
        } else {
            unreachable!();
        }
    }
}

impl Tpm2Response {
    pub fn from_tpm(v: &[u8], handles_count: usize) -> TpmResult<Tpm2Response> {
        // len(v) must be larger than len(tag + response_size + response_code)
        if v.len() < 10 {
            return Err(TpmError::Parse.into());
        }
        let len = v.len() as u32;
        dbg!(v);
        let (tag, v) = TpmStructureTag::from_tpm(v)?;
        let (size, v) = (u32be(&v[0..4]), &v[4..]);
        println!("{:?}", v);
        let (response_code, v) = TpmResponseCode::from_tpm(v)?;

        println!("{:?}", response_code);

        if len != size {
            return Err(TpmError::Parse.into());
        }

        if tag == TpmStructureTag::Sessions {
            let mut handles = vec![];
            for _ in 1..handles_count {
                #[allow(unused)]
                let (handle, v) = TpmHandle::from_tpm(v)?;
                handles.push(handle);
            }
            let (parameter_size, v) = u32::from_tpm(v)?;
            let (params, v) = (&v[..parameter_size as usize], &v[parameter_size as usize..]);
            let mut auth_area = vec![];
            loop {
                let (auth, v) = TpmAuthResponse::from_tpm(v)?;
                if v.is_empty() {
                    break;
                }
                auth_area.push(auth);
            }
            Ok(Tpm2Response {
                tag,
                response_code,
                params: params.to_vec(),
                auth_area,
            })
        } else if tag == TpmStructureTag::NoSessions {
            Ok(Tpm2Response {
                tag,
                response_code,
                auth_area: vec![],
                params: v.to_vec(),
            })
        } else {
            unreachable!();
        }
    }
}
