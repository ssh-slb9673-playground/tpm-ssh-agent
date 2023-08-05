use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::{TpmsCreationData, TpmtPublic};
use crate::tpm::TpmError;
use crate::tpm::{FromTpm, ToTpm};
use crate::util::{p16be, u16be};
use crate::TpmResult;

#[derive(Debug, Clone)]
pub struct Tpm2BDigest {
    pub buffer: Vec<u8>,
}

#[derive(Debug)]
pub struct Tpm2BPublic {
    pub public_area: Option<TpmtPublic>,
}

#[derive(Debug)]
pub struct Tpm2BCreationData {
    pub creation_data: Option<TpmsCreationData>,
}

impl_to_tpm! {
    Tpm2BDigest(self) {
        [&p16be(self.buffer.len() as u16), self.buffer.as_slice()].concat()
    }

    Tpm2BPublic(self) {
        if let Some(public) = &self.public_area {
            let v = public.to_tpm();
            [p16be(v.len() as u16).to_vec(), v].concat()
        } else {
            vec![]
        }
    }

    Tpm2BCreationData(self) {
        if let Some(creation_data) = &self.creation_data {
            let v = creation_data.to_tpm();
            [p16be(v.len() as u16).to_vec(), v].concat()
        } else {
            vec![]
        }
    }
}

impl_from_tpm! {
    Tpm2BDigest(v) {
        if v.len() < 2 {
            return Err(TpmError::create_parse_error("Length mismatch").into());
        }
        let len = u16be(&v[0..2]) as usize;
        Ok((
            Tpm2BDigest {
                buffer: v[2..(2 + len)].to_vec(),
            },
            &v[(2 + len)..],
        ))
    }

    Tpm2BPublic(v) {
        if v.len() < 2 {
            return Err(TpmError::create_parse_error("Length mismatch").into());
        }
        let (len, v) = (u16be(&v[0..2]) as usize, &v[2..]);
        Ok(if len == 0 {
            (Tpm2BPublic {
                public_area: None
            }, v)
        } else {
            let (res, v) = TpmtPublic::from_tpm(v)?;
            (Tpm2BPublic { public_area: Some(res) }, v)
        })
    }

    Tpm2BCreationData(v) {
        if v.len() < 2 {
            return Err(TpmError::create_parse_error("Length mismatch").into());
        }
        let (len, v) = (u16be(&v[0..2]) as usize, &v[2..]);
        Ok(if len == 0 {
            (Tpm2BCreationData {
                creation_data: None
            }, v)
        } else {
            let (res, v) = TpmsCreationData::from_tpm(v)?;
            (Tpm2BCreationData { creation_data: Some(res) }, v)
        })
    }
}

impl Tpm2BDigest {
    pub fn new(v: &[u8]) -> Tpm2BDigest {
        Tpm2BDigest { buffer: v.to_vec() }
    }
}

impl Tpm2BPublic {
    pub fn new(public_area: TpmtPublic) -> Self {
        Self {
            public_area: Some(public_area),
        }
    }

    pub fn empty() -> Self {
        Self { public_area: None }
    }
}

pub type Tpm2BNonce = Tpm2BDigest;
pub type Tpm2BAuth = Tpm2BDigest;
pub type Tpm2BEncryptedSecret = Tpm2BDigest;
pub type Tpm2BSensitiveData = Tpm2BDigest;
pub type Tpm2BPublicKeyRsa = Tpm2BDigest;
pub type Tpm2BPrivateKeyRsa = Tpm2BDigest;
pub type Tpm2BEccParameter = Tpm2BDigest;
pub type Tpm2BData = Tpm2BDigest;
pub type Tpm2BName = Tpm2BDigest;
