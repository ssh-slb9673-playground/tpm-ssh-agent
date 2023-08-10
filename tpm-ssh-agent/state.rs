use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use tpm_i2c::tpm::session::TpmSession;
use tpm_i2c::tpm::structure::TpmHandle;

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    pub session: Option<TpmSession>,
    pub primary_handle: Option<TpmHandle>,
}

impl State {
    pub fn load(file: &Path) -> Result<Option<State>> {
        if !file.exists() {
            Ok(None)
        } else {
            let f = File::open(file)?;
            Ok(Some(serde_json::from_reader(f)?))
        }
    }

    pub fn save(&self, file: &Path) -> Result<()> {
        Ok(serde_json::to_writer(
            &mut File::create(file).map(BufWriter::new)?,
            self,
        )?)
    }
}
