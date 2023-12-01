mod agent;
mod driver;
mod error;
mod keyman;
mod state;

use crate::agent::TpmSshAgent;
use crate::error::Result;
use ssh_agent_lib::Agent;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tpm_i2c::tpm::tcti::i2c::I2cTcti;

#[allow(unused_must_use)]
fn main() -> Result<()> {
    let state_file_path = Path::new("state.json").to_path_buf();

    let tcti = I2cTcti::new(Box::new(driver::hidapi::MCP2221A::new(0x2e)?));

    let keyman = Arc::new(Mutex::new(keyman::TpmKeyManager::new(
        state_file_path,
        Box::new(tcti),
    )?));

    let agent = TpmSshAgent::new(keyman.clone())?;
    for pubkey in agent.get_identities_as_ssh_format()? {
        println!("[+] SSH Public Key: {}", pubkey);
    }

    let socket = "connect.sock";
    let _ = std::fs::remove_file(socket);

    println!("Run agent at {}", socket);
    agent.run_unix(socket);

    keyman.lock().unwrap().close()?;

    Ok(())
}
