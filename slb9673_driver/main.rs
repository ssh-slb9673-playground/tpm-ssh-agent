mod driver;
mod keyman;
mod state;
use ssh_agent_lib::proto::message::Message;
use ssh_agent_lib::Agent;
use std::path::Path;
use std::sync::{Arc, Mutex};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    TpmError(tpm_i2c::Error),
    JsonError(serde_json::Error),
    SshKeyError(ssh_key::Error),
    AgentError,
}

macro_rules! error_wrapping_arm {
    ($et:ty, $arm:ident) => {
        impl std::convert::From<$et> for Error {
            fn from(err: $et) -> Self {
                Error::$arm(err)
            }
        }
    };
}

error_wrapping_arm!(std::io::Error, IoError);
error_wrapping_arm!(tpm_i2c::Error, TpmError);
error_wrapping_arm!(serde_json::Error, JsonError);
error_wrapping_arm!(ssh_key::Error, SshKeyError);

impl From<()> for Error {
    fn from(_: ()) -> Self {
        Error::AgentError
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::IoError(e) => write!(f, "{}", e),
            Error::TpmError(e) => write!(f, "{}", e),
            Error::JsonError(e) => write!(f, "{}", e),
            Error::SshKeyError(e) => write!(f, "{}", e),
            Error::AgentError => write!(f, "AgentError"),
        }
    }
}

impl std::error::Error for Error {}

pub struct TpmSshAgent {
    keyman: Arc<Mutex<keyman::TpmKeyManager>>,
}

impl Agent for TpmSshAgent {
    type Error = ();

    fn handle(&self, message: Message) -> std::result::Result<Message, ()> {
        let mut keyman = self.keyman.lock().unwrap();
        keyman.handle_message(message).or_else(|error| {
            println!("Error handling message - {:?}", error);
            Ok(Message::Failure)
        })
    }
}

#[allow(unused_must_use)]
fn main() -> Result<()> {
    let state_file_path = Path::new("state.json").to_path_buf();

    let keyman = Arc::new(Mutex::new(keyman::TpmKeyManager::new(
        state_file_path,
        Box::new(driver::hidapi::MCP2221A::new(0x2e)?),
    )?));

    let agent = TpmSshAgent {
        keyman: keyman.clone(),
    };

    let keyman_for_handler = keyman.clone();
    ctrlc::set_handler(move || {
        keyman_for_handler.lock().unwrap().close();
        println!("saved");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    keyman.lock().unwrap().setup()?;

    let socket = "connect.sock";
    let _ = std::fs::remove_file(socket);

    println!("Run agent at {}", socket);
    agent.run_unix(socket);

    keyman.lock().unwrap().close()?;

    Ok(())
}
