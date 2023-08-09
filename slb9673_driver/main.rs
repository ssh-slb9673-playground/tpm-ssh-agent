mod driver;
mod error;
mod keyman;
mod state;
use ssh_agent_lib::proto::message::Message;
use ssh_agent_lib::Agent;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub use error::{Error, Result};

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
