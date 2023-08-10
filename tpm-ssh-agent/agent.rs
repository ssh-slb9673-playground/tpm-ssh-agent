use crate::error::Result;
use crate::keyman::TpmKeyManager;
use ssh_agent_lib::proto::message::{Identity, Message};
use ssh_agent_lib::proto::PublicKey::Rsa;
use ssh_agent_lib::proto::{signature, RsaPublicKey, Signature};
use ssh_agent_lib::Agent;
use std::sync::{Arc, Mutex};

pub struct TpmSshAgent {
    keyman: Arc<Mutex<TpmKeyManager>>,
}

impl Agent for TpmSshAgent {
    type Error = ();

    fn handle(&self, message: Message) -> std::result::Result<Message, ()> {
        self.handle_message(message).or(Ok(Message::Failure))
    }
}

impl TpmSshAgent {
    pub fn new(keyman: Arc<Mutex<TpmKeyManager>>) -> Result<Self> {
        let keyman_for_handler = keyman.clone();
        ctrlc::set_handler(move || {
            if let Err(e) = keyman_for_handler.lock().unwrap().close() {
                dbg!(e);
                std::process::exit(1);
            }
            println!("saved");
            std::process::exit(0);
        })
        .expect("Error setting Ctrl-C handler");

        keyman.lock().unwrap().setup()?;
        Ok(TpmSshAgent { keyman })
    }

    pub fn handle_message(
        &self,
        request: Message,
    ) -> std::result::Result<Message, Box<dyn std::error::Error>> {
        use ssh_agent_lib::proto::to_bytes;
        let keyman = &mut self.keyman.lock().unwrap();

        match request {
            Message::RequestIdentities => {
                let mut identities = vec![];
                for identity in keyman.identities.iter() {
                    identities.push(Identity {
                        pubkey_blob: to_bytes(&Rsa(RsaPublicKey {
                            e: identity.e.clone(),
                            n: identity.n.clone(),
                        }))?,
                        comment: "tpm_key".to_string(),
                    });
                }
                Ok(Message::IdentitiesAnswer(identities))
            }
            Message::SignRequest(request) => {
                if request.flags & signature::RSA_SHA2_256 == 0 {
                    println!("Error: Unsupported algorithm has specified");
                    Ok(Message::Failure)
                } else {
                    let signature = to_bytes(&Signature {
                        algorithm: "rsa-sha2-256".to_string(),
                        blob: keyman.sign(&request.data)?,
                    })?;
                    Ok(Message::SignResponse(signature))
                }
            }
            _ => Err(format!("Unknown message: {:?}", request).into()),
        }
    }

    pub fn get_identities_as_ssh_format(&self) -> Result<Vec<String>> {
        use ssh_key::public::{KeyData, RsaPublicKey};
        use ssh_key::{MPInt, PublicKey};

        let mut res = vec![];
        for identity in &self.keyman.lock().unwrap().identities {
            res.push(
                PublicKey::new(
                    KeyData::Rsa(RsaPublicKey {
                        e: MPInt::from_bytes(&identity.e)?,
                        n: MPInt::from_bytes(&identity.n)?,
                    }),
                    "tpm_key",
                )
                .to_openssh()?,
            );
        }
        Ok(res)
    }
}
