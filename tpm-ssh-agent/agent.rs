use crate::error::Result;
use crate::keyman::TpmKeyManager;
use ssh_agent_lib::proto::message::{Identity, Message};
use ssh_agent_lib::proto::PublicKey::EcDsa;
use ssh_agent_lib::proto::{EcDsaPublicKey, Signature};
use ssh_agent_lib::Agent;
use std::sync::{Arc, Mutex};
use tpm_i2c::tpm::ToTpm;

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
                        pubkey_blob: to_bytes(&EcDsa(EcDsaPublicKey {
                            identifier: "nistp256".to_string(),
                            q: Self::point_compression(identity),
                        }))?,
                        comment: "tpm_key".to_string(),
                    });
                }
                Ok(Message::IdentitiesAnswer(identities))
            }
            Message::SignRequest(request) => {
                let (r, s) = keyman.sign(&request.data)?;
                let signature = to_bytes(&Signature {
                    algorithm: "ecdsa-sha2-nistp256".to_string(),
                    blob: [
                        (r.len() as u32 + 1).to_tpm(),
                        vec![0],
                        r,
                        (s.len() as u32 + 1).to_tpm(),
                        vec![0],
                        s,
                    ]
                    .concat(),
                })?;
                Ok(Message::SignResponse(signature))
            }
            _ => Err(format!("Unknown message: {:?}", request).into()),
        }
    }

    pub fn get_identities_as_ssh_format(&self) -> Result<Vec<String>> {
        use ssh_key::public::{EcdsaPublicKey, KeyData};
        use ssh_key::PublicKey;

        let mut res = vec![];
        for identity in &self.keyman.lock().unwrap().identities {
            res.push(
                PublicKey::new(
                    KeyData::Ecdsa(EcdsaPublicKey::NistP256(
                        ssh_key::sec1::point::EncodedPoint::from_bytes(Self::point_compression(
                            identity,
                        ))?,
                    )),
                    "tpm_key",
                )
                .to_openssh()?,
            );
        }
        Ok(res)
    }

    fn point_compression(pubkey: &crate::keyman::EcDsaPublicKey) -> Vec<u8> {
        let padding_x = 32 - pubkey.x.len();
        let padding_y = 32 - pubkey.y.len();
        [
            vec![4],
            vec![0; padding_x],
            pubkey.x.clone(),
            vec![0; padding_y],
            pubkey.y.clone(),
        ]
        .concat()
    }
}
