mod driver;
mod state;
use rand::prelude::*;
use ssh_agent_lib::proto::message::{Identity, Message};
use ssh_agent_lib::proto::{SignRequest, Signature};
use ssh_agent_lib::Agent;
use ssh_key::public::{KeyData, RsaPublicKey};
use ssh_key::{MPInt, PublicKey};
use state::State;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tpm_i2c::tpm::session::TpmSession;
use tpm_i2c::tpm::structure::*;
use tpm_i2c::tpm::{I2CTpmAccessor, Tpm};

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

fn get_rsa_public_template(bits: u16, symmetric: TpmtSymdefObject) -> TpmuPublicParams {
    TpmuPublicParams::RsaDetail(TpmsRsaParams {
        symmetric,
        scheme: TpmtRsaScheme {
            scheme: TpmiAlgorithmRsaScheme::RsaSsa,
            details: TpmuAsymmetricScheme::Signature(TpmsSignatureScheme::AX(TpmsSchemeHash {
                hash_algorithm: TpmiAlgorithmHash::Sha256,
            })),
        },
        key_bits: bits,
        exponent: 65537,
    })
}

fn get_null_symdefobj() -> TpmtSymdefObject {
    TpmtSymdefObject {
        algorithm: TpmiAlgorithmSymObject::Null,
        key_bits: TpmuSymKeybits::Null,
        mode: TpmuSymMode::Null,
    }
}

fn create_primary_key(
    tpm: &mut Tpm,
    session: &mut TpmSession,
    auth_value: &[u8],
) -> Result<tpm_i2c::tpm::commands::Tpm2CreatePrimaryResponse> {
    tpm.create_primary(
        TpmPermanentHandle::Owner.into(),
        session,
        vec![],
        Tpm2BSensitiveCreate {
            sensitive: TpmsSensitiveCreate {
                user_auth: Tpm2BAuth::new(auth_value),
                data: Tpm2BSensitiveData::new(&[]),
            },
        },
        Tpm2BPublic::new(TpmtPublic {
            algorithm_type: TpmiAlgorithmPublic::Rsa,
            algorithm_name: TpmiAlgorithmHash::Sha256,
            object_attributes: TpmAttrObject::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_sign_or_encrypt(true)
                .with_user_with_auth(true),
            auth_policy: Tpm2BDigest::new(&[]),
            parameters: get_rsa_public_template(2048, get_null_symdefobj()),
            unique: TpmuPublicIdentifier::Rsa(Tpm2BDigest::new(&[])),
        }),
        Tpm2BData::new(&[]),
        TpmlPcrSelection {
            pcr_selections: vec![],
        },
    )
    .map_err(|err| err.into())
}

fn create_session(tpm: &mut Tpm, first_nonce: &[u8]) -> Result<TpmSession> {
    tpm.start_auth_session(
        TpmiDhObject::Null,
        TpmiDhEntity::Null,
        Tpm2BNonce::new(first_nonce),
        Tpm2BEncryptedSecret::new(&[]),
        TpmSessionType::Hmac,
        TpmtSymdef {
            algorithm: TpmiAlgorithmSymmetric::Null,
            key_bits: TpmuSymKeybits::Null,
            mode: TpmuSymMode::Null,
        },
        TpmiAlgorithmHash::Sha256,
        vec![],
    )
    .map_or_else(
        |err| Err(err.into()),
        |mut x| {
            x.attributes.set_continue_session(true);
            Ok(x)
        },
    )
}

pub struct TpmSshWrapper {
    pub state_file_path: PathBuf,
    pub tpm: Tpm,
    pub state: State,
    pub identities: RwLock<Vec<ssh_agent_lib::proto::PublicKey>>,
}

fn next_nonce() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut ret = [0u8; 16];
    rng.fill_bytes(&mut ret);
    ret
}

fn remove_handles(tpm: &mut Tpm, ht: TpmHandleType) -> Result<()> {
    use tpm_i2c::tpm::structure::*;
    if let TpmuCapabilities::Handles(x) = &tpm
        .get_capability(TpmCapabilities::Handles, (ht as u32) << 24, 5)?
        .1
        .data
    {
        for handle in &x.handle {
            println!("[+] Flush 0x{:08x}", handle);
            let _ = &tpm.flush_context(*handle);
        }
    }
    Ok(())
}

impl TpmSshWrapper {
    pub fn new(state_file_path: PathBuf, device: Box<dyn I2CTpmAccessor>) -> Result<TpmSshWrapper> {
        let mut tpm = Tpm::new(device)?;
        if let Err(tpm_i2c::Error::TpmError(tpm_i2c::tpm::TpmError::UnsuccessfulResponse(
            TpmResponseCode::ErrorForParam((_, TpmResponseCodeFormat1::Value)),
        ))) = tpm.init(false)
        {
            println!("[*] Startup without all data");
            tpm.init(true)?;
        }

        let state = State::load(&state_file_path)?.map_or_else(
            || -> Result<State> {
                remove_handles(&mut tpm, TpmHandleType::HmacOrLoadedSession)?;
                remove_handles(&mut tpm, TpmHandleType::Transient)?;
                Ok(State {
                    session: None,
                    primary_handle: None,
                })
            },
            Ok,
        )?;

        tpm.print_info()?;

        Ok(TpmSshWrapper {
            state_file_path,
            tpm,
            state,
            identities: RwLock::new(vec![]),
        })
    }

    pub fn open_session(&mut self) -> Result<()> {
        remove_handles(&mut self.tpm, TpmHandleType::HmacOrLoadedSession)?;
        self.state.session = Some(create_session(&mut self.tpm, &next_nonce())?);
        Ok(())
    }

    pub fn sign_raw(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let digest = TpmiAlgorithmHash::Sha256.digest(msg);
        let sig = self.tpm.sign(
            self.state.primary_handle.unwrap(),
            self.state.session.as_mut().unwrap(),
            "password".as_bytes().to_vec(),
            &digest,
            TpmtSignatureScheme {
                scheme: TpmiAlgorithmSigScheme::RsaSsa,
                details: TpmsSignatureScheme::AX(TpmsSchemeHash {
                    hash_algorithm: TpmiAlgorithmHash::Sha256,
                }),
            },
            TpmtTicketHashCheck {
                tag: TpmStructureTag::HashCheck,
                hierarchy: TpmiHandleHierarchy::Owner,
                digest: Tpm2BDigest::new(&[]),
            },
        )?;

        Ok(match sig.details {
            TpmuSignature::Rsa(x) => x.signature.buffer,
            _ => todo!(),
        })
    }

    pub fn close(&mut self) -> Result<()> {
        self.state.save(&self.state_file_path)?;
        self.tpm.shutdown(false)?;
        Ok(())
    }

    pub fn sign(
        &mut self,
        request: &SignRequest,
    ) -> std::result::Result<Option<Signature>, Box<dyn std::error::Error>> {
        /*
        if request.flags & signature::RSA_SHA2_256 != 0 {
            algorithm = "rsa-sha2-256";
            digest = TpmiAlgorithmHash::Sha256;
        } else {
            algorithm = "ssh-rsa";
            digest = TpmiAlgorithmHash::Sha1;
        }*/
        /*if request.flags & ssh_agent_lib::proto::signature::RSA_SHA2_256 == 0 {
            println!("Error");
            return Ok(None);
        }*/

        let algorithm = "rsa-sha2-256";

        self.state
            .session
            .as_mut()
            .unwrap()
            .set_nonce(next_nonce().to_vec());
        let res = self.sign_raw(&request.data)?;

        Ok(Some(Signature {
            algorithm: algorithm.to_string(),
            blob: [res].concat(),
        }))
    }

    fn handle_message(
        &mut self,
        request: Message,
    ) -> std::result::Result<Message, Box<dyn std::error::Error>> {
        use ssh_agent_lib::proto::to_bytes;

        match request {
            Message::RequestIdentities => {
                let mut identities = vec![];
                for identity in self.identities.read().unwrap().iter() {
                    identities.push(Identity {
                        pubkey_blob: to_bytes(&identity)?,
                        comment: "tpm_key".to_string(),
                    });
                }
                Ok(Message::IdentitiesAnswer(identities))
            }
            Message::SignRequest(request) => {
                if let Some(sig) = self.sign(&request)? {
                    let signature = to_bytes(&sig)?;
                    Ok(Message::SignResponse(signature))
                } else {
                    Ok(Message::Failure)
                }
            }
            _ => Err(format!("Unknown message: {:?}", request).into()),
        }
    }

    pub fn setup(&mut self) -> Result<()> {
        self.open_session()?;
        if self.state.primary_handle.is_none() {
            self.state
                .session
                .as_mut()
                .unwrap()
                .set_nonce(next_nonce().to_vec());
            let res = create_primary_key(
                &mut self.tpm,
                self.state.session.as_mut().unwrap(),
                "password".as_bytes(),
            )?;
            self.state.primary_handle = Some(res.handle);
        }
        println!("state: {:?}", &self.state);

        /*
        self.state.session.set_nonce(next_nonce().to_vec());
        let signature = self.sign_raw("hello world".as_bytes())?;
        */

        let public_data = self.tpm.read_public(self.state.primary_handle.unwrap())?;
        if let Some(x) = public_data.0.public_area {
            if let TpmuPublicIdentifier::Rsa(y) = x.unique {
                let pubkey_modulus = [vec![0], y.buffer].concat();
                let pubkey = PublicKey::new(
                    KeyData::Rsa(RsaPublicKey {
                        e: MPInt::from_bytes(&[0x01, 0x00, 0x01])?,
                        n: MPInt::from_bytes(&pubkey_modulus)?,
                    }),
                    "tpm_key",
                );
                self.identities
                    .write()
                    .unwrap()
                    .push(ssh_agent_lib::proto::PublicKey::Rsa(
                        ssh_agent_lib::proto::RsaPublicKey {
                            e: vec![0x01, 0x00, 0x01],
                            n: pubkey_modulus,
                        },
                    ));
                println!("[+] Public key: {:?}", pubkey.to_openssh()?);
            }
        }

        Ok(())
    }
}

pub struct TpmSshAgent {
    wrapper: Arc<Mutex<TpmSshWrapper>>,
}

impl Agent for TpmSshAgent {
    type Error = ();

    fn handle(&self, message: Message) -> std::result::Result<Message, ()> {
        let mut wrapper = self.wrapper.lock().unwrap();
        wrapper.handle_message(message).or_else(|error| {
            println!("Error handling message - {:?}", error);
            Ok(Message::Failure)
        })
    }
}

#[allow(unused_must_use)]
fn main() -> Result<()> {
    let state_file_path = Path::new("state.json").to_path_buf();

    let wrapper = Arc::new(Mutex::new(TpmSshWrapper::new(
        state_file_path,
        Box::new(driver::hidapi::MCP2221A::new(0x2e)?),
    )?));

    let agent = TpmSshAgent {
        wrapper: wrapper.clone(),
    };

    let wrapper_for_handler = wrapper.clone();
    ctrlc::set_handler(move || {
        wrapper_for_handler.lock().unwrap().close();
        println!("saved");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    wrapper.lock().unwrap().setup()?;

    println!(
        "session handle: {:08x}",
        wrapper
            .lock()
            .unwrap()
            .state
            .session
            .as_ref()
            .unwrap()
            .handle
    );

    let socket = "connect.sock";
    let _ = std::fs::remove_file(socket);

    println!("Run agent at {}", socket);
    agent.run_unix(socket);

    wrapper.lock().unwrap().close()?;

    Ok(())
}
