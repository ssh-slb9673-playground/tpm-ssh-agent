pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Tpm(tpm_i2c::Error),
    Json(serde_json::Error),
    SshKey(ssh_key::Error),
    Sec1(ssh_key::sec1::Error),
    Agent,
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

error_wrapping_arm!(std::io::Error, Io);
error_wrapping_arm!(tpm_i2c::Error, Tpm);
error_wrapping_arm!(serde_json::Error, Json);
error_wrapping_arm!(ssh_key::Error, SshKey);
error_wrapping_arm!(ssh_key::sec1::Error, Sec1);

impl From<()> for Error {
    fn from(_: ()) -> Self {
        Error::Agent
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::Io(e) => write!(f, "{}", e),
            Error::Tpm(e) => write!(f, "{}", e),
            Error::Json(e) => write!(f, "{}", e),
            Error::SshKey(e) => write!(f, "{}", e),
            Error::Sec1(e) => write!(f, "{}", e),
            Error::Agent => write!(f, "AgentError"),
        }
    }
}

impl std::error::Error for Error {}
