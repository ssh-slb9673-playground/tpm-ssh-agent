pub type Result<T> = std::result::Result<T, Error>;

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
