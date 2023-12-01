pub mod i2c;

use crate::TpmResult;

pub trait Tcti: Sync + Send {
    fn device_init(&mut self) -> TpmResult<()>;
    fn recv(&mut self) -> TpmResult<Vec<u8>>;
    fn send(&mut self, data: &[u8]) -> TpmResult<()>;
}
