use hal_proto::wire::{read_frame, write_frame, BusRequest, BusResponse};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Blocking Unix Domain Socket client for communicating with `hal-bus`.
pub struct BusClient {
    stream: UnixStream,
}

impl BusClient {
    pub fn connect(socket_path: impl AsRef<Path>) -> io::Result<Self> {
        let stream = UnixStream::connect(socket_path)?;
        Ok(Self { stream })
    }

    pub fn call(&mut self, req: &BusRequest) -> io::Result<BusResponse> {
        write_frame(&mut self.stream, req)?;
        read_frame(&mut self.stream)
    }
}
