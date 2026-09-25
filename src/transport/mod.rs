//! Private transport boundary for the connection.
//!
//! A transport is a byte stream: reads and writes may be short, and one
//! read may carry part of a frame or more than one frame. Framing belongs
//! to the protocol module, not here.
//!
//! The boundary carries two implementations: the Tokio TCP transport used
//! in production and an in-memory transport used to drive deterministic
//! fragmentation and partial writes in tests. Neither is public.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A byte-stream a connection reads from and writes to.
pub trait Transport {
    /// Reads into `buffer`, returning the number of bytes read, or zero at
    /// end of stream.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error.
    fn read(&mut self, buffer: &mut [u8]) -> impl Future<Output = io::Result<usize>>;

    /// Writes part of `bytes`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error.
    fn write(&mut self, bytes: &[u8]) -> impl Future<Output = io::Result<usize>>;

    /// Closes the transport.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error.
    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>>;
}

/// A Tokio TCP transport.
#[derive(Debug)]
pub struct TokioTransport {
    stream: TcpStream,
}

impl TokioTransport {
    /// Opens a TCP connection to `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns the error the operating system reports for the address.
    pub async fn connect(endpoint: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(endpoint).await?;
        Ok(Self { stream })
    }
}

impl Transport for TokioTransport {
    async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer).await
    }

    async fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(bytes).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }
}

/// A transport a test feeds and reads deterministically.
#[cfg(test)]
#[derive(Debug)]
pub struct InMemoryTransport {
    inbound: std::collections::VecDeque<u8>,
    read_step: usize,
    written: Vec<u8>,
    write_step: usize,
    closed: bool,
}

#[cfg(test)]
impl InMemoryTransport {
    /// Builds a transport from the bytes a peer sends and the most bytes
    /// one read or one write may move.
    pub fn new(inbound: &[u8], read_step: usize, write_step: usize) -> Self {
        Self {
            inbound: inbound.iter().copied().collect(),
            read_step,
            written: Vec::new(),
            write_step,
            closed: false,
        }
    }

    /// Returns the bytes written so far.
    pub fn written(&self) -> &[u8] {
        &self.written
    }
}

#[cfg(test)]
impl Transport for InMemoryTransport {
    fn read(&mut self, buffer: &mut [u8]) -> impl Future<Output = io::Result<usize>> {
        if self.closed {
            return std::future::ready(Ok(0));
        }
        let available = buffer.len().min(self.read_step).min(self.inbound.len());
        for slot in buffer.iter_mut().take(available) {
            *slot = self.inbound.pop_front().unwrap_or(0);
        }
        std::future::ready(Ok(available))
    }

    fn write(&mut self, bytes: &[u8]) -> impl Future<Output = io::Result<usize>> {
        if self.closed {
            return std::future::ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        }
        let step = self.write_step.max(1);
        let available = bytes.len().min(step);
        let part = bytes.get(..available).unwrap_or(&[]);
        self.written.extend_from_slice(part);
        std::future::ready(Ok(part.len()))
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.closed = true;
        std::future::ready(Ok(()))
    }
}

/// The transport a connection owns.
#[derive(Debug)]
pub enum AnyTransport {
    /// A Tokio TCP transport.
    Tcp(TokioTransport),
    /// A deterministic in-memory transport, for tests.
    #[cfg(test)]
    Memory(InMemoryTransport),
}

impl AnyTransport {
    /// Reads into `buffer`.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error.
    pub async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(transport) => transport.read(buffer).await,
            #[cfg(test)]
            Self::Memory(transport) => transport.read(buffer).await,
        }
    }

    /// Writes part of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error.
    pub async fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(transport) => transport.write(bytes).await,
            #[cfg(test)]
            Self::Memory(transport) => transport.write(bytes).await,
        }
    }

    /// Closes the transport.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(transport) => transport.shutdown().await,
            #[cfg(test)]
            Self::Memory(transport) => transport.shutdown().await,
        }
    }
}
