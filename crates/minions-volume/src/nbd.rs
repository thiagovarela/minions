//! NBD (Network Block Device) Protocol Implementation
//!
//! Implements the NBD newstyle protocol for serving block devices over Unix sockets.
//! Reference: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

/// NBD protocol magic constants
const NBD_MAGIC: u64 = 0x4e42444d41474943; // "NBDMAGIC"
const NBD_OPTS_MAGIC: u64 = 0x49484156454F5054; // "IHAVEOPT"
const NBD_REP_MAGIC: u64 = 0x3e889045565a9; // Reply magic
const NBD_REQUEST_MAGIC: u32 = 0x25609513;
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x67446698;

/// NBD handshake flags
const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;

/// NBD client flags
const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1 << 0;
const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;

/// NBD export flags
const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
const NBD_FLAG_READ_ONLY: u16 = 1 << 1;
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
const NBD_FLAG_SEND_FUA: u16 = 1 << 3;
const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;

/// NBD options
const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_OPT_ABORT: u32 = 2;
const NBD_OPT_LIST: u32 = 3;
const NBD_OPT_GO: u32 = 7;

/// NBD option reply types
const NBD_REP_ACK: u32 = 1;
const NBD_REP_SERVER: u32 = 2;
const NBD_REP_INFO: u32 = 3;
const NBD_REP_ERR_UNSUP: u32 = 2147483649; // 1 << 31 | 1

/// NBD info types
const NBD_INFO_EXPORT: u16 = 0;

/// NBD commands
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;
const NBD_CMD_TRIM: u16 = 4;

/// NBD command flags
const NBD_CMD_FLAG_FUA: u16 = 1 << 0;

/// NBD error codes
const NBD_SUCCESS: u32 = 0;
const NBD_EIO: u32 = 5;
const NBD_ENOMEM: u32 = 12;
const NBD_EINVAL: u32 = 22;
const NBD_ENOSPC: u32 = 28;

/// NBD request from client
#[derive(Debug)]
pub struct NbdRequest {
    pub magic: u32,
    pub flags: u16,
    pub cmd_type: u16,
    pub handle: u64,
    pub offset: u64,
    pub length: u32,
}

/// NBD reply to client
#[derive(Debug)]
pub struct NbdReply {
    pub magic: u32,
    pub error: u32,
    pub handle: u64,
}

impl NbdRequest {
    /// Read a request from the stream
    pub async fn read_from(stream: &mut UnixStream) -> Result<Self> {
        let magic = stream.read_u32().await?;
        if magic != NBD_REQUEST_MAGIC {
            bail!("Invalid request magic: 0x{:x}", magic);
        }

        let flags = stream.read_u16().await?;
        let cmd_type = stream.read_u16().await?;
        let handle = stream.read_u64().await?;
        let offset = stream.read_u64().await?;
        let length = stream.read_u32().await?;

        Ok(NbdRequest {
            magic,
            flags,
            cmd_type,
            handle,
            offset,
            length,
        })
    }
}

impl NbdReply {
    /// Create a success reply
    pub fn success(handle: u64) -> Self {
        NbdReply {
            magic: NBD_SIMPLE_REPLY_MAGIC,
            error: NBD_SUCCESS,
            handle,
        }
    }

    /// Create an error reply
    pub fn error(handle: u64, error_code: u32) -> Self {
        NbdReply {
            magic: NBD_SIMPLE_REPLY_MAGIC,
            error: error_code,
            handle,
        }
    }

    /// Write reply to stream
    pub async fn write_to(&self, stream: &mut UnixStream) -> Result<()> {
        stream.write_u32(self.magic).await?;
        stream.write_u32(self.error).await?;
        stream.write_u64(self.handle).await?;
        Ok(())
    }
}

/// NBD server configuration
#[derive(Debug, Clone)]
pub struct NbdServerConfig {
    pub socket_path: PathBuf,
    pub export_name: String,
    pub export_size: u64,
    pub read_only: bool,
}

/// NBD command handler trait
/// Implementations provide the actual block device read/write/flush operations
#[async_trait::async_trait]
pub trait NbdCommandHandler: Send + Sync {
    /// Read blocks from the device
    async fn read(&self, offset: u64, length: u32) -> Result<Vec<u8>>;
    
    /// Write blocks to the device
    async fn write(&self, offset: u64, data: &[u8]) -> Result<()>;
    
    /// Flush pending writes
    async fn flush(&self) -> Result<()>;
    
    /// Trim/discard blocks
    async fn trim(&self, offset: u64, length: u32) -> Result<()>;
}

/// NBD server
pub struct NbdServer {
    config: NbdServerConfig,
    listener: Option<UnixListener>,
}

impl NbdServer {
    fn transmission_flags(&self) -> u16 {
        let mut flags = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_TRIM;
        if self.config.read_only {
            flags |= NBD_FLAG_READ_ONLY;
        } else {
            flags |= NBD_FLAG_SEND_FUA;
        }
        flags
    }

    /// Create a new NBD server
    pub fn new(config: NbdServerConfig) -> Result<Self> {
        Ok(NbdServer {
            config,
            listener: None,
        })
    }

    /// Start the server and bind to the socket
    pub async fn start(&mut self) -> Result<()> {
        // Remove existing socket if present
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path)
                .context("Failed to remove existing socket")?;
        }

        // Create parent directory if needed
        if let Some(parent) = self.config.socket_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create socket directory")?;
        }

        let listener = UnixListener::bind(&self.config.socket_path)
            .context("Failed to bind Unix socket")?;

        info!("NBD server listening on {:?}", self.config.socket_path);
        self.listener = Some(listener);
        Ok(())
    }

    /// Accept a single client connection and handle it
    pub async fn accept_and_handle<H>(&mut self, handler: H) -> Result<()>
    where
        H: NbdCommandHandler + 'static,
    {
        let listener = self.listener.as_ref().context("Server not started")?;
        
        let (stream, _addr) = listener.accept().await?;
        info!("Accepted NBD client connection");

        self.handle_client(stream, handler).await
    }

    /// Handle a client connection
    async fn handle_client<H>(&self, mut stream: UnixStream, handler: H) -> Result<()>
    where
        H: NbdCommandHandler,
    {
        // Perform handshake
        self.do_handshake(&mut stream).await?;
        
        // Handle transmission phase (commands)
        self.transmission_phase(stream, handler).await?;
        
        Ok(())
    }

    /// NBD newstyle handshake
    async fn do_handshake(&self, stream: &mut UnixStream) -> Result<()> {
        debug!("Starting NBD handshake");

        // Send initial greeting
        stream.write_u64(NBD_MAGIC).await?;
        stream.write_u64(NBD_OPTS_MAGIC).await?;
        
        // Server handshake flags
        let server_flags = NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES;
        stream.write_u16(server_flags).await?;

        // Read client flags
        let client_flags = stream.read_u32().await?;
        debug!("Client flags: 0x{:x}", client_flags);

        // Option haggling phase
        loop {
            let option_magic = stream.read_u64().await?;
            if option_magic != NBD_OPTS_MAGIC {
                bail!("Invalid option magic: 0x{:x}", option_magic);
            }

            let option = stream.read_u32().await?;
            let length = stream.read_u32().await?;

            match option {
                NBD_OPT_EXPORT_NAME => {
                    // Read export name
                    let mut name_buf = vec![0u8; length as usize];
                    stream.read_exact(&mut name_buf).await?;
                    let requested_name = String::from_utf8_lossy(&name_buf);
                    
                    debug!("Client requested export: {}", requested_name);

                    // Send export size
                    stream.write_u64(self.config.export_size).await?;

                    // Send transmission flags
                    let trans_flags = self.transmission_flags();
                    stream.write_u16(trans_flags).await?;

                    // No zeroes (we set NBD_FLAG_NO_ZEROES)
                    info!("Handshake complete, entering transmission phase");
                    return Ok(());
                }
                NBD_OPT_ABORT => {
                    debug!("Client sent ABORT");
                    bail!("Client aborted connection");
                }
                NBD_OPT_LIST => {
                    // Consume data
                    let mut buf = vec![0u8; length as usize];
                    stream.read_exact(&mut buf).await?;

                    // Send export list (just our one export)
                    stream.write_u64(NBD_REP_MAGIC).await?;
                    stream.write_u32(option).await?;
                    stream.write_u32(NBD_REP_SERVER).await?;
                    
                    let name_bytes = self.config.export_name.as_bytes();
                    stream.write_u32((name_bytes.len() + 4) as u32).await?;
                    stream.write_u32(name_bytes.len() as u32).await?;
                    stream.write_all(name_bytes).await?;

                    // Send ACK
                    stream.write_u64(NBD_REP_MAGIC).await?;
                    stream.write_u32(option).await?;
                    stream.write_u32(NBD_REP_ACK).await?;
                    stream.write_u32(0).await?;
                }
                NBD_OPT_GO => {
                    // GO payload: export name len + export name + info requests
                    let mut payload = vec![0u8; length as usize];
                    stream.read_exact(&mut payload).await?;

                    let requested_name = if payload.len() >= 4 {
                        let name_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                        if payload.len() >= 4 + name_len {
                            String::from_utf8_lossy(&payload[4..4 + name_len]).to_string()
                        } else {
                            self.config.export_name.clone()
                        }
                    } else {
                        self.config.export_name.clone()
                    };

                    debug!("Client sent GO for export '{}'", requested_name);

                    // Send NBD_INFO_EXPORT (size + transmission flags)
                    let trans_flags = self.transmission_flags();
                    stream.write_u64(NBD_REP_MAGIC).await?;
                    stream.write_u32(option).await?;
                    stream.write_u32(NBD_REP_INFO).await?;
                    // payload len: info_type(2) + export_size(8) + export_flags(2) = 12
                    stream.write_u32(12).await?;
                    stream.write_u16(NBD_INFO_EXPORT).await?;
                    stream.write_u64(self.config.export_size).await?;
                    stream.write_u16(trans_flags).await?;

                    // Final ACK
                    stream.write_u64(NBD_REP_MAGIC).await?;
                    stream.write_u32(option).await?;
                    stream.write_u32(NBD_REP_ACK).await?;
                    stream.write_u32(0).await?;

                    info!("Handshake complete (GO), entering transmission phase");
                    return Ok(());
                }
                _ => {
                    // Unsupported option
                    warn!("Unsupported option: {}", option);
                    
                    // Consume data
                    let mut buf = vec![0u8; length as usize];
                    stream.read_exact(&mut buf).await?;

                    // Send error reply
                    stream.write_u64(NBD_REP_MAGIC).await?;
                    stream.write_u32(option).await?;
                    stream.write_u32(NBD_REP_ERR_UNSUP).await?;
                    stream.write_u32(0).await?;
                }
            }
        }
    }

    /// NBD transmission phase - handle read/write commands
    async fn transmission_phase<H>(&self, mut stream: UnixStream, handler: H) -> Result<()>
    where
        H: NbdCommandHandler,
    {
        loop {
            let request = match NbdRequest::read_from(&mut stream).await {
                Ok(req) => req,
                Err(e) => {
                    debug!("Error reading request (client disconnect?): {}", e);
                    break;
                }
            };

            match request.cmd_type {
                NBD_CMD_READ => {
                    debug!(
                        "READ: offset={}, length={}, handle={}",
                        request.offset, request.length, request.handle
                    );

                    match handler.read(request.offset, request.length).await {
                        Ok(data) => {
                            if data.len() != request.length as usize {
                                error!("Read returned wrong length: {} != {}", data.len(), request.length);
                                let reply = NbdReply::error(request.handle, NBD_EIO);
                                reply.write_to(&mut stream).await?;
                            } else {
                                let reply = NbdReply::success(request.handle);
                                reply.write_to(&mut stream).await?;
                                stream.write_all(&data).await?;
                            }
                        }
                        Err(e) => {
                            error!("Read error: {}", e);
                            let reply = NbdReply::error(request.handle, NBD_EIO);
                            reply.write_to(&mut stream).await?;
                        }
                    }
                }
                NBD_CMD_WRITE => {
                    debug!(
                        "WRITE: offset={}, length={}, handle={}",
                        request.offset, request.length, request.handle
                    );

                    if self.config.read_only {
                        warn!("Write attempt on read-only export");
                        let reply = NbdReply::error(request.handle, NBD_EINVAL);
                        reply.write_to(&mut stream).await?;
                        continue;
                    }

                    // Read data from stream
                    let mut data = vec![0u8; request.length as usize];
                    stream.read_exact(&mut data).await?;

                    match handler.write(request.offset, &data).await {
                        Ok(()) => {
                            let reply = NbdReply::success(request.handle);
                            reply.write_to(&mut stream).await?;
                        }
                        Err(e) => {
                            error!("Write error: {}", e);
                            let reply = NbdReply::error(request.handle, NBD_EIO);
                            reply.write_to(&mut stream).await?;
                        }
                    }

                    // Handle FUA (force unit access) - flush immediately
                    if request.flags & NBD_CMD_FLAG_FUA != 0 {
                        debug!("FUA flag set, flushing");
                        if let Err(e) = handler.flush().await {
                            error!("FUA flush error: {}", e);
                        }
                    }
                }
                NBD_CMD_FLUSH => {
                    debug!("FLUSH: handle={}", request.handle);

                    match handler.flush().await {
                        Ok(()) => {
                            let reply = NbdReply::success(request.handle);
                            reply.write_to(&mut stream).await?;
                        }
                        Err(e) => {
                            error!("Flush error: {}", e);
                            let reply = NbdReply::error(request.handle, NBD_EIO);
                            reply.write_to(&mut stream).await?;
                        }
                    }
                }
                NBD_CMD_TRIM => {
                    debug!(
                        "TRIM: offset={}, length={}, handle={}",
                        request.offset, request.length, request.handle
                    );

                    match handler.trim(request.offset, request.length).await {
                        Ok(()) => {
                            let reply = NbdReply::success(request.handle);
                            reply.write_to(&mut stream).await?;
                        }
                        Err(e) => {
                            warn!("Trim error: {}", e);
                            let reply = NbdReply::error(request.handle, NBD_EIO);
                            reply.write_to(&mut stream).await?;
                        }
                    }
                }
                NBD_CMD_DISC => {
                    info!("Client disconnecting");
                    break;
                }
                _ => {
                    warn!("Unknown command type: {}", request.cmd_type);
                    let reply = NbdReply::error(request.handle, NBD_EINVAL);
                    reply.write_to(&mut stream).await?;
                }
            }
        }

        info!("Transmission phase ended");
        Ok(())
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }
}

impl Drop for NbdServer {
    fn drop(&mut self) {
        // Clean up socket file
        if self.config.socket_path.exists() {
            let _ = std::fs::remove_file(&self.config.socket_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nbd_request_size() {
        // NBD request should be 28 bytes
        // 4 (magic) + 2 (flags) + 2 (type) + 8 (handle) + 8 (offset) + 4 (length)
        assert_eq!(std::mem::size_of::<u32>() + std::mem::size_of::<u16>() * 2 
                   + std::mem::size_of::<u64>() * 2 + std::mem::size_of::<u32>(), 28);
    }

    #[test]
    fn test_nbd_reply_size() {
        // NBD reply should be 16 bytes
        // 4 (magic) + 4 (error) + 8 (handle)
        assert_eq!(std::mem::size_of::<u32>() * 2 + std::mem::size_of::<u64>(), 16);
    }
}
