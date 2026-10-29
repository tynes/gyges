//! One accepted socket connection: a unique id, the peer's uid, and a hook
//! that drops the connection's unlocks when it closes (docs/interface.md API §6.3).
//!
//! tonic attaches [`Connected::connect_info`] to every request's extensions,
//! which is how the handlers learn which connection they serve and how the
//! policy layer re-checks the uid.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use gyges_core::VaultManager;
use gyges_core::vault::manager::ConnId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tonic::transport::server::Connected;

/// What every request can see about its connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnInfo {
    pub(crate) id: ConnId,
    /// `None` when the platform did not report peer credentials.
    pub(crate) uid: Option<u32>,
}

/// A `UnixStream` that knows its id and tells the vault when it is gone.
#[derive(Debug)]
pub(crate) struct Conn {
    stream: UnixStream,
    info: ConnInfo,
    vault: Arc<VaultManager>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl Conn {
    pub(crate) fn new(stream: UnixStream, uid: Option<u32>, vault: Arc<VaultManager>) -> Self {
        Self {
            stream,
            info: ConnInfo {
                id: ConnId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
                uid,
            },
            vault,
        }
    }

    pub(crate) fn info(&self) -> ConnInfo {
        self.info
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.vault.connection_closed(self.info.id);
    }
}

impl Connected for Conn {
    type ConnectInfo = ConnInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// The connection a request arrived on, from its extensions.
pub(crate) fn of_request<T>(request: &tonic::Request<T>) -> Option<ConnInfo> {
    request.extensions().get::<ConnInfo>().copied()
}
