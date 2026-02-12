use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use crate::error::{Result, BlackWraithError};
use reqwest::{Client, Proxy};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

#[derive(Clone, Debug)]
pub struct ProxyManager {
    proxy_url: Option<String>,
}

impl ProxyManager {
    pub fn new(proxy_url: Option<String>) -> Self {
        Self { proxy_url }
    }

    pub fn is_active(&self) -> bool {
        self.proxy_url.is_some()
    }

    /// Creates a reqwest Client that uses the proxy if configured
    pub fn build_http_client(&self) -> Result<Client> {
        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true); // Scanning tools often need this

        if let Some(url) = &self.proxy_url {
            let proxy = Proxy::all(url)
                .map_err(|e| BlackWraithError::Network(format!("Invalid proxy URL: {}", e)))?;
            builder = builder.proxy(proxy);
        }

        builder.build().map_err(BlackWraithError::from)
    }

    /// Establishes a TCP connection, routing through the SOCKS5 proxy if configured.
    /// If no proxy is set, establishes a direct TCP connection.
    pub async fn connect(&self, target: SocketAddr) -> Result<BlackWraithStream> {
        if let Some(proxy_url) = &self.proxy_url {
            let authority = proxy_url
                .trim_start_matches("socks5://")
                .trim_start_matches("socks5h://");
            
            let stream = Socks5Stream::connect(authority, target)
                .await
                .map_err(|e| BlackWraithError::Network(format!("SOCKS5 connect failed: {}", e)))?;
            Ok(BlackWraithStream::Proxied(stream))
        } else {
            let stream = TcpStream::connect(target).await?;
            Ok(BlackWraithStream::Direct(stream))
        }
    }
}

pub enum BlackWraithStream {
    Direct(TcpStream),
    Proxied(Socks5Stream<TcpStream>),
}

impl AsyncRead for BlackWraithStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            BlackWraithStream::Direct(s) => Pin::new(s).poll_read(cx, buf),
            BlackWraithStream::Proxied(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BlackWraithStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            BlackWraithStream::Direct(s) => Pin::new(s).poll_write(cx, buf),
            BlackWraithStream::Proxied(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            BlackWraithStream::Direct(s) => Pin::new(s).poll_flush(cx),
            BlackWraithStream::Proxied(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            BlackWraithStream::Direct(s) => Pin::new(s).poll_shutdown(cx),
            BlackWraithStream::Proxied(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
