// Stract is an open source web search engine.
// Copyright (C) 2024 Stract ApS
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

pub mod connection_pool;
pub mod replication;
pub mod service;

mod framing;
#[cfg(test)]
mod framing_tests;

pub use connection_pool::ConnectionPool;

use std::{marker::PhantomData, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

use framing::{close_peer, encode_frame, read_frame, write_frame, FrameObserver};

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

/// Default maximum encoded body bytes for one sonic frame, excluding the native-width header.
///
/// 67,108,864 bytes (64 MiB) applies to outgoing encodes and incoming declarations alike.
/// Services override it with `sonic_service!(…, max_frame_body_bytes = …)`; raw callers use
/// the `*_with_limit` and `*_and_limit` constructors. Larger values fail with a typed error.
pub const DEFAULT_MAX_FRAME_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONNECTION_TTL: Duration = Duration::from_secs(60);

/// Failure of one sonic connection operation.
///
/// Every framing failure (I/O, size, allocation, decode, encode or trailing bytes) discards the
/// affected socket before it is returned, so the owner can never reuse a desynchronised stream.
/// `Display` never contains frame text. `Debug` and `source()` of `Decode`/`Encode` can carry
/// bincode detail, including up to four body bytes or a serde message, so avoid logging them.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Socket I/O failed; a partial header or body is reported as `UnexpectedEof`.
    #[error("Got an IO error")]
    IO(#[from] std::io::Error),

    /// The connection attempt (or every retried attempt) missed its deadline or failed.
    #[error("Failed to connect to peer: connection timeout")]
    ConnectionTimeout,

    /// An owned exchange deadline elapsed; the socket has been discarded.
    #[error("Failed to get response for request: connection timeout")]
    RequestTimeout,

    /// A pooled connection could not be checked out.
    #[error("Could not get connection from pool")]
    PoolGet,

    /// The application rejected the request.
    #[error("The request could not be processed")]
    BadRequest,

    /// A frame body exceeded the configured cap; nothing beyond the header was read or sent.
    #[error("The body size ({body_size}) is larger than the maximum allowed ({max_size})")]
    BodyTooLarge {
        /// Declared body bytes on a read; on a write, the first encoded length that crossed
        /// the cap, which can be a lower bound on the complete value's size.
        body_size: usize,
        /// Configured maximum encoded body bytes, excluding the header.
        max_size: usize,
    },

    /// Bincode rejected the body, including `LimitExceeded` from the decoder claim budget.
    #[error("Could not decode frame body")]
    Decode(#[source] bincode::error::DecodeError),

    /// Bincode could not encode the value; no frame byte was written.
    #[error("Could not encode frame body")]
    Encode(#[source] bincode::error::EncodeError),

    /// A bounded body-storage reservation failed.
    #[error("Could not allocate frame body storage")]
    Allocation(#[source] std::collections::TryReserveError),

    /// The decoder finished one value before the end of the declared body.
    #[error("Frame body contains trailing bytes")]
    TrailingBytes {
        /// Body bytes consumed by the decoded value.
        consumed: usize,
        /// Complete declared body length in bytes.
        body_size: usize,
    },

    /// An earlier failure already discarded this connection's socket.
    #[error("Connection is closed")]
    ConnectionClosed,

    /// An application error unrelated to framing.
    #[error("An application error occurred: {0}")]
    Application(#[from] anyhow::Error),
}

/// Reusable raw client stream with one body-byte cap for requests sent and responses read.
///
/// After any returned error the socket is gone: later calls return
/// [`Error::ConnectionClosed`] and pools refuse to recycle the connection.
pub struct Connection<Req, Res> {
    stream: Option<TcpStream>,
    max_frame_body_bytes: usize,
    observer: FrameObserver,
    created: std::time::Instant,
    marker: PhantomData<(Req, Res)>,
    awaiting_res: bool,
}

impl<Req, Res> Connection<Req, Res>
where
    Req: bincode::Encode,
    Res: bincode::Decode,
{
    /// Connects with the default frame cap and a 30-second connection deadline.
    pub async fn connect(server: impl ToSocketAddrs) -> Result<Self> {
        Self::create(server).await
    }

    /// Connects with the default frame cap and a 30-second connection deadline.
    pub async fn create(server: impl ToSocketAddrs) -> Result<Self> {
        Self::create_with_timeout(server, Duration::from_secs(30)).await
    }

    /// Connects with the default frame cap and the supplied connection deadline.
    pub async fn create_with_timeout(
        server: impl ToSocketAddrs,
        timeout: Duration,
    ) -> Result<Self> {
        Self::create_with_timeout_and_limit(server, timeout, DEFAULT_MAX_FRAME_BODY_BYTES).await
    }

    /// Connects with an explicit encoded body-byte cap for outgoing requests and incoming
    /// responses.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionTimeout`] when `timeout` elapses and [`Error::IO`] when the
    /// connection fails.
    pub async fn create_with_timeout_and_limit(
        server: impl ToSocketAddrs,
        timeout: Duration,
        max_frame_body_bytes: usize,
    ) -> Result<Self> {
        match tokio::time::timeout(timeout, TcpStream::connect(server)).await {
            Ok(stream) => {
                let stream = stream?;
                stream.set_nodelay(true)?;

                Ok(Connection {
                    stream: Some(stream),
                    max_frame_body_bytes,
                    observer: FrameObserver::default(),
                    awaiting_res: false,
                    created: std::time::Instant::now(),
                    marker: PhantomData,
                })
            }
            Err(_) => Err(Error::ConnectionTimeout),
        }
    }

    /// Connects with the default frame cap, retrying failures after each `retry` delay, which
    /// also becomes the next attempt's deadline.
    pub async fn create_with_timeout_retry(
        server: impl ToSocketAddrs + Clone,
        timeout: Duration,
        retry: impl Iterator<Item = Duration>,
    ) -> Result<Self> {
        Self::create_with_timeout_retry_and_limit(
            server,
            timeout,
            retry,
            DEFAULT_MAX_FRAME_BODY_BYTES,
        )
        .await
    }

    /// Connects like [`Self::create_with_timeout_retry`], applying the same explicit
    /// body-byte cap to every attempt.
    ///
    /// # Errors
    /// Returns [`Error::ConnectionTimeout`] once `retry` is exhausted.
    pub async fn create_with_timeout_retry_and_limit(
        server: impl ToSocketAddrs + Clone,
        mut timeout: Duration,
        mut retry: impl Iterator<Item = Duration>,
        max_frame_body_bytes: usize,
    ) -> Result<Self> {
        let retry_frame_limit = max_frame_body_bytes;
        // One creation call site guarantees that every attempt carries the same cap.
        loop {
            match Self::create_with_timeout_and_limit(server.clone(), timeout, retry_frame_limit)
                .await
            {
                Ok(conn) => return Ok(conn),
                Err(_) => {
                    if let Some(next_timeout) = retry.next() {
                        timeout = next_timeout;
                        tokio::time::sleep(timeout).await;
                    } else {
                        return Err(Error::ConnectionTimeout);
                    }
                }
            }
        }
    }

    /// Sends one request and returns the complete decoded response, with no deadline.
    ///
    /// # Errors
    /// Any returned error discards the socket. Dropping this future part-way leaves the
    /// connection awaiting a response, so a cancelled owner must be discarded too.
    pub async fn send_without_timeout(&mut self, request: &Req) -> Result<Res> {
        self.awaiting_res = true;
        let result = self.exchange(request).await;
        if result.is_err() {
            close_peer(&mut self.stream);
        } else {
            self.awaiting_res = false;
        }
        result
    }

    // Every fallible step stays inside the caller's cleanup boundary, so no early return can
    // leave a half-used stream behind.
    async fn exchange(&mut self, request: &Req) -> Result<Res> {
        let stream = self.stream.as_mut().ok_or(Error::ConnectionClosed)?;
        let request_write_limit = self.max_frame_body_bytes;
        let bytes = encode_frame(request, request_write_limit, &self.observer)?;
        write_frame(stream, &bytes, &self.observer).await?;
        let response_read_limit = self.max_frame_body_bytes;
        read_frame(stream, response_read_limit, &self.observer).await
    }

    /// Sends one request within the established 90-second exchange deadline.
    ///
    /// # Errors
    /// As [`Self::send_with_timeout`].
    pub async fn send(&mut self, request: &Req) -> Result<Res> {
        self.send_with_timeout(request, Duration::from_secs(90))
            .await
    }

    /// Sends one request within `timeout`.
    ///
    /// # Errors
    /// Returns the exchange's typed error, or [`Error::RequestTimeout`] when the deadline
    /// elapses; either way the socket is discarded.
    pub async fn send_with_timeout(&mut self, request: &Req, timeout: Duration) -> Result<Res> {
        match tokio::time::timeout(timeout, self.send_without_timeout(request)).await {
            Ok(res) => res,
            Err(_) => {
                close_peer(&mut self.stream);
                Err(Error::RequestTimeout)
            }
        }
    }

    /// Returns true while an exchange is pending or after one failed, so pools never
    /// recycle it.
    pub fn awaiting_response(&self) -> bool {
        self.awaiting_res
    }

    /// Returns true for a discarded socket without probing it, and otherwise keeps the
    /// existing 60-second TTL and liveness probe.
    pub async fn is_closed(&mut self) -> bool {
        let Some(stream) = self.stream.as_mut() else {
            return true;
        };
        if self.created.elapsed() > MAX_CONNECTION_TTL {
            stream.shutdown().await.ok();
            return true;
        }

        !matches!(
            tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut [])).await,
            Ok(Ok(_))
        )
    }
}

/// Raw listener whose accepted peers each inherit its encoded body-byte cap.
pub struct Server<Req, Res> {
    listener: TcpListener,
    max_frame_body_bytes: usize,
    marker: PhantomData<(Req, Res)>,
}

impl<Req, Res> Server<Req, Res>
where
    Req: bincode::Decode,
{
    /// Binds with the default cap for request reads and response writes.
    pub async fn bind(addr: impl ToSocketAddrs) -> Result<Self> {
        Self::bind_with_limit(addr, DEFAULT_MAX_FRAME_BODY_BYTES).await
    }

    /// Binds with an explicit encoded body-byte cap for request reads and response writes.
    ///
    /// The cap is finite by design; zero admits only zero-byte encodings such as `()`.
    pub async fn bind_with_limit(
        addr: impl ToSocketAddrs,
        max_frame_body_bytes: usize,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Server {
            listener,
            max_frame_body_bytes,
            marker: PhantomData,
        })
    }

    /// Accepts one peer; its failures never affect the listener or other peers.
    pub async fn accept(&self) -> Result<ServerConnection<Req, Res>> {
        let (stream, client) = self.listener.accept().await?;
        tracing::debug!(?client, "accepted connection");

        Ok(ServerConnection::new(stream, self.max_frame_body_bytes))
    }
}

/// One accepted peer socket, discarded after any returned framing failure.
pub struct ServerConnection<Req, Res> {
    stream: Option<TcpStream>,
    max_frame_body_bytes: usize,
    observer: FrameObserver,
    marker: PhantomData<(Req, Res)>,
}

impl<Req, Res> ServerConnection<Req, Res>
where
    Req: bincode::Decode,
{
    // Each accepted peer owns its policy copy and observation state.
    fn new(stream: TcpStream, max_frame_body_bytes: usize) -> Self {
        ServerConnection {
            stream: Some(stream),
            max_frame_body_bytes,
            observer: FrameObserver::default(),
            marker: PhantomData,
        }
    }

    /// Reads and decodes one whole bounded request frame.
    ///
    /// # Errors
    /// Returns the typed framing error after discarding this peer's socket; later calls
    /// return [`Error::ConnectionClosed`].
    pub async fn request(&mut self) -> Result<Request<'_, Req, Res>> {
        let request_read_limit = self.max_frame_body_bytes;
        let stream = self.stream.as_mut().ok_or(Error::ConnectionClosed)?;
        let result = read_frame(stream, request_read_limit, &self.observer).await;
        let body = match result {
            Ok(body) => body,
            Err(error) => {
                close_peer(&mut self.stream);
                return Err(error);
            }
        };
        Ok(Request {
            conn: self,
            body: Some(body),
        })
    }
}

/// A complete decoded request that borrows the socket its response is written to.
pub struct Request<'a, Req, Res> {
    conn: &'a mut ServerConnection<Req, Res>,
    body: Option<Req>,
}

impl<Req, Res> Request<'_, Req, Res>
where
    Res: bincode::Encode,
{
    // Encoding finishes before the first header byte, so an oversized value sends nothing.
    async fn respond_without_timeout(&mut self, response: Res) -> Result<()> {
        let result = async {
            let stream = self.conn.stream.as_mut().ok_or(Error::ConnectionClosed)?;
            let response_write_limit = self.conn.max_frame_body_bytes;
            let bytes = encode_frame(&response, response_write_limit, &self.conn.observer)?;
            write_frame(stream, &bytes, &self.conn.observer).await
        }
        .await;
        if result.is_err() {
            close_peer(&mut self.conn.stream);
        }
        result
    }

    /// Writes one complete bounded response within 90 seconds.
    ///
    /// # Errors
    /// Returns [`Error::BodyTooLarge`] locally (the peer then sees EOF, as the wire has no
    /// error envelope), another typed write error, or [`Error::RequestTimeout`]; each
    /// discards the socket.
    pub async fn respond(mut self, response: Res) -> Result<()> {
        match tokio::time::timeout(
            Duration::from_secs(90),
            self.respond_without_timeout(response),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                close_peer(&mut self.conn.stream);
                Err(Error::RequestTimeout)
            }
        }
    }

    /// Borrows the decoded request body until service dispatch takes it.
    ///
    /// # Panics
    /// Panics if the body was already taken by this module's service dispatch. Peer data cannot
    /// cause it: a `Request` exists only after a complete successful decode.
    pub fn body(&self) -> &Req {
        self.body.as_ref().unwrap()
    }

    // Service dispatch takes the decoded body once while keeping the response socket.
    fn take_body(&mut self) -> Req {
        self.body.take().expect("body was taken twice")
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, future::Future};

    use proptest::prelude::*;

    use crate::free_socket_addr;

    use super::*;

    fn fixture<
        Req: bincode::Encode + bincode::Decode + Send + 'static,
        Res: bincode::Encode + bincode::Decode + Send + 'static,
        A: Send + 'static,
        B: Send + 'static,
        X: Future<Output = Result<A, TestCaseError>> + Send,
        Y: Future<Output = Result<B, TestCaseError>> + Send,
    >(
        svr_fn: impl FnOnce(Server<Req, Res>) -> X + Send + 'static,
        con_fn: impl FnOnce(Connection<Req, Res>) -> Y + Send + 'static,
    ) -> (Result<A, TestCaseError>, Result<B, TestCaseError>) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let addr = free_socket_addr();
                let server = Server::bind(addr).await.unwrap();
                let connection = Connection::create(addr).await.unwrap();

                let svr_task = tokio::spawn(async move { svr_fn(server).await });
                let con_task = tokio::spawn(async move { con_fn(connection).await });

                let (svr_res, con_res) = tokio::join!(svr_task, con_task);
                (
                    svr_res.unwrap_or_else(|err| panic!("server failed: {err}")),
                    con_res.unwrap_or_else(|err| panic!("connection failed: {err}")),
                )
            })
    }

    #[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq)]
    struct Message {
        text: String,
        other: HashMap<String, f32>,
    }

    impl Arbitrary for Message {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: ()) -> Self::Strategy {
            (
                any::<String>(),
                prop::collection::hash_map(".*", 0.0f32..100.0f32, 0..10),
            )
                .prop_map(|(text, other)| Message { text, other })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn basic_arb(a1: Message, b1: Message) {
            let (a2, b2) = (a1.clone(), b1.clone());
            let (svr_res, con_res) = fixture(
                |svr| async move {
                    let mut conn = svr.accept().await?;
                    let req = conn.request().await?;
                    prop_assert_eq!(req.body(), &a1);
                    req.respond(b1).await?;
                    Ok(())
                },
                |mut con| async move {
                    let res = con.send(&a2).await?;
                    prop_assert_eq!(res, b2);
                    Ok(())
                },
            );
            svr_res?;
            con_res?;
        }
    }
}
