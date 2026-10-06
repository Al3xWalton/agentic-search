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

use std::{sync::Arc, time::Duration};

use tokio::net::ToSocketAddrs;

use crate::OneOrMany;

use super::Result;

/// A typed sonic service whose source-level body-byte cap governs both of its peers.
pub trait Service: Sized + Send + Sync + 'static {
    /// Encoded body-byte cap for this service's requests and responses, excluding the native
    /// header. Both peers derive it from source; `sonic_service!` sets it via its optional
    /// `max_frame_body_bytes = …` argument, otherwise it is the sonic default.
    const MAX_FRAME_BODY_BYTES: usize = super::DEFAULT_MAX_FRAME_BODY_BYTES;
    /// Request envelope; its variant order is the wire format.
    type Request: bincode::Encode + bincode::Decode + Send + Sync;
    /// Response envelope; its variant order is the wire format.
    type Response: bincode::Encode + bincode::Decode + Send + Sync;

    /// Dispatches a decoded request to its application handler.
    fn handle(
        req: Self::Request,
        server: &Self,
    ) -> impl std::future::Future<Output = Self::Response> + Send + '_;
}

/// An application message handled by one service.
pub trait Message<S: Service>: Send + Sync {
    /// Application response carried inside the service envelope.
    type Response: Send + Sync;
    /// Handles the decoded message and returns its application response.
    fn handle(self, server: &S) -> impl std::future::Future<Output = Self::Response>;
}
/// Maps an application message to and from its service envelope variants.
pub trait Wrapper<S: Service>: Message<S> {
    /// Wraps the message in its request variant.
    fn wrap_request(req: Self) -> S::Request;
    /// Extracts this message's response variant, or `None` for any other variant.
    fn unwrap_response(res: S::Response) -> Option<Self::Response>;
}

/// Service listener whose accepted peers each run, and fail, independently.
pub struct Server<S: Service> {
    inner: super::Server<OneOrMany<S::Request>, OneOrMany<S::Response>>,
    service: Arc<S>,
}

impl<S: Service> Server<S> {
    /// Binds a listener whose request reads and response writes use `S::MAX_FRAME_BODY_BYTES`.
    pub async fn bind(service: S, addr: impl ToSocketAddrs) -> Result<Self> {
        let server_frame_limit = S::MAX_FRAME_BODY_BYTES;
        Ok(Server {
            inner: super::Server::bind_with_limit(addr, server_frame_limit).await?,
            service: Arc::new(service),
        })
    }
    /// Accepts one peer and spawns its request loop; a framing failure ends only that loop.
    pub async fn accept(&self) -> Result<()> {
        let mut conn = self.inner.accept().await?;

        let service = Arc::clone(&self.service);
        tokio::spawn(async move {
            while let Ok(mut req) = conn.request().await {
                match req.take_body() {
                    OneOrMany::One(body) => {
                        let res = S::handle(body, &service).await;

                        if let Err(e) = req.respond(OneOrMany::One(res)).await {
                            tracing::error!("failed to respond to request: {}", e);
                        }
                    }
                    OneOrMany::Many(bodies) => {
                        let mut res = Vec::new();

                        for req in bodies {
                            res.push(S::handle(req, &service));
                        }

                        let res = futures::future::join_all(res).await;

                        if let Err(e) = req.respond(OneOrMany::Many(res)).await {
                            tracing::error!("failed to respond to request: {}", e);
                        }
                    }
                }
            }
        });

        Ok(())
    }
}

/// Service client whose single and batched exchanges use `S::MAX_FRAME_BODY_BYTES`.
pub struct Connection<S: Service> {
    await_res: bool,
    inner: super::Connection<OneOrMany<S::Request>, OneOrMany<S::Response>>,
}

impl<S: Service> Connection<S> {
    /// Connects with the service cap and the established 30-second connection deadline.
    pub async fn create(server: impl ToSocketAddrs) -> Result<Connection<S>> {
        Self::create_with_timeout(server, Duration::from_secs(30)).await
    }

    /// Connects with the service cap and the supplied connection deadline.
    pub async fn create_with_timeout(
        server: impl ToSocketAddrs,
        timeout: Duration,
    ) -> Result<Connection<S>> {
        let client_frame_limit = S::MAX_FRAME_BODY_BYTES;
        Ok(Connection {
            await_res: false,
            inner: super::Connection::create_with_timeout_and_limit(
                server,
                timeout,
                client_frame_limit,
            )
            .await?,
        })
    }

    /// Connects with the service cap on every retried attempt; see the raw retry constructor.
    pub async fn create_with_timeout_retry(
        server: impl ToSocketAddrs + Clone,
        timeout: Duration,
        retry: impl Iterator<Item = Duration>,
    ) -> Result<Connection<S>> {
        let retry_service_limit = S::MAX_FRAME_BODY_BYTES;
        Ok(Connection {
            await_res: false,
            inner: super::Connection::create_with_timeout_retry_and_limit(
                server,
                timeout,
                retry,
                retry_service_limit,
            )
            .await?,
        })
    }

    /// Sends one message with no deadline; a framing error discards the raw socket.
    /// A caller that cancels this future must discard the connection.
    pub async fn send_without_timeout<R: Wrapper<S>>(&mut self, request: R) -> Result<R::Response> {
        self.await_res = true;
        let res = Ok(R::unwrap_response(
            self.inner
                .send_without_timeout(&OneOrMany::One(R::wrap_request(request)))
                .await?
                .one()
                .expect("response is missing"),
        )
        .unwrap());
        self.await_res = false;
        res
    }

    /// Sends one message within the raw client's 90-second exchange deadline.
    pub async fn send<R: Wrapper<S>>(&mut self, request: R) -> Result<R::Response> {
        self.await_res = true;
        let res = Ok(R::unwrap_response(
            self.inner
                .send(&OneOrMany::One(R::wrap_request(request)))
                .await?
                .one()
                .expect("response is missing"),
        )
        .unwrap());
        self.await_res = false;
        res
    }

    /// Sends one message within `timeout`.
    pub async fn send_with_timeout<R: Wrapper<S>>(
        &mut self,
        request: R,
        timeout: Duration,
    ) -> Result<R::Response> {
        self.await_res = true;
        let res = Ok(R::unwrap_response(
            self.inner
                .send_with_timeout(&OneOrMany::One(R::wrap_request(request)), timeout)
                .await?
                .one()
                .expect("response is missing"),
        )
        .unwrap());
        self.await_res = false;
        res
    }

    /// Sends a batch in one frame; the cap applies to the whole batch envelope.
    pub async fn batch_send_with_timeout<R: Wrapper<S> + Clone>(
        &mut self,
        requests: &[R],
        timeout: Duration,
    ) -> Result<Vec<R::Response>> {
        self.await_res = true;
        let res = Ok(self
            .inner
            .send_with_timeout(
                &OneOrMany::Many(
                    requests
                        .iter()
                        .map(|req| R::wrap_request(req.clone()))
                        .collect::<Vec<_>>(),
                ),
                timeout,
            )
            .await?
            .many()
            .into_iter()
            .map(|res| R::unwrap_response(res).unwrap())
            .collect());
        self.await_res = false;
        res
    }

    /// Returns true when the raw socket was discarded, expired or fails its liveness probe.
    pub async fn is_closed(&mut self) -> bool {
        self.inner.is_closed().await
    }

    /// Returns true while an exchange is pending or after one failed.
    pub fn awaiting_response(&self) -> bool {
        self.await_res
    }
}

macro_rules! sonic_service {
    ($service:ident, [$($req:ident),*$(,)?]) => {
        $crate::distributed::sonic::service::sonic_service!(
            $service, [$($req),*],
            max_frame_body_bytes = $crate::distributed::sonic::DEFAULT_MAX_FRAME_BODY_BYTES
        );
    };
    (
        $service:ident,
        [$($req:ident),*$(,)?],
        max_frame_body_bytes = $max_frame_body_bytes:expr
    ) => {
        mod service_impl__ {
            #![allow(dead_code)]

            use super::{$service, $($req),*};

            use $crate::distributed::sonic;

            /// Request envelope whose variants keep the declared message order on the wire.
            #[derive(Clone, ::bincode::Encode, ::bincode::Decode)]
            pub enum Request {
                $($req(Box<$req>),)*
            }
            /// Response envelope whose variants mirror the request order on the wire.
            #[derive(::bincode::Encode, ::bincode::Decode)]
            pub enum Response {
                $($req(Box<<$req as sonic::service::Message<$service>>::Response>),)*
            }
            $(
                impl sonic::service::Wrapper<$service> for $req {
                    fn wrap_request(req: Self) -> Request {
                        Request::$req(Box::new(req))
                    }
                    fn unwrap_response(res: <$service as sonic::service::Service>::Response) -> Option<Self::Response> {
                        #[allow(irrefutable_let_patterns)]
                        if let Response::$req(value) = res {
                            Some(*value)
                        } else {
                            None
                        }
                    }
                }
            )*
            impl sonic::service::Service for $service {
                const MAX_FRAME_BODY_BYTES: usize = $max_frame_body_bytes;
                type Request = Request;
                type Response = Response;

                // NOTE: This is a workaround for the fact that async functions
                // don't have a Send bound by default, and there's currently no
                // way of specifying that.
                #[allow(clippy::manual_async_fn)]
                fn handle(req: Request, server: &Self) -> impl std::future::Future<Output = Self::Response> + Send + '_ {
                    async move {
                        match req {
                            $(
                                Request::$req(value) => Response::$req(Box::new(sonic::service::Message::handle(*value, server).await)),
                            )*
                        }
                    }
                }
            }
            impl $service {
                /// Binds this service with its declared request and response body-byte cap.
                pub async fn bind(self, addr: impl ::tokio::net::ToSocketAddrs) -> sonic::Result<sonic::service::Server<Self>> {
                    sonic::service::Server::bind(self, addr).await
                }
            }
        }
    };
}

pub(crate) use sonic_service;

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use std::{marker::PhantomData, net::SocketAddr, sync::atomic::AtomicI32};

    use crate::distributed::sonic::{service, ConnectionPool};

    use super::{Server, Service, Wrapper};
    use futures::Future;

    struct ConnectionBuilder<S> {
        addr: SocketAddr,
        marker: PhantomData<S>,
    }

    impl<S: Service> ConnectionBuilder<S> {
        async fn conn(&self) -> Result<super::Connection<S>, anyhow::Error> {
            Ok(super::Connection::create(self.addr).await?)
        }

        async fn send<R: Wrapper<S>>(&self, req: R) -> Result<R::Response, anyhow::Error> {
            Ok(self.conn().await?.send(req).await?)
        }

        fn addr(&self) -> SocketAddr {
            self.addr
        }
    }

    fn fixture<
        S: Service + Send + Sync + 'static,
        B: Send + Sync + 'static,
        Y: Future<Output = Result<B, TestCaseError>> + Send,
    >(
        service: S,
        con_fn: impl FnOnce(ConnectionBuilder<S>) -> Y + Send + 'static,
    ) -> Result<B, TestCaseError>
    where
        S::Request: Send + Sync + 'static,
        S::Response: Send + Sync + 'static,
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let server = Server::bind(service, ("127.0.0.1", 0)).await.unwrap();
                let addr = server.inner.listener.local_addr().unwrap();

                let svr_task: tokio::task::JoinHandle<Result<(), anyhow::Error>> =
                    tokio::spawn(async move {
                        loop {
                            server.accept().await?;
                        }
                    });
                let con_res = tokio::spawn(async move {
                    con_fn(ConnectionBuilder {
                        addr,
                        marker: PhantomData,
                    })
                    .await
                })
                .await;
                svr_task.abort();

                con_res.unwrap_or_else(|err| panic!("connection failed: {err}"))
            })
    }

    mod counter_service {
        use std::sync::atomic::AtomicI32;

        use super::super::Message;
        use proptest::prelude::*;

        pub struct CounterService {
            pub counter: AtomicI32,
        }

        sonic_service!(CounterService, [Change, Reset]);

        #[derive(
            Debug, Clone, serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode,
        )]
        pub struct Change {
            pub amount: i32,
        }

        impl Arbitrary for Change {
            type Parameters = ();
            type Strategy = BoxedStrategy<Self>;

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                (0..100).prop_map(|amount| Change { amount }).boxed()
            }
        }

        #[derive(
            Debug, Clone, serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode,
        )]
        pub struct Reset;

        impl Message<CounterService> for Change {
            type Response = i32;

            async fn handle(self, server: &CounterService) -> Self::Response {
                let prev = server
                    .counter
                    .fetch_add(self.amount, std::sync::atomic::Ordering::SeqCst);
                prev + self.amount
            }
        }

        impl Message<CounterService> for Reset {
            type Response = ();

            async fn handle(self, server: &CounterService) -> Self::Response {
                server.counter.store(0, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    use counter_service::*;

    #[test]
    fn simple_service() -> Result<(), TestCaseError> {
        fixture(
            CounterService {
                counter: AtomicI32::new(0),
            },
            |b| async move {
                let val = b
                    .send(Change { amount: 15 })
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                assert_eq!(val, 15);
                let val = b
                    .send(Change { amount: 15 })
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                assert_eq!(val, 30);
                b.send(Reset)
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                let val = b
                    .send(Change { amount: 15 })
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                assert_eq!(val, 15);
                Ok(())
            },
        )?;

        Ok(())
    }

    #[test]
    fn test_connection_reuse() {
        fixture(
            CounterService {
                counter: AtomicI32::new(0),
            },
            |b| async move {
                let mut conn = b.conn().await.unwrap();

                let val = conn
                    .send(Change { amount: 15 })
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                assert_eq!(val, 15);

                let val = conn
                    .send(Change { amount: 15 })
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                assert_eq!(val, 30);

                conn.send(Reset)
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;

                // send in a new connection
                let val = b
                    .send(Change { amount: 15 })
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                assert_eq!(val, 15);

                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn test_connection_pool() {
        fixture(
            CounterService {
                counter: AtomicI32::new(0),
            },
            |b| async move {
                let pool: ConnectionPool<service::Connection<CounterService>> =
                    ConnectionPool::new(b.addr()).unwrap();

                let val = pool
                    .get()
                    .await
                    .unwrap()
                    .send(Change { amount: 15 })
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                assert_eq!(val, 15);

                let val = pool
                    .get()
                    .await
                    .unwrap()
                    .send(Change { amount: 15 })
                    .await
                    .map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                assert_eq!(val, 30);

                Ok(())
            },
        )
        .unwrap();
    }

    proptest! {
        #[test]
        fn ref_serialization(a: Change) {
            fixture(CounterService { counter: AtomicI32::new(0) }, |conn| async move {
                conn.send(Reset).await.map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                let val = conn.send(a.clone()).await.map_err(|e| TestCaseError::Fail(e.to_string().into()))?;
                prop_assert_eq!(val, a.amount);
                Ok(())
            })?;
        }
    }
}
