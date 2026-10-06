// SPDX-License-Identifier: AGPL-3.0-only
//! Loopback witnesses exercise production frame readers, writers and policy handoffs.
//! Complete values and passive operation snapshots distinguish each expected error.
//! Synthetic bodies do not establish production traffic maxima or aggregate memory bounds.

use std::{future::Future, io::ErrorKind, net::SocketAddr, time::Duration};

use bincode::{Decode, Encode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use super::{framing::Event, framing::FrameObserver, *};

const DEADLINE: Duration = Duration::from_secs(5);

// Fixture deadlines are distinct from framing observations.
async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("HARNESS_DEADLINE")
}

// The reserved range belongs only to the serial legacy_retirement_contract and ci-all runs.
async fn listener() -> (TcpListener, SocketAddr) {
    for _ in 0..16 {
        let listener = bounded(TcpListener::bind("127.0.0.1:0"))
            .await
            .expect("HARNESS_BIND");
        let addr = listener.local_addr().expect("HARNESS_ADDRESS");
        if !(57300..=57320).contains(&addr.port()) {
            return (listener, addr);
        }
    }
    panic!("HARNESS_PORT_ATTEMPTS");
}

// Only the reserve/drop/production-bind race permits a retry.
async fn server<Req: Decode, Res>(limit: Option<usize>) -> (Server<Req, Res>, SocketAddr) {
    for _ in 0..16 {
        let reservation = bounded(TcpListener::bind("127.0.0.1:0"))
            .await
            .expect("HARNESS_RESERVE");
        let addr = reservation.local_addr().expect("HARNESS_ADDRESS");
        if (57300..=57320).contains(&addr.port()) {
            continue;
        }
        drop(reservation);
        let result = match limit {
            Some(limit) => bounded(Server::bind_with_limit(addr, limit)).await,
            None => bounded(Server::bind(addr)).await,
        };
        match result {
            Ok(server) => return (server, addr),
            Err(Error::IO(error)) if error.kind() == ErrorKind::AddrInUse => {}
            Err(_) => panic!("HARNESS_SERVER_BIND"),
        }
    }
    panic!("HARNESS_PORT_ATTEMPTS");
}

// A deadline becomes a distinct observation, so the caller can reap its tasks before asserting.
async fn within<T>(future: impl Future<Output = Result<T, Error>>) -> Result<T, Seen> {
    match tokio::time::timeout(DEADLINE, future).await {
        Ok(result) => result.map_err(seen),
        Err(_) => Err(Seen::Timeout),
    }
}

// Aborts and drains a fixture task so a failing assertion leaves no task running behind it.
async fn reap<T>(task: &mut JoinHandle<T>) {
    task.abort();
    let _ = task.await;
}

// A timed-out task is aborted and joined before reporting a fixture failure.
async fn joined<T>(mut task: JoinHandle<T>) -> Result<T, tokio::task::JoinError> {
    match tokio::time::timeout(DEADLINE, &mut task).await {
        Ok(result) => result,
        Err(_) => {
            task.abort();
            let _ = task.await;
            panic!("HARNESS_TASK_DEADLINE");
        }
    }
}

// Independent wire construction also checks the exact encoded request bytes.
fn wire<T: Encode>(value: &T) -> Vec<u8> {
    let body = bincode::encode_to_vec(value, common::bincode_config()).expect("HARNESS_ENCODE");
    frame(&body)
}

// A declared length can differ from the supplied body in refusal cases.
fn frame(body: &[u8]) -> Vec<u8> {
    let mut bytes = body.len().to_ne_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

// Controlled peers read only the small complete frames emitted by each fixture.
async fn read_wire(peer: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; std::mem::size_of::<usize>()];
    bounded(peer.read_exact(&mut header))
        .await
        .expect("HARNESS_HEADER");
    let size = usize::from_ne_bytes(header);
    assert!(size <= 64 * 1024 * 1024, "HARNESS_FRAME_SIZE");
    let mut body = vec![0; size];
    bounded(peer.read_exact(&mut body))
        .await
        .expect("HARNESS_BODY");
    [header.as_slice(), body.as_slice()].concat()
}

// Error fields remain comparable without formatting frame-derived bincode detail.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Cap(usize, usize),
    Integer(bincode::error::IntegerType, bincode::error::IntegerType),
    Budget,
    DecodeEnd(usize),
    OtherDecode,
    Trailing(usize, usize),
    Io(ErrorKind),
    Closed,
    Encode,
    OtherEncode,
    Allocation,
    Timeout,
    Other,
}

// Each expected error keeps its typed fields; unrelated errors stay distinct.
fn seen(error: Error) -> Seen {
    use bincode::error::DecodeError;
    match error {
        Error::BodyTooLarge {
            body_size,
            max_size,
        } => Seen::Cap(body_size, max_size),
        Error::Decode(DecodeError::InvalidIntegerType { expected, found }) => {
            Seen::Integer(expected, found)
        }
        Error::Decode(DecodeError::LimitExceeded) => Seen::Budget,
        Error::Decode(DecodeError::UnexpectedEnd { additional }) => Seen::DecodeEnd(additional),
        Error::Decode(_) => Seen::OtherDecode,
        Error::TrailingBytes {
            consumed,
            body_size,
        } => Seen::Trailing(consumed, body_size),
        Error::IO(error) => Seen::Io(error.kind()),
        Error::ConnectionClosed => Seen::Closed,
        Error::Encode(bincode::error::EncodeError::Other("synthetic encode failure")) => {
            Seen::Encode
        }
        Error::Encode(_) => Seen::OtherEncode,
        Error::Allocation(_) => Seen::Allocation,
        Error::RequestTimeout => Seen::Timeout,
        _ => Seen::Other,
    }
}

// Native u32 decoding of the reserved tag has two independently fixed fields.
fn invalid_integer() -> Seen {
    use bincode::error::IntegerType::{Reserved, U32};
    Seen::Integer(U32, Reserved)
}

// EOF/reset/broken-pipe alone indicate peer closure; other errors are preserved.
#[derive(Debug, PartialEq, Eq)]
enum Closure {
    PeerClosed,
    Byte(u8),
    Other(ErrorKind),
}

// A retained local owner must close the socket without help from peer EOF.
async fn closure(peer: &mut TcpStream) -> Closure {
    let mut byte = [0];
    match bounded(peer.read(&mut byte)).await {
        Ok(0) => Closure::PeerClosed,
        Ok(_) => Closure::Byte(byte[0]),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ) =>
        {
            Closure::PeerClosed
        }
        Err(error) => Closure::Other(error.kind()),
    }
}

// Both directions use the same controlled body and expected observations.
#[derive(Clone, Copy)]
enum Side {
    Server,
    Client(u8),
}

// Retain the actual socket owner past a failure and its named assertion.
enum Owner<T> {
    Server(ServerConnection<T, u32>),
    Client(Connection<u32, T>),
}

impl<T: Decode> Owner<T> {
    // Ownership is checked before waiting on peer EOF.
    fn open(&self) -> bool {
        match self {
            Self::Server(conn) => conn.stream.is_some(),
            Self::Client(conn) => conn.stream.is_some(),
        }
    }

    // A repeated operation must return ConnectionClosed without new frame work.
    async fn again(&mut self) -> Result<T, Seen> {
        match self {
            Self::Server(conn) => conn
                .request()
                .await
                .map(|mut req| req.take_body())
                .map_err(seen),
            Self::Client(conn) => conn.send(&7).await.map_err(seen),
        }
    }
}

// A panic remains data until the parent's named assertion checks it.
#[derive(PartialEq)]
enum Returned<T> {
    Normal(Result<T, Seen>),
    TaskPanicked,
    TaskCancelled,
}

// Complete observations include ownership and the real operation sequence.
#[derive(PartialEq)]
struct Observation<T> {
    returned: Returned<T>,
    open: bool,
    events: Vec<Event>,
}

// The handle and observer travel together so staged failures can reap the task first.
struct Reading<T> {
    task: JoinHandle<(Owner<T>, Result<T, Seen>)>,
    observer: FrameObserver,
    prefix: usize,
}

impl<T: Decode> Reading<T> {
    // Compare body operations separately from the client's already-captured request writes.
    fn events(&self) -> Vec<Event> {
        self.observer.snapshot()[self.prefix..].to_vec()
    }

    // Inspect the next operation, not a loop waiting for a preferred expected value.
    // Relies on the current-thread runtime of `#[tokio::test]`: the reader task records every
    // event of one poll before it yields, so a wake never observes a half-recorded stage.
    async fn stage(&mut self, previous: usize, expected: &[Event], marker: &str) {
        let _ = bounded(self.observer.after(self.prefix + previous)).await;
        let actual = self.events();
        if actual != expected {
            self.task.abort();
            let _ = (&mut self.task).await;
        }
        assert!(actual == expected, "{marker}");
    }

    // Joining precedes assertions, including when decode returns a task panic.
    async fn finish(self) -> (Observation<T>, Option<Owner<T>>) {
        let outcome = joined(self.task).await;
        let events = self.observer.snapshot()[self.prefix..].to_vec();
        let (returned, owner) = match outcome {
            Ok((owner, result)) => (Returned::Normal(result), Some(owner)),
            Err(error) if error.is_panic() => (Returned::TaskPanicked, None),
            Err(_) => (Returned::TaskCancelled, None),
        };
        let open = owner.as_ref().is_some_and(Owner::open);
        (
            Observation {
                returned,
                open,
                events,
            },
            owner,
        )
    }
}

// Construction and reads enter public sonic APIs for both peers and all send wrappers.
async fn receiver<T: Decode + Send + 'static>(
    side: Side,
    limit: Option<usize>,
) -> (TcpStream, Reading<T>) {
    match side {
        Side::Server => {
            let (server, addr) = server::<T, u32>(limit).await;
            let peer = bounded(TcpStream::connect(addr))
                .await
                .expect("HARNESS_CONNECT");
            let mut conn = bounded(server.accept())
                .await
                .unwrap_or_else(|_| panic!("HARNESS_ACCEPT"));
            let observer = conn.observer.clone();
            let task = tokio::spawn(async move {
                let result = conn
                    .request()
                    .await
                    .map(|mut req| req.take_body())
                    .map_err(seen);
                (Owner::Server(conn), result)
            });
            (
                peer,
                Reading {
                    task,
                    observer,
                    prefix: 0,
                },
            )
        }
        Side::Client(mode) => {
            let (listener, addr) = listener().await;
            let mut conn = match limit {
                Some(limit) => {
                    Connection::create_with_timeout_and_limit(addr, DEADLINE, limit).await
                }
                None => Connection::connect(addr).await,
            }
            .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
            let (mut peer, _) = bounded(listener.accept()).await.expect("HARNESS_ACCEPT");
            let observer = conn.observer.clone();
            let task = tokio::spawn(async move {
                let result = match mode {
                    0 => conn.send(&7).await,
                    1 => conn.send_with_timeout(&7, DEADLINE).await,
                    _ => conn.send_without_timeout(&7).await,
                }
                .map_err(seen);
                (Owner::Client(conn), result)
            });
            assert!(
                read_wire(&mut peer).await == wire(&7u32),
                "HARNESS_REQUEST_BYTES"
            );
            let prefix = observer.snapshot().len();
            (
                peer,
                Reading {
                    task,
                    observer,
                    prefix,
                },
            )
        }
    }
}

// Cap failures compare all pre-read events and retained ownership before peer closure.
async fn cap_case<T: Decode + Send + PartialEq + 'static>(
    side: Side,
    limit: Option<usize>,
    declared: usize,
    body: &[u8],
    half_close: bool,
    marker: &str,
) {
    let (mut peer, reading) = receiver::<T>(side, limit).await;
    bounded(peer.write_all(&declared.to_ne_bytes()))
        .await
        .expect("HARNESS_HEADER");
    bounded(peer.write_all(body)).await.expect("HARNESS_BODY");
    if half_close {
        bounded(peer.shutdown()).await.expect("HARNESS_SHUTDOWN");
    }
    let maximum = limit.unwrap_or(67_108_864);
    let (actual, _owner) = reading.finish().await;
    let expected = Observation {
        returned: Returned::Normal(Err(Seen::Cap(declared, maximum))),
        open: false,
        events: vec![Event::Header(declared, maximum)],
    };
    assert!(actual == expected, "{marker}");
    assert!(closure(&mut peer).await == Closure::PeerClosed, "{marker}");
}

// Accepted small frames prove the same observer records read and reservation work.
async fn array_control<const N: usize>(side: Side, marker: &str) {
    let (mut peer, reading) = receiver::<[u8; N]>(side, Some(32)).await;
    bounded(peer.write_all(&frame(&[7; N])))
        .await
        .expect("HARNESS_BODY");
    let (actual, _owner) = reading.finish().await;
    assert!(
        actual
            == Observation {
                returned: Returned::Normal(Ok([7; N])),
                open: true,
                events: vec![
                    Event::Header(N, 32),
                    Event::ReadOffer(N, 0, 0),
                    Event::ReadReturn(N),
                    Event::Reserve(N, N),
                    Event::Decode(N)
                ],
            },
        "{marker}"
    );
}

// The default expectation is fixed independently of the production constant.
async fn caps(side: Side, marker: &str) {
    array_control::<31>(side, marker).await;
    array_control::<32>(side, marker).await;
    cap_case::<u32>(side, None, 67_108_865, &[7], true, marker).await;
    cap_case::<u32>(side, None, usize::MAX, &[7], true, marker).await;
    cap_case::<u32>(side, Some(32), 33, &[7], true, marker).await;
    cap_case::<[u8; 33]>(side, Some(32), 33, &[7; 33], false, marker).await;
}

#[tokio::test]
async fn w01_server_cap() {
    caps(Side::Server, "W01_CAP").await;
}

#[tokio::test]
async fn w02_client_cap() {
    for mode in 0..3 {
        caps(Side::Client(mode), "W02_CAP").await;
    }
}

// Staged writes make each reservation's requested target independently observable.
async fn staged<const N: usize>(side: Side, finish: bool, marker: &str) {
    let (mut peer, mut reading) = receiver::<[u8; N]>(side, Some(32)).await;
    bounded(peer.write_all(&N.to_ne_bytes()))
        .await
        .expect("HARNESS_HEADER");
    let mut events = vec![Event::Header(N, 32), Event::ReadOffer(N, 0, 0)];
    reading.stage(0, &events, marker).await;
    let bytes = [7, 9, 11];
    let count = if finish { N } else { 1 };
    for (index, byte) in bytes.iter().copied().enumerate().take(count) {
        let previous = events.len();
        bounded(peer.write_all(&[byte]))
            .await
            .expect("HARNESS_BODY");
        events.extend([Event::ReadReturn(1), Event::Reserve(1, index + 1)]);
        if index + 1 < N {
            events.push(Event::ReadOffer(N - index - 1, index + 1, index + 1));
            reading.stage(previous, &events, marker).await;
        }
    }
    let returned = if finish {
        events.push(Event::Decode(N));
        let value: [u8; N] = bytes[..N].try_into().expect("HARNESS_ARRAY");
        Returned::Normal(Ok(value))
    } else {
        bounded(peer.shutdown()).await.expect("HARNESS_SHUTDOWN");
        events.push(Event::ReadReturn(0));
        Returned::Normal(Err(Seen::Io(ErrorKind::UnexpectedEof)))
    };
    let (actual, _owner) = reading.finish().await;
    assert!(
        actual
            == Observation {
                returned,
                open: finish,
                events
            },
        "{marker}"
    );
    if !finish {
        assert!(closure(&mut peer).await == Closure::PeerClosed, "{marker}");
    }
}

// An absent large body must still offer only fixed scratch storage with no reservation.
async fn absent_chunk(side: Side) {
    let (mut peer, mut reading) = receiver::<Vec<u8>>(side, None).await;
    bounded(peer.write_all(&16_385usize.to_ne_bytes()))
        .await
        .expect("HARNESS_HEADER");
    let mut events = vec![
        Event::Header(16_385, 67_108_864),
        Event::ReadOffer(16_384, 0, 0),
    ];
    reading.stage(0, &events, "W03_BOUND").await;
    bounded(peer.shutdown()).await.expect("HARNESS_SHUTDOWN");
    events.push(Event::ReadReturn(0));
    let (actual, _owner) = reading.finish().await;
    assert!(
        actual
            == Observation {
                returned: Returned::Normal(Err(Seen::Io(ErrorKind::UnexpectedEof))),
                open: false,
                events,
            },
        "W03_BOUND"
    );
    assert!(closure(&mut peer).await == Closure::PeerClosed, "W03_BOUND");
}

// Whole-value round trips exercise both writers and readers on a reusable connection.
async fn roundtrip<T>(values: Vec<T>, limit: usize, marker: &str)
where
    T: Encode + Decode + Clone + PartialEq + Send + Sync + 'static,
{
    let (server, addr) = server::<T, T>(Some(limit)).await;
    let mut client = Connection::create_with_timeout_and_limit(addr, DEADLINE, limit)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let expected = values.clone();
    let count = values.len();
    let task = tokio::spawn(async move {
        let mut conn = server.accept().await?;
        let mut requests = Vec::new();
        for _ in 0..count {
            let req = conn.request().await?;
            let value = req.body().clone();
            requests.push(value.clone());
            req.respond(value).await?;
        }
        Ok::<_, Error>(requests)
    });
    let mut responses = Vec::new();
    for value in &values {
        responses.push(bounded(client.send(value)).await.map_err(seen));
    }
    let received = joined(task).await;
    assert!(
        matches!(received, Ok(Ok(ref requests)) if requests == &expected)
            && responses == expected.into_iter().map(Ok).collect::<Vec<_>>()
            && !client.awaiting_response()
            && client.stream.is_some(),
        "{marker}"
    );
}

#[tokio::test]
async fn w03_incremental_reads() {
    for side in [Side::Server, Side::Client(0)] {
        staged::<2>(side, false, "W03_BOUND").await;
        staged::<2>(side, true, "W03_BOUND").await;
        absent_chunk(side).await;
    }
    for side in [Side::Server, Side::Client(0)] {
        staged::<3>(side, true, "W03_GROWTH").await;
    }
    roundtrip(
        vec![vec![7u8; 32_771], vec![9u8; 16_391]],
        65_536,
        "W03_BOUND",
    )
    .await;
}

// Invalid and trailing bodies use an open peer write half to prove local closure.
async fn decode_case<T: Decode + Send + PartialEq + 'static>(
    side: Side,
    body: &[u8],
    expected: Seen,
    marker: &str,
) {
    let (mut peer, reading) = receiver::<T>(side, Some(32)).await;
    bounded(peer.write_all(&frame(body)))
        .await
        .expect("HARNESS_BODY");
    let size = body.len();
    let (actual, _owner) = reading.finish().await;
    assert!(
        actual
            == Observation {
                returned: Returned::Normal(Err(expected)),
                open: false,
                events: vec![
                    Event::Header(size, 32),
                    Event::ReadOffer(size, 0, 0),
                    Event::ReadReturn(size),
                    Event::Reserve(size, size),
                    Event::Decode(size)
                ],
            },
        "{marker}"
    );
    assert!(closure(&mut peer).await == Closure::PeerClosed, "{marker}");
}

#[tokio::test]
async fn w04_decode_errors() {
    roundtrip(vec![7u32, 9], 32, "W04_DECODE").await;
    for side in [Side::Server, Side::Client(0)] {
        decode_case::<u32>(side, &[0xff], invalid_integer(), "W04_DECODE").await;
    }
    for side in [Side::Server, Side::Client(0)] {
        decode_case::<u32>(side, &[7, 0], Seen::Trailing(1, 2), "W04_TRAILING").await;
        decode_case::<u32>(side, &[251], Seen::DecodeEnd(2), "W04_DECODE").await;
    }
}

type BadTask = JoinHandle<(ServerConnection<u32, u32>, Result<u32, Seen>)>;
type HealthyTask = JoinHandle<Result<(ServerConnection<u32, u32>, Vec<(u32, u32)>), Error>>;

// Every task W05 spawns, so each failure path can abort and drain all of them before reporting.
#[derive(Default)]
struct W05Tasks {
    bad: Option<BadTask>,
    healthy: Option<HealthyTask>,
    third: Option<JoinHandle<Result<u32, Error>>>,
}

impl W05Tasks {
    // Aborts and drains whatever is still owned; joined tasks were already taken out.
    async fn reap(&mut self) {
        if let Some(task) = self.bad.as_mut() {
            reap(task).await;
        }
        if let Some(task) = self.healthy.as_mut() {
            reap(task).await;
        }
        if let Some(task) = self.third.as_mut() {
            reap(task).await;
        }
        *self = Self::default();
    }

    // A failed check reaps every task first, then reports the named or harness marker.
    async fn check(&mut self, ok: bool, marker: &str) {
        if !ok {
            self.reap().await;
        }
        assert!(ok, "{marker}");
    }
}

// Joins one owned task under the harness deadline; a missed deadline is returned, not raised.
async fn settle<T>(slot: &mut Option<JoinHandle<T>>) -> Option<Result<T, tokio::task::JoinError>> {
    let mut task = slot.take()?;
    match tokio::time::timeout(DEADLINE, &mut task).await {
        Ok(result) => Some(result),
        Err(_) => {
            reap(&mut task).await;
            None
        }
    }
}

// Peer closure under the harness deadline; `None` is a fixture failure, never a closure verdict.
async fn closure_within(peer: &mut TcpStream) -> Option<Closure> {
    let mut byte = [0];
    let read = tokio::time::timeout(DEADLINE, peer.read(&mut byte))
        .await
        .ok()?;
    Some(match read {
        Ok(0) => Closure::PeerClosed,
        Ok(_) => Closure::Byte(byte[0]),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ) =>
        {
            Closure::PeerClosed
        }
        Err(error) => Closure::Other(error.kind()),
    })
}

// An overlapping healthy connection and the original listener survive a failed peer.
#[tokio::test]
async fn w05_concurrent_isolation() {
    let (server, addr) = server::<u32, u32>(Some(32)).await;
    let mut peer_a = bounded(TcpStream::connect(addr))
        .await
        .expect("HARNESS_CONNECT");
    let mut conn_a = bounded(server.accept())
        .await
        .unwrap_or_else(|_| panic!("HARNESS_ACCEPT"));
    let mut client_b = Connection::<u32, u32>::connect(addr)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let mut conn_b = bounded(server.accept())
        .await
        .unwrap_or_else(|_| panic!("HARNESS_ACCEPT"));
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let mut tasks = W05Tasks {
        bad: Some(tokio::spawn(async move {
            let _ = released.await;
            let outcome = conn_a.request().await.map(|req| *req.body()).map_err(seen);
            (conn_a, outcome)
        })),
        healthy: Some(tokio::spawn(async move {
            let mut transcript = Vec::new();
            for _ in 0..2 {
                let req = conn_b.request().await?;
                let value = *req.body();
                req.respond(value * 10).await?;
                transcript.push((value, value * 10));
            }
            Ok::<_, Error>((conn_b, transcript))
        })),
        third: None,
    };
    let first = within(client_b.send(&7)).await;
    let sent = release.send(()).is_ok()
        && tokio::time::timeout(DEADLINE, peer_a.write_all(&frame(&[0xff])))
            .await
            .is_ok_and(|written| written.is_ok());
    tasks.check(sent, "HARNESS_BODY").await;
    let bad = settle(&mut tasks.bad).await;
    let closed = closure_within(&mut peer_a).await;
    tasks
        .check(bad.is_some() && closed.is_some(), "HARNESS_DEADLINE")
        .await;
    let isolated = matches!(&bad, Some(Ok((conn, Err(error))))
        if conn.stream.is_none() && error == &invalid_integer())
        && closed == Some(Closure::PeerClosed);
    tasks.check(isolated, "W05_ISOLATION").await;
    let second = within(client_b.send(&9)).await;
    let healthy = settle(&mut tasks.healthy).await;
    let mut client_c = Connection::<u32, u32>::connect(addr)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let mut conn_c = bounded(server.accept())
        .await
        .unwrap_or_else(|_| panic!("HARNESS_ACCEPT"));
    tasks.third = Some(tokio::spawn(async move {
        let req = conn_c.request().await?;
        let value = *req.body();
        req.respond(110).await?;
        Ok::<_, Error>(value)
    }));
    let third = within(client_c.send(&11)).await;
    let third_task = settle(&mut tasks.third).await;
    let reusable = !client_b.awaiting_response() && !client_b.is_closed().await;
    tasks
        .check(
            first == Ok(70)
                && second == Ok(90)
                && third == Ok(110)
                && matches!(healthy, Some(Ok(Ok((conn, values))))
                if conn.stream.is_some() && values == vec![(7, 70), (9, 90)])
                && matches!(third_task, Some(Ok(Ok(11))))
                && reusable,
            "W05_ISOLATION",
        )
        .await;
}

// Second operations are checked only after the retained socket has been inspected.
async fn discard_case(side: Side, bytes: &[u8], half_close: bool, error: Seen, events: Vec<Event>) {
    let (mut peer, reading) = receiver::<u32>(side, Some(32)).await;
    let observer = reading.observer.clone();
    bounded(peer.write_all(bytes)).await.expect("HARNESS_BODY");
    if half_close {
        bounded(peer.shutdown()).await.expect("HARNESS_SHUTDOWN");
    }
    let (actual, owner) = reading.finish().await;
    assert!(
        actual
            == Observation {
                returned: Returned::Normal(Err(error)),
                open: false,
                events,
            },
        "W06_CLOSED"
    );
    let mut owner = owner.expect("HARNESS_OWNER");
    let before = observer.snapshot();
    let second = bounded(owner.again()).await;
    assert!(
        second == Err(Seen::Closed) && !owner.open() && observer.snapshot() == before,
        "W06_CLOSED"
    );
    assert!(
        closure(&mut peer).await == Closure::PeerClosed,
        "W06_CLOSED"
    );
}

// Real pool recycling must replace a failed connection and reuse a healthy one.
async fn pool_case() {
    use futures::FutureExt;
    let (listener, addr) = listener().await;
    let task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("HARNESS_ACCEPT");
        let first_request = read_wire(&mut first).await;
        first
            .write_all(&frame(&[0xff]))
            .await
            .expect("HARNESS_BODY");
        let first_closed = closure(&mut first).await;
        let (mut second, _) = listener.accept().await.expect("HARNESS_ACCEPT");
        let mut transcript = vec![(1, first_request, frame(&[0xff]))];
        for response in [70u32, 90] {
            let request = read_wire(&mut second).await;
            let response = wire(&response);
            second.write_all(&response).await.expect("HARNESS_BODY");
            transcript.push((2, request, response));
        }
        let third_accept = listener.accept().now_or_never().is_some();
        (first_closed, transcript, third_accept)
    });
    let pool = ConnectionPool::<Connection<u32, u32>>::new(addr).expect("HARNESS_POOL");
    let mut failed = bounded(pool.get()).await.expect("HARNESS_CHECKOUT");
    let failure = bounded(failed.send(&7)).await.map_err(seen);
    let discarded = failed.stream.is_none() && failed.awaiting_response();
    drop(failed);
    let mut second = bounded(pool.get()).await.expect("HARNESS_CHECKOUT");
    let a = bounded(second.send(&7)).await.map_err(seen);
    drop(second);
    let mut third = bounded(pool.get()).await.expect("HARNESS_CHECKOUT");
    let b = bounded(third.send(&9)).await.map_err(seen);
    let transcript = joined(task).await;
    assert!(
        failure == Err(invalid_integer())
            && discarded
            && a == Ok(70)
            && b == Ok(90)
            && matches!(transcript, Ok((Closure::PeerClosed, ref values, false)) if values == &vec![
                (1, wire(&7u32), frame(&[0xff])),
                (2, wire(&7u32), wire(&70u32)), (2, wire(&9u32), wire(&90u32)),
            ]),
        "W06_CLOSED"
    );
}

#[tokio::test]
async fn w06_discard_and_pool() {
    roundtrip(vec![7u32, 9], 32, "W06_CLOSED").await;
    for side in [Side::Server, Side::Client(0)] {
        discard_case(
            side,
            &frame(&[0xff]),
            false,
            invalid_integer(),
            vec![
                Event::Header(1, 32),
                Event::ReadOffer(1, 0, 0),
                Event::ReadReturn(1),
                Event::Reserve(1, 1),
                Event::Decode(1),
            ],
        )
        .await;
        discard_case(
            side,
            &33usize.to_ne_bytes(),
            false,
            Seen::Cap(33, 32),
            vec![Event::Header(33, 32)],
        )
        .await;
        discard_case(side, &[1], true, Seen::Io(ErrorKind::UnexpectedEof), vec![]).await;
        let bytes = [2usize.to_ne_bytes().as_slice(), &[7]].concat();
        discard_case(
            side,
            &bytes,
            true,
            Seen::Io(ErrorKind::UnexpectedEof),
            vec![
                Event::Header(2, 32),
                Event::ReadOffer(2, 0, 0),
                Event::ReadReturn(1),
                Event::Reserve(1, 1),
                Event::ReadOffer(1, 1, 1),
                Event::ReadReturn(0),
            ],
        )
        .await;
    }
    pool_case().await;
}

// The encoder has a bounded successful control and an ordinary typed error.
struct SyntheticEncode(bool);

impl Encode for SyntheticEncode {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        if self.0 {
            Err(bincode::error::EncodeError::Other(
                "synthetic encode failure",
            ))
        } else {
            7u32.encode(encoder)
        }
    }
}

// The peer accepts either EOF or the complete small frame, so a lost cap cannot stall it.
async fn optional_frame(peer: &mut TcpStream) -> Vec<u8> {
    let mut first = [0];
    match bounded(peer.read(&mut first)).await {
        Ok(0) => Vec::new(),
        Ok(_) => {
            let mut header = [0; std::mem::size_of::<usize>()];
            header[0] = first[0];
            bounded(peer.read_exact(&mut header[1..]))
                .await
                .expect("HARNESS_HEADER");
            let size = usize::from_ne_bytes(header);
            assert!(size < 1024, "HARNESS_FRAME_SIZE");
            let mut bytes = vec![0; size];
            bounded(peer.read_exact(&mut bytes))
                .await
                .expect("HARNESS_BODY");
            [header.as_slice(), bytes.as_slice()].concat()
        }
        Err(error) if error.kind() == ErrorKind::ConnectionReset => Vec::new(),
        Err(_) => panic!("HARNESS_READ"),
    }
}

// Join and ownership are asserted before reading EOF so a missing close fails causally.
async fn request_write<T: Encode + Send + Sync + 'static>(value: T, expected: Seen, marker: &str) {
    let (listener, addr) = listener().await;
    let mut conn = Connection::<T, u32>::create_with_timeout_and_limit(addr, DEADLINE, 32)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let (mut peer, _) = bounded(listener.accept()).await.expect("HARNESS_ACCEPT");
    let observer = conn.observer.clone();
    let task = tokio::spawn(async move {
        let result = conn.send(&value).await.map_err(seen);
        (conn, result)
    });
    let wire_task = tokio::spawn(async move {
        let bytes = optional_frame(&mut peer).await;
        if !bytes.is_empty() {
            bounded(peer.write_all(&wire(&9u32)))
                .await
                .expect("HARNESS_RESPONSE");
        }
        bytes
    });
    let result = joined(task).await;
    let bytes = joined(wire_task).await;
    assert!(
        matches!(result, Ok((ref conn, Err(ref error)))
        if conn.stream.is_none() && conn.awaiting_response() && error == &expected)
            && matches!(bytes, Ok(ref bytes) if bytes.is_empty())
            && observer.snapshot().is_empty(),
        "{marker}"
    );
}

// Response encoding errors are local; the peer receives no frame bytes or error envelope.
async fn response_write() {
    let (server, addr) = server::<u32, [u8; 33]>(Some(32)).await;
    let mut peer = bounded(TcpStream::connect(addr))
        .await
        .expect("HARNESS_CONNECT");
    bounded(peer.write_all(&wire(&7u32)))
        .await
        .expect("HARNESS_REQUEST");
    let mut conn = bounded(server.accept())
        .await
        .unwrap_or_else(|_| panic!("HARNESS_ACCEPT"));
    let observer = conn.observer.clone();
    let task = tokio::spawn(async move {
        let request = conn.request().await?;
        let value = *request.body();
        let result = request.respond([7; 33]).await.map_err(seen);
        Ok::<_, Error>((conn, value, result))
    });
    let result = joined(task).await;
    assert!(
        matches!(result, Ok(Ok((ref conn, 7, Err(Seen::Cap(33, 32)))))
        if conn.stream.is_none())
            && observer.snapshot()
                == vec![
                    Event::Header(1, 32),
                    Event::ReadOffer(1, 0, 0),
                    Event::ReadReturn(1),
                    Event::Reserve(1, 1),
                    Event::Decode(1),
                ],
        "W08_RESPONSE_WRITE"
    );
    assert!(
        optional_frame(&mut peer).await.is_empty(),
        "W08_RESPONSE_WRITE"
    );
}

// Successful custom encoding shares the exact standard u32 representation.
async fn encode_control() {
    let (listener, addr) = listener().await;
    let mut conn =
        Connection::<SyntheticEncode, u32>::create_with_timeout_and_limit(addr, DEADLINE, 32)
            .await
            .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let task = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.expect("HARNESS_ACCEPT");
        let request = read_wire(&mut peer).await;
        peer.write_all(&wire(&9u32))
            .await
            .expect("HARNESS_RESPONSE");
        request
    });
    let result = bounded(conn.send(&SyntheticEncode(false)))
        .await
        .map_err(seen);
    let request = joined(task).await;
    assert!(
        result == Ok(9) && matches!(request, Ok(ref bytes) if bytes == &wire(&7u32)),
        "W08_ENCODE"
    );
}

#[tokio::test]
async fn w08_outgoing_limits() {
    encode_control().await;
    request_write(SyntheticEncode(true), Seen::Encode, "W08_ENCODE").await;
    roundtrip(vec![[7u8; 32], [9; 32]], 32, "W08_REQUEST_WRITE").await;
    request_write([7u8; 33], Seen::Cap(33, 32), "W08_REQUEST_WRITE").await;
    response_write().await;
    let mut body = vec![7];
    let observer = FrameObserver::default();
    let overflow = framing::reserve_bounded(&mut body, usize::MAX, usize::MAX, &observer);
    assert!(
        matches!(
            overflow,
            Err(Error::Encode(bincode::error::EncodeError::Other(
                "sonic encoded length overflow"
            )))
        ) && body == [7]
            && observer.snapshot().is_empty(),
        "W08_ENCODE"
    );
}

// Claim-only decoding makes the budget mutation finite without container allocation.
#[derive(PartialEq)]
struct Claim(u8);

impl Decode for Claim {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let tag = u8::decode(decoder)?;
        decoder.claim_bytes_read(if tag == 0 { 1 } else { 268_435_457 })?;
        Ok(Self(tag))
    }
}

#[tokio::test]
async fn w09_decode_budget() {
    for side in [Side::Server, Side::Client(0)] {
        let (mut peer, reading) = receiver::<Claim>(side, Some(32)).await;
        bounded(peer.write_all(&frame(&[0])))
            .await
            .expect("HARNESS_BODY");
        let (actual, _owner) = reading.finish().await;
        assert!(
            actual
                == Observation {
                    returned: Returned::Normal(Ok(Claim(0))),
                    open: true,
                    events: vec![
                        Event::Header(1, 32),
                        Event::ReadOffer(1, 0, 0),
                        Event::ReadReturn(1),
                        Event::Reserve(1, 1),
                        Event::Decode(1)
                    ],
                },
            "W09_BUDGET"
        );
        decode_case::<Claim>(side, &[1], Seen::Budget, "W09_BUDGET").await;
    }
    roundtrip(vec![vec![7u8, 9, 11]], 32, "W09_BUDGET").await;
    let length =
        bincode::encode_to_vec(u64::MAX, common::bincode_config()).expect("HARNESS_ENCODE");
    for side in [Side::Server, Side::Client(0)] {
        decode_case::<Vec<u8>>(side, &length, Seen::Budget, "W09_BUDGET").await;
    }
}

// The drop signal waits for all production service tasks to release their service owner.
#[derive(Default)]
struct ServiceState {
    calls: std::sync::Mutex<Vec<Vec<u8>>>,
    dropped: tokio::sync::Notify,
}

mod small {
    //! A small service cap makes complete boundary frames inexpensive.
    use super::{service, ServiceState};
    use crate::distributed::sonic::service::sonic_service;

    /// Synthetic echo service whose invocation list survives task teardown.
    pub struct EchoService {
        /// Shared invocation and teardown observations.
        pub(super) state: std::sync::Arc<ServiceState>,
    }

    /// Byte-vector request whose service envelope is measured independently.
    #[derive(Clone, bincode::Encode, bincode::Decode)]
    pub struct Echo(pub Vec<u8>);

    impl service::Message<EchoService> for Echo {
        type Response = Vec<u8>;

        async fn handle(self, server: &EchoService) -> Self::Response {
            server
                .state
                .calls
                .lock()
                .expect("HARNESS_CALLS")
                .push(self.0.clone());
            self.0
        }
    }

    impl Drop for EchoService {
        fn drop(&mut self) {
            self.state.dropped.notify_one();
        }
    }

    sonic_service!(EchoService, [Echo], max_frame_body_bytes = 32);
}

mod ordinary {
    //! The original two-argument macro retains default framing policy.
    use super::service;
    use crate::distributed::sonic::service::sonic_service;

    /// Synthetic service using the original macro form.
    pub struct EchoService;

    /// Byte-vector request shared with a complete response control.
    #[derive(Clone, bincode::Encode, bincode::Decode)]
    pub struct Echo(pub Vec<u8>);

    impl service::Message<EchoService> for Echo {
        type Response = Vec<u8>;

        async fn handle(self, _: &EchoService) -> Self::Response {
            self.0
        }
    }

    sonic_service!(EchoService, [Echo]);
}

// Construct the entire service envelope, including sequence and variant bytes.
fn service_body(length: u8, batch: bool) -> Vec<u8> {
    let mut body = if batch {
        vec![1, 1, 0, length]
    } else {
        vec![0, 0, length]
    };
    body.extend(vec![7; usize::from(length)]);
    body
}

// Compare full independently encoded service request envelopes before sending them.
fn request_body(length: u8, batch: bool) -> Vec<u8> {
    use service::Wrapper;
    let request = small::Echo::wrap_request(small::Echo(vec![7; usize::from(length)]));
    let request = if batch {
        crate::OneOrMany::Many(vec![request])
    } else {
        crate::OneOrMany::One(request)
    };
    let body = bincode::encode_to_vec(request, common::bincode_config()).expect("HARNESS_ENCODE");
    assert!(body == service_body(length, batch), "W07_ENVELOPE");
    body
}

// The macro constant is exercised on raw sockets independently of service bind propagation.
async fn macro_policy() {
    let policy = <small::EchoService as service::Service>::MAX_FRAME_BODY_BYTES;
    let (mut peer, reading) = receiver::<[u8; 33]>(Side::Server, Some(policy)).await;
    bounded(peer.write_all(&frame(&[7; 33])))
        .await
        .expect("HARNESS_BODY");
    let (actual, _owner) = reading.finish().await;
    assert!(
        actual
            == Observation {
                returned: Returned::Normal(Err(Seen::Cap(33, 32))),
                open: false,
                events: vec![Event::Header(33, 32)],
            },
        "W07_MACRO_POLICY"
    );
    assert!(
        closure(&mut peer).await == Closure::PeerClosed,
        "W07_MACRO_POLICY"
    );
    roundtrip(vec![[7u8; 32]], policy, "W07_MACRO_POLICY").await;
}

// Both the generated bind method and the ordinary service constructor must carry the cap.
async fn bind_service(
    state: std::sync::Arc<ServiceState>,
    generated: bool,
) -> (service::Server<small::EchoService>, SocketAddr) {
    for _ in 0..16 {
        let reservation = bounded(TcpListener::bind("127.0.0.1:0"))
            .await
            .expect("HARNESS_RESERVE");
        let addr = reservation.local_addr().expect("HARNESS_ADDRESS");
        if (57300..=57320).contains(&addr.port()) {
            continue;
        }
        drop(reservation);
        let service = small::EchoService {
            state: state.clone(),
        };
        let result = if generated {
            service.bind(addr).await
        } else {
            service::Server::bind(service, addr).await
        };
        match result {
            Ok(server) => return (server, addr),
            Err(Error::IO(error)) if error.kind() == ErrorKind::AddrInUse => {}
            Err(_) => panic!("HARNESS_SERVICE_BIND"),
        }
    }
    panic!("HARNESS_PORT_ATTEMPTS");
}

// A complete over-cap request must not enter the handler; a later valid request must.
async fn server_policy(generated: bool) {
    let state = std::sync::Arc::new(ServiceState::default());
    let (server, addr) = bind_service(state.clone(), generated).await;
    let mut peer = bounded(TcpStream::connect(addr))
        .await
        .expect("HARNESS_CONNECT");
    bounded(server.accept())
        .await
        .unwrap_or_else(|_| panic!("HARNESS_ACCEPT"));
    let body = request_body(30, false);
    assert!(
        body == [vec![0, 0, 30], vec![7; 30]].concat(),
        "W07_ENVELOPE"
    );
    bounded(peer.write_all(&frame(&body)))
        .await
        .expect("HARNESS_BODY");
    let bytes = optional_frame(&mut peer).await;
    let refused_calls = state.calls.lock().expect("HARNESS_CALLS").clone();
    let mut good = bounded(TcpStream::connect(addr))
        .await
        .expect("HARNESS_CONNECT");
    bounded(server.accept())
        .await
        .unwrap_or_else(|_| panic!("HARNESS_ACCEPT"));
    bounded(good.write_all(&frame(&request_body(29, false))))
        .await
        .expect("HARNESS_BODY");
    let response = read_wire(&mut good).await;
    drop(good);
    drop(peer);
    drop(server);
    bounded(state.dropped.notified()).await;
    let calls = state.calls.lock().expect("HARNESS_CALLS").clone();
    assert!(
        bytes.is_empty()
            && refused_calls.is_empty()
            && calls == vec![vec![7; 29]]
            && response == frame(&service_body(29, false)),
        "W07_SERVER_POLICY"
    );
}

// Constructor and send modes remain separate from the two retry marker groups.
#[derive(Clone, Copy)]
enum ServiceRoute {
    Create,
    Timed,
    Pool,
    Remote,
    Retry,
}

// All service sends use a valid response shape, so a lost cap returns a complete value.
async fn service_send(
    conn: &mut service::Connection<small::EchoService>,
    mode: u8,
) -> Result<Vec<Vec<u8>>, Seen> {
    let request = small::Echo(vec![7]);
    match mode {
        0 => conn.send(request).await.map(|value| vec![value]),
        1 => conn
            .send_without_timeout(request)
            .await
            .map(|value| vec![value]),
        2 => conn
            .send_with_timeout(request, DEADLINE)
            .await
            .map(|value| vec![value]),
        _ => conn.batch_send_with_timeout(&[request], DEADLINE).await,
    }
    .map_err(seen)
}

// Pools and replication clients reach production constructors rather than test builders.
async fn route_send(addr: SocketAddr, route: ServiceRoute, mode: u8) -> Result<Vec<Vec<u8>>, Seen> {
    match route {
        ServiceRoute::Create | ServiceRoute::Timed | ServiceRoute::Retry => {
            let mut conn = match route {
                ServiceRoute::Create => service::Connection::create(addr).await,
                ServiceRoute::Timed => {
                    service::Connection::create_with_timeout(addr, DEADLINE).await
                }
                ServiceRoute::Retry => {
                    service::Connection::create_with_timeout_retry(
                        addr,
                        DEADLINE,
                        std::iter::empty(),
                    )
                    .await
                }
                _ => unreachable!(),
            }
            .map_err(seen)?;
            service_send(&mut conn, mode).await
        }
        ServiceRoute::Pool => {
            let pool = ConnectionPool::<service::Connection<small::EchoService>>::new(addr)
                .expect("HARNESS_POOL");
            let mut conn = pool.get().await.expect("HARNESS_CHECKOUT");
            service_send(&mut conn, mode).await
        }
        ServiceRoute::Remote => {
            let remote = replication::RemoteClient::<small::EchoService>::new(addr);
            if mode == 3 {
                remote
                    .batch_send_with_timeout(&[small::Echo(vec![7])], DEADLINE)
                    .await
                    .map_err(seen)
            } else {
                remote
                    .send_with_timeout(small::Echo(vec![7]), DEADLINE)
                    .await
                    .map(|value| vec![value])
                    .map_err(seen)
            }
        }
    }
}

// The peer records complete requests and offers one measured response envelope.
async fn client_policy(route: ServiceRoute, mode: u8, size: u8, marker: &str) {
    let batch = mode == 3;
    let length = size - if batch { 4 } else { 3 };
    let body = service_body(length, batch);
    assert!(
        body.len() == usize::from(size) && request_body(length, batch) == body,
        "W07_ENVELOPE"
    );
    let (listener, addr) = listener().await;
    let task = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.expect("HARNESS_ACCEPT");
        let request = read_wire(&mut peer).await;
        peer.write_all(&frame(&body))
            .await
            .expect("HARNESS_RESPONSE");
        (request, closure(&mut peer).await)
    });
    let send_task = tokio::spawn(route_send(addr, route, mode));
    let actual = joined(send_task).await;
    let transcript = joined(task).await;
    let expected = if size > 32 {
        Err(Seen::Cap(usize::from(size), 32))
    } else {
        Ok(vec![vec![7; usize::from(length)]])
    };
    assert!(
        matches!(actual, Ok(ref value) if value == &expected)
            && matches!(transcript, Ok((ref request, Closure::PeerClosed))
            if request == &frame(&request_body(1, batch))),
        "{marker}"
    );
}

// Raw retry has its own assertion before service retry can reach the same constructor.
async fn raw_retry() {
    for size in [32usize, 33] {
        let (listener, addr) = listener().await;
        let task = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.expect("HARNESS_ACCEPT");
            let request = read_wire(&mut peer).await;
            peer.write_all(&frame(&vec![7; size]))
                .await
                .expect("HARNESS_RESPONSE");
            request
        });
        let result = if size == 32 {
            let mut conn = Connection::<u32, [u8; 32]>::create_with_timeout_retry_and_limit(
                addr,
                DEADLINE,
                std::iter::empty(),
                32,
            )
            .await
            .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
            bounded(conn.send(&7))
                .await
                .map(|value| value.to_vec())
                .map_err(seen)
        } else {
            let mut conn = Connection::<u32, [u8; 33]>::create_with_timeout_retry_and_limit(
                addr,
                DEADLINE,
                std::iter::empty(),
                32,
            )
            .await
            .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
            bounded(conn.send(&7))
                .await
                .map(|value| value.to_vec())
                .map_err(seen)
        };
        let request = joined(task).await;
        let expected = if size == 32 {
            Ok(vec![7; 32])
        } else {
            Err(Seen::Cap(33, 32))
        };
        assert!(
            result == expected && matches!(request, Ok(bytes) if bytes == wire(&7u32)),
            "W07_RAW_RETRY"
        );
    }
}

// The original macro form must accept a response that the 32-byte service refuses.
async fn default_service() {
    let (listener, addr) = listener().await;
    let task = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.expect("HARNESS_ACCEPT");
        let request = read_wire(&mut peer).await;
        peer.write_all(&frame(&service_body(30, false)))
            .await
            .expect("HARNESS_RESPONSE");
        request
    });
    let mut conn = service::Connection::<ordinary::EchoService>::create(addr)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let result = bounded(conn.send(ordinary::Echo(vec![7])))
        .await
        .map_err(seen);
    let request = joined(task).await;
    assert!(
        result == Ok(vec![7; 30])
            && matches!(request, Ok(bytes) if bytes == frame(&service_body(1, false))),
        "W07_MACRO_POLICY"
    );
}

#[tokio::test]
async fn w07_service_policy() {
    macro_policy().await;
    default_service().await;
    server_policy(true).await;
    server_policy(false).await;
    for route in [
        ServiceRoute::Create,
        ServiceRoute::Timed,
        ServiceRoute::Pool,
    ] {
        for mode in 0..4 {
            for size in [31, 32, 33] {
                client_policy(route, mode, size, "W07_CLIENT_POLICY").await;
            }
        }
    }
    for mode in [2, 3] {
        for size in [32, 33] {
            client_policy(ServiceRoute::Remote, mode, size, "W07_CLIENT_POLICY").await;
        }
    }
    raw_retry().await;
    for size in [32, 33] {
        client_policy(ServiceRoute::Retry, 0, size, "W07_RETRY_POLICY").await;
    }
}

// Native headers are fragmented on writes and consecutive complete frames are coalesced.
async fn wire_server() {
    let (server, addr) = server::<u32, u32>(Some(32)).await;
    let mut peer = bounded(TcpStream::connect(addr))
        .await
        .expect("HARNESS_CONNECT");
    let task = tokio::spawn(async move {
        let mut conn = server.accept().await?;
        let mut values = Vec::new();
        for _ in 0..3 {
            let req = conn.request().await?;
            let value = *req.body();
            values.push(value);
            req.respond(value * 10).await?;
        }
        Ok::<_, Error>(values)
    });
    for byte in 1usize.to_ne_bytes() {
        bounded(peer.write_all(&[byte]))
            .await
            .expect("HARNESS_HEADER");
    }
    bounded(peer.write_all(&[7])).await.expect("HARNESS_BODY");
    let first = read_wire(&mut peer).await;
    bounded(peer.write_all(&[wire(&9u32), wire(&11u32)].concat()))
        .await
        .expect("HARNESS_BODY");
    let second = read_wire(&mut peer).await;
    let third = read_wire(&mut peer).await;
    let requests = joined(task).await;
    assert!(
        matches!(requests, Ok(Ok(ref values)) if values == &[7, 9, 11])
            && [first, second, third] == [wire(&70u32), wire(&90u32), wire(&110u32)],
        "W10_WIRE"
    );
}

// The response reader must leave the next coalesced frame untouched between sends.
async fn wire_client() {
    let (listener, addr) = listener().await;
    let task = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.expect("HARNESS_ACCEPT");
        let first = read_wire(&mut peer).await;
        for byte in 1usize.to_ne_bytes() {
            peer.write_all(&[byte]).await.expect("HARNESS_HEADER");
        }
        peer.write_all(&[70]).await.expect("HARNESS_BODY");
        let second = read_wire(&mut peer).await;
        peer.write_all(&[wire(&90u32), wire(&110u32)].concat())
            .await
            .expect("HARNESS_BODY");
        let third = read_wire(&mut peer).await;
        [first, second, third]
    });
    let mut conn = Connection::<u32, u32>::create(addr)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let mut values = Vec::new();
    for value in [7, 9, 11] {
        values.push(bounded(conn.send(&value)).await.map_err(seen));
    }
    let requests = joined(task).await;
    assert!(
        values == [Ok(70), Ok(90), Ok(110)]
            && matches!(requests, Ok(bytes) if bytes == [wire(&7u32), wire(&9u32), wire(&11u32)]),
        "W10_WIRE"
    );
}

// Multi-field records make truncation or field loss visible in complete value comparisons.
#[derive(Clone, PartialEq, Encode, Decode)]
struct SizedRecord {
    id: u64,
    title: String,
    text: String,
}

// Whole independently encoded values cover schemas without a PartialEq implementation.
async fn measured<T: Encode + Decode + Clone + Send + Sync + 'static>(
    value: T,
    label: &str,
) -> usize {
    let expected =
        bincode::encode_to_vec(&value, common::bincode_config()).expect("HARNESS_ENCODE");
    let size = expected.len();
    let (server, addr) = server::<T, T>(None).await;
    let task = tokio::spawn(async move {
        let mut conn = server.accept().await?;
        let req = conn.request().await?;
        let encoded =
            bincode::encode_to_vec(req.body(), common::bincode_config()).expect("HARNESS_ENCODE");
        let response = req.body().clone();
        req.respond(response).await?;
        Ok::<_, Error>(encoded)
    });
    let mut conn = Connection::<T, T>::connect(addr)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let result = bounded(conn.send(&value))
        .await
        .map_err(seen)
        .map(|response| {
            bincode::encode_to_vec(response, common::bincode_config()).expect("HARNESS_ENCODE")
        });
    let request = joined(task).await;
    assert!(
        matches!(request, Ok(Ok(ref bytes)) if bytes == &expected) && result == Ok(expected),
        "W10_SIZES"
    );
    println!("SIZING {label} body_bytes={size}");
    size
}

// Indexing uses the actual OneOrMany and generated IndexWebpages service envelope.
async fn index_size(pages: usize, body_bytes: usize, label: &str) {
    use crate::entrypoint::{indexer::IndexableWebpage, live_index::search_server::IndexWebpages};
    use service::Wrapper;
    let page = IndexableWebpage {
        record: None,
        url: "https://example.invalid/".into(),
        body: "x".repeat(body_bytes),
        fetch_time_ms: 7,
    };
    let message = IndexWebpages {
        pages: vec![page; pages],
        consistency_fraction: Some(1.0),
    };
    let value = crate::OneOrMany::One(IndexWebpages::wrap_request(message));
    measured(value, label).await;
}

#[tokio::test]
async fn w10_wire_and_sizes() {
    wire_server().await;
    wire_client().await;
    roundtrip(vec![(), ()], 0, "W10_WIRE").await;
    let search = (0..20)
        .map(|id| SizedRecord {
            id,
            title: "t".repeat(16),
            text: "s".repeat(275),
        })
        .collect::<Vec<_>>();
    measured(search.clone(), "search_20_snippets_275").await;
    let encoded =
        bincode::encode_to_vec(&search, common::bincode_config()).expect("HARNESS_ENCODE");
    cap_case::<Vec<SizedRecord>>(
        Side::Server,
        Some(32),
        encoded.len(),
        &encoded,
        false,
        "W10_SIZES",
    )
    .await;
    let retrieval = (0..300)
        .map(|id| SizedRecord {
            id,
            title: "t".repeat(16),
            text: "r".repeat(4096),
        })
        .collect::<Vec<_>>();
    measured(retrieval, "retrieval_300_strings_4096").await;
    index_size(512, 16 * 1024, "index_512_bodies_16384").await;
    index_size(1, 32 * 1024 * 1024, "index_1_body_33554432").await;
    let pairs = (0..4096u64)
        .map(|key| {
            let mut value = crate::hyperloglog::HyperLogLog::<64>::default();
            value.add(key);
            (key, value)
        })
        .collect::<Vec<_>>();
    let size = measured(pairs, "dht_4096_pairs_hll64").await;
    println!("SIZING dht_300_batches body_bytes={}", size * 300);
}

// Independent literals for the DHT override (A17) and the sonic default it is compared with.
const DHT_CAP: usize = 134_217_728;
const DEFAULT_CAP: usize = 67_108_864;

type DhtServer = crate::ampc::dht::network::Server;
type DhtValue = Option<crate::ampc::dht::value::Value>;

// A DHT read whose string key sets the request body length; the table is never populated.
fn dht_get(key: String) -> crate::ampc::dht::network::api::Get {
    crate::ampc::dht::network::api::Get {
        table: "t".into(),
        key: crate::ampc::dht::key::Key::String(key),
    }
}

// Counts encoded bytes without building a second copy of a large request.
fn encoded_size<T: Encode>(value: &T) -> usize {
    let mut writer = bincode::enc::write::SizeWriter::default();
    bincode::encode_into_writer(value, &mut writer, common::bincode_config())
        .expect("HARNESS_ENCODE");
    writer.bytes_written
}

// Builds a `Get` whose whole service envelope is exactly `body` bytes long.
fn dht_get_of_size(body: usize) -> crate::ampc::dht::network::api::Get {
    use service::Wrapper;
    let probe = dht_get("k".repeat(65_536));
    let envelope = bincode::encode_to_vec(
        crate::OneOrMany::One(<crate::ampc::dht::network::api::Get as Wrapper<
            DhtServer,
        >>::wrap_request(probe.clone())),
        common::bincode_config(),
    )
    .expect("HARNESS_ENCODE");
    let get = bincode::encode_to_vec(&probe, common::bincode_config()).expect("HARNESS_ENCODE");
    // The envelope is a OneOrMany tag and a variant index before the unchanged `Get` bytes.
    assert!(
        envelope[2..] == get[..] && envelope.len() == 2 + get.len(),
        "HARNESS_ENVELOPE"
    );
    let overhead = envelope.len() - 65_536;
    let request = dht_get("k".repeat(body - overhead));
    assert!(2 + encoded_size(&request) == body, "HARNESS_ENVELOPE");
    request
}

// A real service client receives a bare header (plus one sentinel byte) from a controlled peer.
async fn header_reply<S, R>(
    request: R,
    declared: usize,
    half_close: bool,
) -> (Result<(), Seen>, Closure)
where
    S: service::Service,
    R: service::Wrapper<S>,
{
    let (listener, addr) = listener().await;
    let peer = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.expect("HARNESS_ACCEPT");
        let _request = read_wire(&mut peer).await;
        peer.write_all(&declared.to_ne_bytes())
            .await
            .expect("HARNESS_HEADER");
        peer.write_all(&[7]).await.expect("HARNESS_BODY");
        if half_close {
            peer.shutdown().await.expect("HARNESS_SHUTDOWN");
        }
        closure(&mut peer).await
    });
    let mut conn = service::Connection::<S>::create(addr)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let result = bounded(conn.send_with_timeout(request, DEADLINE))
        .await
        .map(|_| ())
        .map_err(seen);
    drop(conn);
    (result, joined(peer).await.expect("HARNESS_PEER"))
}

// A real DHT service over in-memory raft storage, bound through its generated `bind`.
async fn bind_dht() -> (
    openraft::Raft<crate::ampc::dht::TypeConfig>,
    service::Server<DhtServer>,
    SocketAddr,
) {
    use crate::ampc::dht::{log_store::LogStore, network::Network, store::StateMachineStore};
    let config = std::sync::Arc::new(
        openraft::Config::default()
            .validate()
            .expect("HARNESS_RAFT"),
    );
    let store = std::sync::Arc::new(StateMachineStore::default());
    let raft = openraft::Raft::new(1, config, Network, LogStore::default(), store.clone())
        .await
        .expect("HARNESS_RAFT");
    for _ in 0..16 {
        let reservation = bounded(TcpListener::bind("127.0.0.1:0"))
            .await
            .expect("HARNESS_RESERVE");
        let addr = reservation.local_addr().expect("HARNESS_ADDRESS");
        if (57300..=57320).contains(&addr.port()) {
            continue;
        }
        drop(reservation);
        match DhtServer::new(raft.clone(), store.clone()).bind(addr).await {
            Ok(server) => return (raft, server, addr),
            Err(Error::IO(error)) if error.kind() == ErrorKind::AddrInUse => {}
            Err(_) => panic!("HARNESS_SERVICE_BIND"),
        }
    }
    panic!("HARNESS_PORT_ATTEMPTS");
}

// The real DHT server decodes a body just over 64 MiB and refuses a header one byte over its cap.
async fn dht_server_outcomes(over_default: usize) -> (Result<DhtValue, Seen>, Vec<u8>, Closure) {
    let (raft, server, addr) = bind_dht().await;
    let accept = tokio::spawn(async move { while server.accept().await.is_ok() {} });
    let mut conn = service::Connection::<DhtServer>::create(addr)
        .await
        .unwrap_or_else(|_| panic!("HARNESS_CLIENT"));
    let accepted = bounded(conn.send_with_timeout(dht_get_of_size(over_default), DEADLINE))
        .await
        .map_err(seen);
    drop(conn);
    let mut peer = bounded(TcpStream::connect(addr))
        .await
        .expect("HARNESS_CONNECT");
    bounded(peer.write_all(&(DHT_CAP + 1).to_ne_bytes()))
        .await
        .expect("HARNESS_HEADER");
    bounded(peer.write_all(&[7])).await.expect("HARNESS_BODY");
    let bytes = optional_frame(&mut peer).await;
    let closed = closure(&mut peer).await;
    accept.abort();
    let _ = accept.await;
    bounded(raft.shutdown()).await.expect("HARNESS_RAFT");
    (accepted, bytes, closed)
}

#[tokio::test]
async fn w11_dht_frame_policy() {
    let pin = (
        <DhtServer as service::Service>::MAX_FRAME_BODY_BYTES,
        header_reply::<DhtServer, _>(dht_get("k".into()), DHT_CAP + 1, false).await,
    );
    assert!(
        pin == (
            DHT_CAP,
            (Err(Seen::Cap(DHT_CAP + 1, DHT_CAP)), Closure::PeerClosed)
        ),
        "W11_DHT_POLICY"
    );
    let over_default = DEFAULT_CAP + 1;
    let default_client =
        header_reply::<ordinary::EchoService, _>(ordinary::Echo(vec![7]), over_default, true).await;
    let dht_client = header_reply::<DhtServer, _>(dht_get("k".into()), over_default, true).await;
    let dht_server = dht_server_outcomes(over_default).await;
    assert!(
        default_client
            == (
                Err(Seen::Cap(over_default, DEFAULT_CAP)),
                Closure::PeerClosed
            )
            && dht_client == (Err(Seen::Io(ErrorKind::UnexpectedEof)), Closure::PeerClosed)
            && dht_server == (Ok(None), Vec::new(), Closure::PeerClosed),
        "W11_DHT_POLICY"
    );
    cap_case::<Vec<u8>>(
        Side::Server,
        None,
        over_default,
        &[7],
        true,
        "W11_DHT_POLICY",
    )
    .await;
}
