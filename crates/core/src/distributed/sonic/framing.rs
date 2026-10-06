// SPDX-License-Identifier: AGPL-3.0-only
//! The one sonic frame reader and writer, shared by raw clients and servers.
//!
//! A frame is a native-endian `usize` header holding the body length, then a standard bincode
//! body. Reads check the declared length against the connection's cap before any body storage
//! or body read, then grow storage only as bytes arrive. Decoding runs under a separate claim
//! budget and must consume the whole body. Writes encode completely, within the cap, before
//! the first socket byte. Connection owners in `mod.rs` discard the socket on every error
//! returned here. Not covered: aggregate connections, read duration, or memory and CPU spent by
//! custom `Encode`/`Decode` implementations and serde visitors.

use bincode::{enc::write::Writer, error::EncodeError};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

use super::{Error, Result};

/// Size of the fixed stack scratch buffer; also the largest body slice offered to one read,
/// so storage never depends on a declaration before bytes arrive.
pub(super) const READ_CHUNK_BYTES: usize = 16 * 1024;
/// Bincode byte-claim budget per decode (256 MiB). Containers claim their decoded layout,
/// which a small encoded length can inflate, so this is separate from the encoded-body cap.
pub(super) const MAX_DECODE_CLAIM_BYTES: usize = 256 * 1024 * 1024;

/// Per-connection record of real framing operations for loopback witnesses. It never alters
/// control flow, and outside `cfg(test)` it is an empty type that records nothing.
#[derive(Clone, Default)]
pub(super) struct FrameObserver {
    #[cfg(test)]
    events: std::sync::Arc<std::sync::Mutex<Vec<Event>>>,
    #[cfg(test)]
    changed: std::sync::Arc<tokio::sync::Notify>,
}

/// One observed framing operation, with complete numeric fields.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Event {
    /// Parsed declaration and configured maximum, before admission.
    Header(usize, usize),
    /// Offered slice length, buffered body length and actual capacity.
    ReadOffer(usize, usize, usize),
    /// Number of bytes returned by a body read.
    ReadReturn(usize),
    /// Additional requested bytes and requested total capacity, before reservation.
    Reserve(usize, usize),
    /// Body length at entry to the real decoder.
    Decode(usize),
    /// Offered socket write length, with true identifying a header.
    Write(bool, usize),
}

impl FrameObserver {
    // Notifications follow storage so a waiter cannot miss an already-recorded operation.
    #[cfg(test)]
    fn record(&self, event: Event) {
        self.events.lock().expect("FRAME_OBSERVER_LOCK").push(event);
        self.changed.notify_one();
    }

    /// Returns every operation recorded so far, so assertions compare whole sequences.
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> Vec<Event> {
        self.events.lock().expect("FRAME_OBSERVER_LOCK").clone()
    }

    /// Waits until more than `count` operations exist and returns them all; callers assert the
    /// result rather than waiting for a preferred value, so a changed value fails fast.
    #[cfg(test)]
    pub(super) async fn after(&self, count: usize) -> Vec<Event> {
        loop {
            let notified = self.changed.notified();
            let events = self.snapshot();
            if events.len() > count {
                return events;
            }
            notified.await;
        }
    }

    // Keep the test seam beside the header admission point.
    fn header(&self, _size: usize, _limit: usize) {
        #[cfg(test)]
        self.record(Event::Header(_size, _limit));
    }

    // Capture actual storage at the slice offered to the socket.
    fn read_offer(&self, _offered: usize, _buffered: usize, _capacity: usize) {
        #[cfg(test)]
        self.record(Event::ReadOffer(_offered, _buffered, _capacity));
    }

    // Record EOF separately from a body that has not arrived yet.
    fn read_return(&self, _size: usize) {
        #[cfg(test)]
        self.record(Event::ReadReturn(_size));
    }

    // Requested capacity is observable before allocator rounding can change it.
    fn reserve(&self, _additional: usize, _target: usize) {
        #[cfg(test)]
        self.record(Event::Reserve(_additional, _target));
    }

    // Decoder entry must remain after the complete body read.
    fn decode(&self, _size: usize) {
        #[cfg(test)]
        self.record(Event::Decode(_size));
    }

    // Observe writes only after bounded encoding has completed.
    fn write(&self, _header: bool, _size: usize) {
        #[cfg(test)]
        self.record(Event::Write(_header, _size));
    }
}

/// Returns `BodyTooLarge` when `body_size` exceeds `max_body_size`; equality is accepted.
pub(super) fn check_body_size(body_size: usize, max_body_size: usize) -> Result<()> {
    if body_size > max_body_size {
        return Err(Error::BodyTooLarge {
            body_size,
            max_size: max_body_size,
        });
    }
    Ok(())
}

/// Makes room for `additional` more bytes without ever reserving past `max_body_size`.
///
/// Growth is geometric, so a body read in small slices is not copied on every read, but the
/// target is clamped to the maximum. Length overflow can only come from a writer, so it maps
/// to `Encode`; a failed reservation maps to `Allocation`.
pub(super) fn reserve_bounded(
    body: &mut Vec<u8>,
    additional: usize,
    max_body_size: usize,
    observer: &FrameObserver,
) -> Result<()> {
    let needed = body
        .len()
        .checked_add(additional)
        .ok_or(Error::Encode(EncodeError::Other(
            "sonic encoded length overflow",
        )))?;
    check_body_size(needed, max_body_size)?;
    if needed <= body.capacity() {
        return Ok(());
    }
    let grown = body.capacity().saturating_mul(2).max(needed);
    let target = grown.min(max_body_size);
    observer.reserve(target - body.len(), target);
    body.try_reserve_exact(target - body.len())
        .map_err(Error::Allocation)
}

/// Reads one whole frame and decodes it, for both server requests and client responses.
pub(super) async fn read_frame<T: bincode::Decode>(
    stream: &mut TcpStream,
    max_body_size: usize,
    observer: &FrameObserver,
) -> Result<T> {
    let mut header = [0; std::mem::size_of::<usize>()];
    stream.read_exact(&mut header).await?;
    let body_size = usize::from_ne_bytes(header);
    observer.header(body_size, max_body_size);
    check_body_size(body_size, max_body_size)?;
    let mut body = Vec::new();
    let mut chunk = [0; READ_CHUNK_BYTES];
    while body.len() < body_size {
        let remaining = body_size - body.len();
        // A read must not consume bytes from the following frame's header.
        let read_len = remaining.min(chunk.len());
        observer.read_offer(read_len, body.len(), body.capacity());
        let received = stream.read(&mut chunk[..read_len]).await?;
        observer.read_return(received);
        if received == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        reserve_bounded(&mut body, received, body_size, observer)?;
        body.extend_from_slice(&chunk[..received]);
    }
    observer.decode(body.len());
    decode_frame(&body)
}

/// Decodes exactly one value from `body` under the claim budget; leftovers are an error.
pub(super) fn decode_frame<T: bincode::Decode>(body: &[u8]) -> Result<T> {
    let (value, consumed) = bincode::decode_from_slice(
        body,
        common::bincode_config().with_limit::<MAX_DECODE_CLAIM_BYTES>(),
    )
    .map_err(Error::Decode)?;
    if consumed != body.len() {
        return Err(Error::TrailingBytes {
            consumed,
            body_size: body.len(),
        });
    }
    Ok(value)
}

// A pending typed failure survives bincode's writer error adapter.
struct BoundedWriter<'a> {
    body: Vec<u8>,
    max_body_size: usize,
    pending: Option<Error>,
    observer: &'a FrameObserver,
}

// Admission and fallible reservation precede each append, including custom encoders.
impl Writer for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::result::Result<(), EncodeError> {
        if self.pending.is_some() {
            return Err(EncodeError::Other("sonic bounded writer failure"));
        }
        if let Err(error) = reserve_bounded(
            &mut self.body,
            bytes.len(),
            self.max_body_size,
            self.observer,
        ) {
            self.pending = Some(error);
            return Err(EncodeError::Other("sonic bounded writer failure"));
        }
        self.body.extend_from_slice(bytes);
        Ok(())
    }
}

/// Encodes `value` into a new body of at most `max_body_size` bytes.
///
/// The value is never encoded unbounded first, and nothing is written to a socket here, so an
/// oversized value is refused before any frame byte leaves the process.
pub(super) fn encode_frame<T: bincode::Encode>(
    value: &T,
    max_body_size: usize,
    observer: &FrameObserver,
) -> Result<Vec<u8>> {
    let mut writer = BoundedWriter {
        body: Vec::new(),
        max_body_size,
        pending: None,
        observer,
    };
    let result = bincode::encode_into_writer(value, &mut writer, common::bincode_config());
    match result {
        Ok(()) => match writer.pending {
            Some(error) => Err(error),
            None => Ok(writer.body),
        },
        Err(error) => match writer.pending {
            Some(error) => Err(error),
            None => Err(Error::Encode(error)),
        },
    }
}

/// Writes the native-endian length header and the already-bounded body, then flushes.
pub(super) async fn write_frame(
    stream: &mut TcpStream,
    body: &[u8],
    observer: &FrameObserver,
) -> Result<()> {
    let header = body.len().to_ne_bytes();
    observer.write(true, header.len());
    stream.write_all(&header).await?;
    observer.write(false, body.len());
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Drops the socket. A failed exchange may leave unread or half-written bytes, so the only
/// safe state is no stream at all; a half-close would leave the read half reusable.
pub(super) fn close_peer(stream: &mut Option<TcpStream>) {
    *stream = None;
}
