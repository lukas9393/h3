//! QUIC Transport traits
//!
//! This module includes traits and types meant to allow being generic over any
//! QUIC implementation.

use std::task::{self, Poll};

use bytes::Buf;

pub use crate::proto::stream::{InvalidStreamId, StreamId};
pub use crate::stream::WriteBuf;

// Unresolved questions:
//
// - Should the `poll_` methods be `Pin<&mut Self>`?

/// Trait that represent an error from the transport layer
pub trait Error: std::error::Error + Send + Sync {
    /// Check if the current error is a transport timeout
    fn is_timeout(&self) -> bool;

    /// Get the QUIC error code from connection close or stream stop
    fn err_code(&self) -> Option<u64>;
}

impl<'a, E: Error + 'a> From<E> for Box<dyn Error + 'a> {
    fn from(err: E) -> Box<dyn Error + 'a> {
        Box::new(err)
    }
}

/// Trait representing a QUIC connection.
pub trait Connection<B: Buf> {
    /// The type produced by `poll_accept_bidi()`
    type BidiStream: SendStream<B> + RecvStream;
    /// The type of the sending part of `BidiStream`
    type SendStream: SendStream<B>;
    /// The type produced by `poll_accept_recv()`
    type RecvStream: RecvStream;
    /// A producer of outgoing Unidirectional and Bidirectional streams.
    type OpenStreams: OpenStreams<B>;
    /// Error type yielded by this trait methods
    type Error: Into<Box<dyn Error>>;

    /// Accept an incoming unidirecional stream
    ///
    /// Returning `None` implies the connection is closing or closed.
    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, Self::Error>>;

    /// Accept an incoming bidirecional stream
    ///
    /// Returning `None` implies the connection is closing or closed.
    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, Self::Error>>;

    /// Poll the connection to create a new bidirectional stream.
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, Self::Error>>;

    /// Poll the connection to create a new unidirectional stream.
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, Self::Error>>;

    /// Get an object to open outgoing streams.
    fn opener(&self) -> Self::OpenStreams;

    /// Close the connection immediately
    fn close(&mut self, code: crate::error::Code, reason: &[u8]);
}

/// Trait for opening outgoing streams
pub trait OpenStreams<B: Buf> {
    /// The type produced by `poll_open_bidi()`
    type BidiStream: SendStream<B> + RecvStream;
    /// The type produced by `poll_open_send()`
    type SendStream: SendStream<B>;
    /// The type of the receiving part of `BidiStream`
    type RecvStream: RecvStream;
    /// Error type yielded by these trait methods
    type Error: Into<Box<dyn Error>>;
    /// The type of the send datagram
    type SendDatagrams: SendDatagrams;
    /// The type of the recieve datagram
    type RecvDatagrams: RecvDatagrams;

    /// Poll the connection to create a new bidirectional stream.
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, Self::Error>>;

    /// Poll the connection to create a new unidirectional stream.
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, Self::Error>>;

    /// Close the connection immediately
    fn close(&mut self, code: crate::error::Code, reason: &[u8]);

    /// Get an Send Datagram object
    fn send_datagrams(&self) -> Self::SendDatagrams;

    /// Get an Recieve Datagram object
    fn recieve_datagrams(&self) -> Self::RecvDatagrams;
}

/// A trait describing the "send" actions of a QUIC stream.
pub trait SendStream<B: Buf> {
    /// The error type returned by fallible send methods.
    type Error: Into<Box<dyn Error>>;

    /// Polls if the stream can send more data.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Send more data on the stream.
    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), Self::Error>;

    /// Poll to finish the sending side of the stream.
    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Send a QUIC reset code.
    fn reset(&mut self, reset_code: u64);

    /// Get QUIC send stream id
    fn id(&self) -> StreamId;
}

/// A trait describing the "send" actions of a QUIC datagram "stream".
pub trait SendDatagrams {
    /// The error type returned by fallible send methods.
    type Error: Into<Box<dyn Error>>;

    /// Compute the maximum size of datagrams that may be passed to [`send_datagram()`].
    fn max_datagram_size(&self) -> Option<usize>;

    /// Transmit `data` as an unreliable, unordered application datagram.
    fn send_datagrams<B: Buf>(&mut self, data: B) -> Result<(), Self::Error>;
}

/// A trait describing the "send" actions of a QUIC datagram "stream".
pub trait RecvDatagrams {
    /// The type of `Buf` for data received on this stream.
    type Buf: Buf;
    /// The error type that can occur when receiving data.
    type Error: Into<Box<dyn Error>>;

    /// TODO
    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<Self::Buf, Self::Error>>>;
}

/// A trait describing the "receive" actions of a QUIC stream.
pub trait RecvStream {
    /// The type of `Buf` for data received on this stream.
    type Buf: Buf;
    /// The error type that can occur when receiving data.
    type Error: Into<Box<dyn Error>>;

    /// Poll the stream for more data.
    ///
    /// When the receive side will no longer receive more data (such as because
    /// the peer closed their sending side), this should return `None`.
    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, Self::Error>>;

    /// Send a `STOP_SENDING` QUIC code.
    fn stop_sending(&mut self, error_code: u64);
}

/// Optional trait to allow "splitting" a bidirectional stream into two sides.
pub trait BidiStream<B: Buf>: SendStream<B> + RecvStream {
    /// The type for the send half.
    type SendStream: SendStream<B>;
    /// The type for the receive half.
    type RecvStream: RecvStream;

    /// Split this stream into two halves.
    fn split(self) -> (Self::SendStream, Self::RecvStream);
}
