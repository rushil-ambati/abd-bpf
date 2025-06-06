//! Core network operations for ABD protocol benchmarking
//!
//! This module provides the fundamental network operations used by both latency
//! and throughput benchmarks. It handles ABD message serialization, network
//! communication, and response validation.

use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use abd_common::{
    constants::ABD_UDP_PORT,
    message::{AbdMessage, AbdMessageData, AbdMessageType, AbdRole, ArchivedAbdMessage},
};
use log::{debug, trace};
use rkyv::{access, deserialize, rancor::Error as RkyvError};

use crate::types::{BenchmarkError, BenchmarkResult};

/// Performs a write operation against the specified target node
///
/// Creates an ABD write message with the provided data, sends it to the target,
/// and waits for a `WriteAck` response. Measures the round-trip time.
///
/// # Arguments
///
/// * `target_ip` - IPv4 address of the target ABD node
/// * `data` - Data payload to write
/// * `timeout` - Maximum time to wait for response
///
/// # Returns
///
/// Round-trip latency in microseconds on success
pub fn perform_write_operation(
    target_ip: Ipv4Addr,
    data: &AbdMessageData,
    timeout: Duration,
) -> BenchmarkResult<f64> {
    trace!("Starting write operation to {target_ip}");

    // Create ABD write message
    let msg = AbdMessage::new(
        0,               // counter
        *data,           // data payload
        AbdRole::Writer, // recipient role
        0,               // sender_id
        AbdRole::Client, // sender role
        0,               // tag
        AbdMessageType::Write,
    );

    // Serialize message
    let payload = rkyv::to_bytes::<RkyvError>(&msg).map_err(|e| {
        BenchmarkError::Serialization(format!("Failed to serialize write message: {e}"))
    })?;

    // Create socket and configure timeout
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| BenchmarkError::Network(format!("Failed to bind UDP socket: {e}")))?;

    sock.set_read_timeout(Some(timeout))
        .map_err(|e| BenchmarkError::Network(format!("Failed to set socket timeout: {e}")))?;

    let target_addr = SocketAddrV4::new(target_ip, ABD_UDP_PORT);

    // Send request and measure timing
    let start = Instant::now();
    sock.send_to(&payload, target_addr)
        .map_err(|e| BenchmarkError::Network(format!("Failed to send write request: {e}")))?;

    // Receive response
    let mut buf = vec![0u8; 65_535].into_boxed_slice();
    let (n, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| BenchmarkError::Network(format!("Failed to receive write response: {e}")))?;

    let elapsed = start.elapsed();
    trace!("Write operation completed in {elapsed:?}");

    // Validate response
    validate_write_response(&buf[..n])?;

    Ok(elapsed.as_secs_f64() * 1_000_000.0) // Convert to microseconds
}

/// Performs a read operation against the specified target node
///
/// Creates an ABD read message, sends it to the target, and waits for a `ReadAck`
/// response. Measures the round-trip time.
///
/// # Arguments
///
/// * `target_ip` - IPv4 address of the target ABD node
/// * `timeout` - Maximum time to wait for response
///
/// # Returns
///
/// Round-trip latency in microseconds on success
pub fn perform_read_operation(target_ip: Ipv4Addr, timeout: Duration) -> BenchmarkResult<f64> {
    trace!("Starting read operation to {target_ip}");

    // Create ABD read message
    let msg = AbdMessage::new(
        0,                         // counter
        AbdMessageData::default(), // empty data for reads
        AbdRole::Reader,           // recipient role
        0,                         // sender_id
        AbdRole::Client,           // sender role
        0,                         // tag
        AbdMessageType::Read,
    );

    // Serialize message
    let payload = rkyv::to_bytes::<RkyvError>(&msg).map_err(|e| {
        BenchmarkError::Serialization(format!("Failed to serialize read message: {e}"))
    })?;

    // Create socket and configure timeout
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| BenchmarkError::Network(format!("Failed to bind UDP socket: {e}")))?;

    sock.set_read_timeout(Some(timeout))
        .map_err(|e| BenchmarkError::Network(format!("Failed to set socket timeout: {e}")))?;

    let target_addr = SocketAddrV4::new(target_ip, ABD_UDP_PORT);

    // Send request and measure timing
    let start = Instant::now();
    sock.send_to(&payload, target_addr)
        .map_err(|e| BenchmarkError::Network(format!("Failed to send read request: {e}")))?;

    // Receive response
    let mut buf = vec![0u8; 65_535].into_boxed_slice();
    let (n, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| BenchmarkError::Network(format!("Failed to receive read response: {e}")))?;

    let elapsed = start.elapsed();
    trace!("Read operation completed in {elapsed:?}");

    // Validate response
    validate_read_response(&buf[..n])?;

    Ok(elapsed.as_secs_f64() * 1_000_000.0) // Convert to microseconds
}

/// Validates a write response message
///
/// Deserializes the response and verifies it's a proper `WriteAck` message.
fn validate_write_response(buf: &[u8]) -> BenchmarkResult<()> {
    let archived = access::<ArchivedAbdMessage, RkyvError>(buf)
        .map_err(|e| BenchmarkError::Protocol(format!("Failed to access write response: {e}")))?;

    let resp: AbdMessage = deserialize::<AbdMessage, RkyvError>(archived).map_err(|e| {
        BenchmarkError::Protocol(format!("Failed to deserialize write response: {e}"))
    })?;

    match AbdMessageType::try_from(resp.type_) {
        Ok(AbdMessageType::WriteAck) => {
            debug!("Received valid WriteAck from node {}", resp.sender_id);
            Ok(())
        }
        Ok(other) => Err(BenchmarkError::Protocol(format!(
            "Expected WriteAck, received {other:?}"
        ))),
        Err(()) => Err(BenchmarkError::Protocol(format!(
            "Invalid message type: {}",
            resp.type_
        ))),
    }
}

/// Validates a read response message
///
/// Deserializes the response and verifies it's a proper `ReadAck` message.
fn validate_read_response(buf: &[u8]) -> BenchmarkResult<()> {
    let archived = access::<ArchivedAbdMessage, RkyvError>(buf)
        .map_err(|e| BenchmarkError::Protocol(format!("Failed to access read response: {e}")))?;

    let resp: AbdMessage = deserialize::<AbdMessage, RkyvError>(archived).map_err(|e| {
        BenchmarkError::Protocol(format!("Failed to deserialize read response: {e}"))
    })?;

    match AbdMessageType::try_from(resp.type_) {
        Ok(AbdMessageType::ReadAck) => {
            debug!(
                "Received valid ReadAck from node {} with data: {}",
                resp.sender_id, resp.data
            );
            Ok(())
        }
        Ok(other) => Err(BenchmarkError::Protocol(format!(
            "Expected ReadAck, received {other:?}"
        ))),
        Err(()) => Err(BenchmarkError::Protocol(format!(
            "Invalid message type: {}",
            resp.type_
        ))),
    }
}

/// Creates a socket with appropriate timeout settings for throughput benchmarks
///
/// Configures a UDP socket with the specified timeout for use in high-throughput
/// scenarios where requests may be sent rapidly.
pub fn create_throughput_socket(timeout: Duration) -> BenchmarkResult<UdpSocket> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| BenchmarkError::Network(format!("Failed to bind throughput socket: {e}")))?;

    sock.set_read_timeout(Some(timeout))
        .map_err(|e| BenchmarkError::Network(format!("Failed to set socket timeout: {e}")))?;

    Ok(sock)
}

/// Sends a pre-serialized message via the provided socket
///
/// Used in throughput benchmarks where message serialization is done once
/// and the same payload is sent repeatedly for efficiency.
pub fn send_message(sock: &UdpSocket, payload: &[u8], target: SocketAddrV4) -> BenchmarkResult<()> {
    sock.send_to(payload, target)
        .map_err(|e| BenchmarkError::Network(format!("Failed to send message: {e}")))?;
    Ok(())
}

/// Receives and validates a response for throughput benchmarks
///
/// Returns true if a valid `WriteAck` was received, false for timeouts or invalid responses.
/// This is optimized for throughput scenarios where we want to quickly categorize responses.
pub fn receive_and_validate_response(sock: &UdpSocket, buf: &mut [u8]) -> BenchmarkResult<bool> {
    match sock.recv_from(buf) {
        Ok((n, _)) => {
            // Quick validation - just check if it's a WriteAck
            access::<ArchivedAbdMessage, RkyvError>(&buf[..n]).map_or_else(
                |_| Ok(false),
                |archived| {
                    deserialize::<AbdMessage, RkyvError>(archived).map_or_else(
                        |_| Ok(false),
                        |resp| {
                            Ok(
                                AbdMessageType::try_from(resp.type_)
                                    == Ok(AbdMessageType::WriteAck),
                            )
                        },
                    )
                },
            )
        }
        Err(ref e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(false) // Timeout
        }
        Err(e) => Err(BenchmarkError::Network(format!("Receive error: {e}"))),
    }
}

/// Performs a fast write operation optimized for throughput benchmarks
///
/// This is an optimized version of `perform_write_operation` that uses default
/// empty data and focuses on speed rather than detailed error reporting.
/// Used in throughput benchmarks where the same operation is repeated many times.
///
/// # Arguments
///
/// * `target_ip` - IPv4 address of the target ABD node
/// * `timeout_ms` - Timeout in milliseconds
///
/// # Returns
///
/// Returns Ok(()) on successful `WriteAck`, Err on any failure
pub fn perform_write_operation_fast(target_ip: Ipv4Addr, timeout_ms: u64) -> BenchmarkResult<()> {
    // Create ABD write message with default empty data
    let msg = AbdMessage::new(
        0,                         // counter
        AbdMessageData::default(), // empty data for throughput testing
        AbdRole::Writer,           // recipient role
        0,                         // sender_id
        AbdRole::Client,           // sender role
        0,                         // tag
        AbdMessageType::Write,
    );

    // Serialize message (could be cached for even better performance)
    let payload = rkyv::to_bytes::<RkyvError>(&msg).map_err(|e| {
        BenchmarkError::Serialization(format!("Failed to serialize write message: {e}"))
    })?;

    // Create socket with timeout
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| BenchmarkError::Network(format!("Failed to bind UDP socket: {e}")))?;

    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| BenchmarkError::Network(format!("Failed to set socket timeout: {e}")))?;

    let target_addr = SocketAddrV4::new(target_ip, ABD_UDP_PORT);

    // Send request
    sock.send_to(&payload, target_addr)
        .map_err(|e| BenchmarkError::Network(format!("Failed to send write request: {e}")))?;

    // Receive and validate response quickly
    let mut buf = vec![0u8; 65_535].into_boxed_slice();
    let (n, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| BenchmarkError::Network(format!("Failed to receive write response: {e}")))?;

    // Quick validation
    validate_write_response(&buf[..n])?;
    Ok(())
}

/// Performs a fast read operation optimized for throughput benchmarks
///
/// This is an optimized version of `perform_read_operation` that focuses on
/// speed rather than detailed error reporting.
///
/// # Arguments
///
/// * `target_ip` - IPv4 address of the target ABD node
/// * `timeout_ms` - Timeout in milliseconds
///
/// # Returns
///
/// Returns Ok(()) on successful `ReadAck`, Err on any failure
pub fn perform_read_operation_fast(target_ip: Ipv4Addr, timeout_ms: u64) -> BenchmarkResult<()> {
    // Create ABD read message
    let msg = AbdMessage::new(
        0,                         // counter
        AbdMessageData::default(), // empty data for reads
        AbdRole::Reader,           // recipient role
        0,                         // sender_id
        AbdRole::Client,           // sender role
        0,                         // tag
        AbdMessageType::Read,
    );

    // Serialize message
    let payload = rkyv::to_bytes::<RkyvError>(&msg).map_err(|e| {
        BenchmarkError::Serialization(format!("Failed to serialize read message: {e}"))
    })?;

    // Create socket with timeout
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| BenchmarkError::Network(format!("Failed to bind UDP socket: {e}")))?;

    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| BenchmarkError::Network(format!("Failed to set socket timeout: {e}")))?;

    let target_addr = SocketAddrV4::new(target_ip, ABD_UDP_PORT);

    // Send request
    sock.send_to(&payload, target_addr)
        .map_err(|e| BenchmarkError::Network(format!("Failed to send read request: {e}")))?;

    // Receive and validate response quickly
    let mut buf = vec![0u8; 65_535].into_boxed_slice();
    let (n, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| BenchmarkError::Network(format!("Failed to receive read response: {e}")))?;

    // Quick validation
    validate_read_response(&buf[..n])?;
    Ok(())
}

/// Performs a timed operation (read or write) and returns the latency
///
/// Used for latency tracking during throughput benchmarks.
///
/// # Arguments
///
/// * `target_ip` - IPv4 address of the target ABD node
/// * `timeout_ms` - Timeout in milliseconds
/// * `is_write` - True for write operation, false for read operation
///
/// # Returns
///
/// Returns latency in microseconds on success, Err on any failure
pub fn perform_timed_operation(
    target_ip: Ipv4Addr,
    timeout_ms: u64,
    is_write: bool,
) -> BenchmarkResult<f64> {
    let start = std::time::Instant::now();

    let result = if is_write {
        perform_write_operation_fast(target_ip, timeout_ms)
    } else {
        perform_read_operation_fast(target_ip, timeout_ms)
    };

    let elapsed = start.elapsed();

    match result {
        Ok(()) => Ok(elapsed.as_secs_f64() * 1_000_000.0), // Convert to microseconds
        Err(e) => Err(e),
    }
}
