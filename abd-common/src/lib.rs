//! Common types and constants for the ABD (Attiya, Bar-Noy, Dolev) protocol implementation.
//!
//! This crate provides shared definitions for both kernel and user-space components,
//! including message types, serialization, and network node/client information.

#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
extern crate std;

use core::{
    cmp::min,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    time::Duration,
};

use rkyv::{rend::u32_le, Archive, Deserialize, Serialize};

/// Prefix for network interface names assigned to ABD nodes.
pub const ABD_IFACE_NODE_PREFIX: &str = "node";

/// Name of the network interface used by the ABD writer node.
pub const ABD_IFACE_WRITER: &str = "writer";

/// Magic number used to identify valid ABD messages.
pub const ABD_MAGIC: u32 = 0xdead_beef;

/// Maximum number of nodes supported in the ABD protocol.
pub const ABD_MAX_NODES: u32 = 16;

/// UDP port used by the ABD server for communication.
pub const ABD_SERVER_UDP_PORT: u16 = 4243;

/// UDP port used for ABD protocol communication between nodes.
pub const ABD_UDP_PORT: u16 = 4242;

/// Identifier for the ABD writer node.
pub const ABD_WRITER_ID: u32 = 0;

/// Structure representing an ABD protocol message.
///
/// This struct is serializable with `rkyv` for zero-copy deserialization.
#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
#[non_exhaustive]
pub struct AbdMsg {
    /// Counter for versioning or ordering.
    pub counter: u64,
    /// Magic number for message validation.
    pub magic: u32,
    /// Sender node identifier.
    pub sender: u32,
    /// Logical tag for the operation.
    pub tag: u64,
    /// Message type as a `u32` (see [`AbdMsgType`]).
    pub type_: u32,
    /// Value associated with the operation.
    pub value: AbdValue,
}
impl AbdMsg {
    /// Constructs a new `AbdMsg` with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `sender` - The sender node's identifier.
    /// * `ty` - The type of ABD message.
    /// * `tag` - The logical tag for the operation.
    /// * `value` - The value associated with the operation.
    /// * `counter` - The version or ordering counter.
    #[must_use]
    #[inline]
    pub fn new(sender: u32, type_: AbdMsgType, tag: u64, value: AbdValue, counter: u64) -> Self {
        Self {
            magic: ABD_MAGIC,
            sender,
            type_: type_.into(),
            tag,
            value,
            counter,
        }
    }
}

impl AbdMsgType {
    /// Converts a `u32` value to an `AbdMsgType` if possible.
    ///
    /// Returns `Some(AbdMsgType)` if the value matches a known message type,
    /// or `None` otherwise.
    const fn from_u32(value: u32) -> Option<Self> {
        match value {
            _ if value == Self::Read as u32 => Some(Self::Read),
            _ if value == Self::Write as u32 => Some(Self::Write),
            _ if value == Self::ReadAck as u32 => Some(Self::ReadAck),
            _ if value == Self::WriteAck as u32 => Some(Self::WriteAck),
            _ => None,
        }
    }
}
impl From<AbdMsgType> for u32 {
    /// Converts an `AbdMsgType` to its corresponding `u32` representation.
    #[inline]
    fn from(val: AbdMsgType) -> Self {
        val as Self
    }
}
impl From<AbdMsgType> for u32_le {
    /// Converts an `AbdMsgType` to its little-endian `u32_le` representation.
    #[inline]
    fn from(val: AbdMsgType) -> Self {
        (val as u32).into()
    }
}
impl TryFrom<u32> for AbdMsgType {
    type Error = ();

    /// Attempts to convert a `u32` to an `AbdMsgType`.
    ///
    /// Returns `Ok(AbdMsgType)` if the value matches a known message type,
    /// or `Err(())` otherwise.
    #[inline]
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::from_u32(value).ok_or(())
    }
}

/// Enum representing the type of ABD protocol message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AbdMsgType {
    /// Read request message.
    Read = 1,
    /// Acknowledgement for a read operation.
    ReadAck = 2,
    /// Write request message.
    Write = 3,
    /// Acknowledgement for a write operation.
    WriteAck = 4,
}

/// Value type stored in the ABD system.
#[derive(Archive, Copy, Clone, Deserialize, Serialize, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AbdValue {
    primitive: i64,
    byte_array: [u8; 8],
    ip_address: IpAddr,
    duration: Duration,
    tuple: (f32, f32),
    optional: Option<char>,
}
impl Default for AbdValue {
    /// Constructs a default `AbdValue` with all fields set to zero or empty.
    #[inline]
    fn default() -> Self {
        Self {
            primitive: 0,
            byte_array: [0; 8],
            ip_address: Ipv4Addr::UNSPECIFIED.into(),
            duration: Duration::ZERO,
            tuple: (0., 0.),
            optional: None,
        }
    }
}
impl From<&str> for AbdValue {
    /// Converts a string like `"1234,abc,192.168.1.1,7,0.25,1.85,!"` to an `AbdValue`.
    /// Expects a comma-separated string containing values in the following order:
    /// - u64 primitive
    /// - up to 8-byte string into byte_array
    /// - an IP address (v4 or v6)
    /// - a whole number for duration in seconds
    /// - an f32 value which wil be the first element of the tuple
    /// - an f32 value which wil be the second element of the tuple
    /// - an optional character
    fn from(s: &str) -> Self {
        let mut parts = s.split(',');

        let primitive = if let Some(part) = parts.next() {
            i64::from_str(part.trim()).unwrap_or(0)
        } else {
            0
        };

        let mut byte_array = [0u8; 8];
        if let Some(part) = parts.next() {
            let bytes = part.trim().as_bytes();
            let len = min(bytes.len(), 8);
            byte_array[..len].copy_from_slice(&bytes[..len]);
        }

        let ip_address: IpAddr = if let Some(part) = parts.next() {
            IpAddr::from_str(part.trim()).unwrap_or(Ipv4Addr::UNSPECIFIED.into())
        } else {
            Ipv4Addr::UNSPECIFIED.into()
        };

        let duration = if let Some(part) = parts.next() {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                Duration::ZERO
            } else {
                Duration::from_secs(trimmed.parse().unwrap_or(0))
            }
        } else {
            Duration::ZERO
        };

        let mut tuple = (0., 0.);
        if let Some(part) = parts.next() {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                tuple.0 = 0.;
            } else {
                tuple.0 = trimmed.parse().unwrap_or(0.);
            }
        }
        if let Some(part) = parts.next() {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                tuple.1 = 0.;
            } else {
                tuple.1 = trimmed.parse().unwrap_or(0.);
            }
        }

        let optional: Option<char> = if let Some(part) = parts.next() {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.chars().next().unwrap())
            }
        } else {
            None
        };

        Self {
            primitive,
            byte_array,
            ip_address,
            duration,
            tuple,
            optional,
        }
    }
}

/// Information about a network node participating in the ABD protocol.
///
/// This struct is `#[repr(C)]` for FFI compatibility.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct NodeInfo {
    /// Network interface index.
    pub ifindex: u32,
    /// IPv4 address of the node.
    pub ipv4: Ipv4Addr,
    /// MAC address of the node.
    pub mac: [u8; 6],
}
impl NodeInfo {
    /// Constructs a new `NodeInfo` with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - The network interface index.
    /// * `ipv4` - The IPv4 address of the node.
    /// * `mac` - The MAC address of the node.
    #[must_use]
    #[inline]
    pub const fn new(ifindex: u32, ipv4: Ipv4Addr, mac: [u8; 6]) -> Self {
        Self { ifindex, ipv4, mac }
    }
}
#[expect(
    clippy::undocumented_unsafe_blocks,
    reason = "unsafe because of Pod trait"
)]
#[cfg(feature = "user")]
unsafe impl aya::Pod for NodeInfo {}

/// Information about a client in the ABD protocol.
///
/// This struct is `#[repr(C)]` for FFI compatibility.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct ClientInfo {
    /// Network interface index.
    pub ifindex: u32,
    /// IPv4 address of the client.
    pub ipv4: Ipv4Addr,
    /// MAC address of the client.
    pub mac: [u8; 6],
    /// UDP port used by the client.
    pub port: u16,
}

impl ClientInfo {
    /// Constructs a new `ClientInfo` with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - The network interface index.
    /// * `ipv4` - The IPv4 address of the client.
    /// * `mac` - The MAC address of the client.
    /// * `port` - The UDP port used by the client.
    #[must_use]
    #[inline]
    pub const fn new(ifindex: u32, ipv4: Ipv4Addr, mac: [u8; 6], port: u16) -> Self {
        Self {
            ifindex,
            ipv4,
            mac,
            port,
        }
    }
}
