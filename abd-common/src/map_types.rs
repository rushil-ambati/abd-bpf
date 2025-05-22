use core::net::Ipv4Addr;

use crate::message::ArchivedAbdMessageData;

pub type SpinLock = u64;
pub type Tag = Locked<u64>;
pub type Counter = Locked<u64>;
pub type Status = Locked<u8>; // Each actor defines its own status codes, but zero is always considered "active and idle"

/// A generic tagged entry with a lock and a value of any type.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Locked<T> {
    pub lock: SpinLock,
    pub val: T,
}
impl<T: Default> Default for Locked<T> {
    #[inline]
    fn default() -> Self {
        Self {
            lock: 0,
            val: T::default(),
        }
    }
}

/// A tagged/timestamped data entry to be stored on a replica server.
/// The object lock is inside the `tag`.
#[repr(C)]
pub struct TagValue {
    pub tag: Tag,
    pub data: ArchivedAbdMessageData,
}

/// Information about a network node participating in the ABD protocol.
///
/// This struct is `#[repr(C)]` for FFI compatibility.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
#[repr(C)]
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
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
#[repr(C)]
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
