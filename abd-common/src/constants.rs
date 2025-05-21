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
