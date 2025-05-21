use rkyv::{rend::u32_le, Archive, Deserialize, Serialize};

use crate::{constants::ABD_MAGIC, value::AbdValue};

/// Structure representing an ABD protocol message.
///
/// This struct is serializable with `rkyv` for zero-copy deserialization.
#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(derive(Debug))]
#[non_exhaustive]
pub struct AbdMessage {
    /// Counter for versioning or ordering.
    pub counter: u64,
    /// Magic number for message validation.
    pub magic: u32,
    /// Sender node identifier.
    pub sender: u32,
    /// Logical tag for the operation.
    pub tag: u64,
    /// Message type.
    pub type_: u32,
    /// Value associated with the operation.
    pub value: AbdValue,
}
impl AbdMessage {
    /// Constructs a new `AbdMessage` with the given parameters.
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
    pub fn new(
        counter: u64,
        sender: u32,
        tag: u64,
        type_: AbdMessageType,
        value: AbdValue,
    ) -> Self {
        Self {
            counter,
            magic: ABD_MAGIC,
            sender,
            tag,
            type_: type_.into(),
            value,
        }
    }
}

/// Enum representing the type of ABD protocol message.
/// We don't use rkyv here because we want to use the enum as a u32 (so we can bpf_csum_diff on it)
/// See <https://github.com/rkyv/rkyv/issues/482#issuecomment-2351618161>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AbdMessageType {
    /// Read request message.
    Read = 1,
    /// Acknowledgement for a read operation.
    ReadAck = 2,
    /// Write request message.
    Write = 3,
    /// Acknowledgement for a write operation.
    WriteAck = 4,
}
impl AbdMessageType {
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
impl From<AbdMessageType> for u32 {
    /// Converts an `AbdMsgType` to its corresponding `u32` representation.
    #[inline]
    fn from(val: AbdMessageType) -> Self {
        val as Self
    }
}
impl From<AbdMessageType> for u32_le {
    /// Converts an `AbdMsgType` to its little-endian `u32_le` representation.
    #[inline]
    fn from(val: AbdMessageType) -> Self {
        (val as u32).into()
    }
}
impl TryFrom<u32> for AbdMessageType {
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
