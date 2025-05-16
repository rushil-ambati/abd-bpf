#![no_std]

use core::net::Ipv4Addr;

use rkyv::{rend::u32_le, Archive, Deserialize, Serialize};

pub const ABD_SERVER_IFACE_PREFIX: &str = "server";
pub const ABD_WRITER_IFACE_NAME: &str = "writer";
pub const ABD_WRITER_ID: u32 = 0;
pub const ABD_UDP_PORT: u16 = 4242;
pub const ABD_SERVER_UDP_PORT: u16 = 4243;
pub const ABD_MAGIC: u32 = 0xdeadbeef;

#[derive(Debug, Eq, PartialEq)]
pub enum AbdMsgType {
    Read,
    Write,
    ReadAck,
    WriteAck,
}

impl AbdMsgType {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            x if x == AbdMsgType::Read as u32 => Some(Self::Read),
            x if x == AbdMsgType::Write as u32 => Some(Self::Write),
            x if x == AbdMsgType::ReadAck as u32 => Some(Self::ReadAck),
            x if x == AbdMsgType::WriteAck as u32 => Some(Self::WriteAck),
            _ => None,
        }
    }
}

impl From<AbdMsgType> for u32 {
    fn from(val: AbdMsgType) -> Self {
        val as u32
    }
}

impl From<AbdMsgType> for u32_le {
    fn from(val: AbdMsgType) -> Self {
        (val as u32).into()
    }
}

impl TryFrom<u32> for AbdMsgType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        AbdMsgType::from_u32(value).ok_or(())
    }
}

impl TryFrom<u32_le> for AbdMsgType {
    type Error = ();

    fn try_from(value: u32_le) -> Result<Self, Self::Error> {
        AbdMsgType::from_u32(value.into()).ok_or(())
    }
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AbdMsg {
    pub _magic: u32,
    pub sender: u32,
    pub type_: u32,
    pub tag: u64,
    pub value: u64,
    pub counter: u64,
}

impl AbdMsg {
    pub fn new(sender: u32, ty: AbdMsgType, tag: u64, value: u64, counter: u64) -> Self {
        Self {
            _magic: ABD_MAGIC,
            sender,
            type_: ty as u32,
            tag,
            value,
            counter,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AbdActorInfo {
    pub ipv4: Ipv4Addr,
    pub ifindex: u32,
    pub mac: [u8; 6],
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for AbdActorInfo {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ClientInfo {
    pub ipv4: Ipv4Addr,
    pub ifindex: u32,
    pub port: u16,
    pub mac: [u8; 6],
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ClientInfo {}
