#![no_std]

use rkyv::{Archive, Deserialize, Serialize};

pub const ABD_UDP_PORT: u16 = 4242; // UDP port used for ABD messages
pub const ABD_MAGIC: u32 = 0xdeadbeef;

#[derive(Debug, Eq, PartialEq)]
pub enum AbdMsgType {
    Read,
    Write,
    ReadAck,
    WriteAck,
}

impl TryFrom<u8> for AbdMsgType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == AbdMsgType::Read as u8 => Ok(Self::Read),
            x if x == AbdMsgType::Write as u8 => Ok(Self::Write),
            x if x == AbdMsgType::ReadAck as u8 => Ok(Self::ReadAck),
            x if x == AbdMsgType::WriteAck as u8 => Ok(Self::WriteAck),
            _ => Err(()),
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AbdMsg {
    pub magic: u32,
    pub sender: u8,
    pub type_: u8,
    pub tag: u32,
    pub value: u32,
    pub counter: u32,
}

impl AbdMsg {
    pub fn new(sender: u8, ty: AbdMsgType, tag: u32, value: u32, counter: u32) -> Self {
        Self {
            magic: ABD_MAGIC,
            sender,
            type_: ty as u8,
            tag,
            value,
            counter,
        }
    }
}
