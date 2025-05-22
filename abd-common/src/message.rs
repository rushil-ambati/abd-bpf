use core::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use heapless::{FnvIndexMap, String as HString};
use rkyv::{rend::u32_le, Archive, Deserialize, Serialize};

use crate::constants::ABD_MAGIC;

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
    /// Data associated with the message.
    pub data: AbdMessageData,
}
impl AbdMessage {
    /// Constructs a new `AbdMessage` with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `sender` - The sender node's identifier.
    /// * `ty` - The type of ABD message.
    /// * `tag` - The logical tag for the operation.
    /// * `data` - The data associated with the operation.
    /// * `counter` - The version or ordering counter.
    #[must_use]
    #[inline]
    pub fn new(
        counter: u64,
        sender: u32,
        tag: u64,
        type_: AbdMessageType,
        data: AbdMessageData,
    ) -> Self {
        Self {
            counter,
            magic: ABD_MAGIC,
            sender,
            tag,
            type_: type_.into(),
            data,
        }
    }
}

/// Enum representing the type of ABD protocol message.
///
/// We don't use rkyv here because we want to use the enum as a u32 (so we can `bpf_csum_diff` on it)
/// See <https://github.com/rkyv/rkyv/issues/482#issuecomment-2351618161>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(C)]
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

/// Contents of an ABD message
#[derive(rkyv::Archive, Copy, Clone, rkyv::Deserialize, rkyv::Serialize, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AbdMessageData {
    int: i64,
    text: [u8; 8],
    ip: IpAddr,
    duration: Duration,
    point: (f32, f32),
    char_opt: Option<char>,
    person: [u8; 128],
    hashmap: [u8; 1024],
}
impl Default for AbdMessageData {
    #[inline]
    fn default() -> Self {
        Self {
            int: 0,
            text: [0; 8],
            ip: Ipv4Addr::UNSPECIFIED.into(),
            duration: Duration::ZERO,
            point: (0.0, 0.0),
            char_opt: None,
            person: [0; 128],
            hashmap: [0; 1024],
        }
    }
}

#[cfg(feature = "user")]
impl std::str::FromStr for AbdMessageData {
    type Err = String;

    /// Parses a structured string like:
    /// `int=42 text=hello ip=192.168.1.100 duration=5 point=(1.5,2.0) char_opt=Z person=(Bob,27) hashmap={author:Bob;version:1.0;license:MIT}`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut v = Self::default();

        for token in s.split_whitespace() {
            let (key, val) = token
                .split_once('=')
                .ok_or_else(|| format!("Invalid entry: {token}"))?;

            match key {
                "int" => v.int = val.parse().unwrap_or(0),
                "text" => {
                    let bytes = val.as_bytes();
                    let len = core::cmp::min(bytes.len(), 8);
                    v.text[..len].copy_from_slice(&bytes[..len]);
                    v.text[len..].fill(0);
                }
                "ip" => v.ip = val.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                "duration" => {
                    let secs = val.parse().unwrap_or(0);
                    v.duration = Duration::from_secs(secs);
                }
                "point" => {
                    let val = val.trim_matches(|c| c == '(' || c == ')');
                    if let Some((x, y)) = val.split_once(',') {
                        v.point = (
                            x.trim().parse().unwrap_or(0.0),
                            y.trim().parse().unwrap_or(0.0),
                        );
                    }
                }
                "char_opt" => {
                    v.char_opt = val.chars().next();
                }
                "person" => {
                    let val = val.trim_matches(|c| c == '(' || c == ')');
                    if let Some((name_str, age_str)) = val.split_once(',') {
                        let mut name = heapless::String::new();
                        name.push_str(name_str.trim())
                            .map_err(|()| "Name too long")?;
                        let age = age_str.trim().parse().unwrap_or(0);
                        let person = Person { name, age };
                        serde_json_core::to_slice(&person, &mut v.person)
                            .map_err(|e| format!("JSON encode error: {e:?}"))?;
                    }
                }
                "hashmap" => {
                    let val = val.trim_matches(|c| c == '{' || c == '}');

                    let mut map = ShortStringMap::new();

                    for entry in val.split(';') {
                        if let Some((k, v)) = entry.split_once(':') {
                            let mut key = HString::new();
                            let mut val = HString::new();
                            key.push_str(k.trim()).map_err(|()| "Key too long")?;
                            val.push_str(v.trim()).map_err(|()| "Value too long")?;
                            map.insert(key, val).map_err(|_| "Map too full")?;
                        }
                    }

                    let _ = postcard::to_slice(&map, &mut v.hashmap)
                        .map_err(|e| format!("JSON encode error (map): {e:?}"))?;
                }
                _ => return Err(format!("Unknown field: {key}")),
            }
        }
        Ok(v)
    }
}

impl core::fmt::Display for AbdMessageData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = core::str::from_utf8(&self.text)
            .unwrap_or("Invalid UTF-8")
            .trim_end_matches('\0');

        let person: Option<Person> = self.person.iter().position(|&b| b == b'}').and_then(|end| {
            serde_json_core::from_slice(&self.person[..=end])
                .ok()
                .map(|(p, _)| p)
        });

        let map: ShortStringMap =
            postcard::from_bytes(&self.hashmap).unwrap_or_else(|_| ShortStringMap::new());

        writeln!(f, "AbdMessageData {{")?;
        writeln!(f, "    int:        {},", self.int)?;
        writeln!(f, "    text:       \"{}\",", text)?;
        writeln!(f, "    ip:         {},", self.ip)?;
        writeln!(f, "    duration:   {:#?},", self.duration)?;
        writeln!(f, "    point:      ({}, {}),", self.point.0, self.point.1)?;
        writeln!(f, "    char_opt:   {:#?},", self.char_opt)?;
        writeln!(f, "    person:     {:?},", person)?;
        writeln!(f, "    hashmap:    {:?},", map)?;
        write!(f, "}}")
    }
}

/// JSON-encoded person metadata
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Person {
    name: heapless::String<8>,
    age: u8,
}

type ShortStringMap = FnvIndexMap<HString<8>, HString<8>, 4>;
