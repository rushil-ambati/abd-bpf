use core::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

/// Value type stored in the ABD system.
#[derive(rkyv::Archive, Copy, Clone, rkyv::Deserialize, rkyv::Serialize, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AbdValue {
    int: i64,
    text: [u8; 8],
    ip: IpAddr,
    duration: Duration,
    point: (f32, f32),
    char_opt: Option<char>,
    person: [u8; 128],
    hashmap: [u8; 1024],
}
impl Default for AbdValue {
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
impl std::str::FromStr for AbdValue {
    type Err = String;

    /// Parses a structured string like:
    /// `int=42 text=hello ip=192.168.1.100 duration=5 point=(1.5,2.0) char_opt=Z person=(Bob,27) hashmap={author:Bob;version:1.0;license:MIT}`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut v = Self::default();

        for token in s.split_whitespace() {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| format!("Invalid entry: {token}"))?;

            match key {
                "int" => v.int = value.parse().unwrap_or(0),
                "text" => {
                    let bytes = value.as_bytes();
                    let len = core::cmp::min(bytes.len(), 8);
                    v.text[..len].copy_from_slice(&bytes[..len]);
                    v.text[len..].fill(0);
                }
                "ip" => v.ip = value.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                "duration" => {
                    let secs = value.parse().unwrap_or(0);
                    v.duration = Duration::from_secs(secs);
                }
                "point" => {
                    let val = value.trim_matches(|c| c == '(' || c == ')');
                    if let Some((x, y)) = val.split_once(',') {
                        v.point = (
                            x.trim().parse().unwrap_or(0.0),
                            y.trim().parse().unwrap_or(0.0),
                        );
                    }
                }
                "char_opt" => {
                    v.char_opt = value.chars().next();
                }
                "person" => {
                    let val = value.trim_matches(|c| c == '(' || c == ')');
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
                    let val = value.trim_matches(|c| c == '{' || c == '}');

                    let mut map = MetaMap::new();

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

#[cfg(feature = "user")]
impl core::fmt::Display for AbdValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = core::str::from_utf8(&self.text)
            .unwrap_or("Invalid UTF-8")
            .trim_end_matches('\0');

        let person: Option<Person> = self.person.iter().position(|&b| b == b'}').and_then(|end| {
            serde_json_core::from_slice(&self.person[..=end])
                .ok()
                .map(|(p, _)| p)
        });

        writeln!(
            f,
            "AbdValue {{
int: {},
text: {},
ip: {},
duration: {:?},
point: ({}, {}),
char_opt: {:?},
person: {:?},",
            self.int,
            text,
            self.ip,
            self.duration,
            self.point.0,
            self.point.1,
            self.char_opt,
            person
        )?;

        let map: MetaMap = postcard::from_bytes(&self.hashmap)
            .map_err(|_| core::fmt::Error)
            .unwrap_or(MetaMap::new());

        writeln!(f, "hashmap: [")?;
        for (k, v) in &map {
            writeln!(f, "    {k}: {v},")?;
        }
        writeln!(f, "]")?;

        write!(f, "}}")
    }
}

#[cfg(feature = "user")]
use heapless::{FnvIndexMap, String as HString};

#[cfg(feature = "user")]
type MetaMap = FnvIndexMap<HString<8>, HString<8>, 4>; // key: up to 8 bytes, value: up to 8 bytes, max 4 entries

/// JSON-encoded person metadata
#[cfg(feature = "user")]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Person {
    name: heapless::String<8>,
    age: u8,
}
