use core::{
    cmp::min,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    time::Duration,
};

use rkyv::{Archive, Deserialize, Serialize};

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
