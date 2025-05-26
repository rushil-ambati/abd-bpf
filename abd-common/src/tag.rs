/// The upper 32 bits are the **sequence number**,
/// the lower 32 bits are the **writer id**.
/// Using `default()` is fine, as it will yield `0` for both parts.
pub type AbdTag = u64;

#[inline(always)]
#[must_use]
pub const fn pack(seq: u32, wid: u32) -> AbdTag {
    ((seq as u64) << 32) | wid as u64
}

#[inline(always)]
#[must_use]
pub const fn seq(tag: AbdTag) -> u32 {
    (tag >> 32) as u32
}

#[allow(clippy::cast_possible_truncation)]
#[inline(always)]
#[must_use]
pub const fn wid(tag: AbdTag) -> u32 {
    tag as u32
}

/// `a > b` according to the lexicographic order
#[inline(always)]
#[must_use]
pub const fn gt(a: AbdTag, b: AbdTag) -> bool {
    let sa = seq(a);
    let sb = seq(b);
    sa > sb || (sa == sb && wid(a) > wid(b))
}

/// Increase the sequence part and keep the writer-id.
#[inline(always)]
#[must_use]
pub const fn bump_seq(tag: u64) -> u64 {
    pack(seq(tag) + 1, wid(tag))
}
