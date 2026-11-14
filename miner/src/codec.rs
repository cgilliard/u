//! Reading and writing the byte encodings: integers little-endian, field
//! elements in their four-byte canonical form. A reader takes what it
//! reads from the front of a slice and returns the rest, or `None` for a
//! slice too short or an element not below the modulus.

use crate::hash::Digest;
use crate::poseidon2::{DIGEST, Fp, digest_from_bytes};

/// Serialized size of one field element.
pub const FP_BYTES: usize = 4;
/// Serialized size of a digest.
pub const DIGEST_BYTES: usize = DIGEST * FP_BYTES;

/// Serialized size of an output's position where blocks carry one: six
/// bytes, for positions below `2^48`. The chain holds `2^41` outputs at
/// most ([`crate::output::OUTPUT_CAPACITY`]), which five bytes fall short of.
pub const POSITION_BYTES: usize = 6;

/// Reads a position of [`POSITION_BYTES`] from the front of `bytes`.
pub fn read_position(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (head, rest) = bytes.split_at_checked(POSITION_BYTES)?;
    let mut buf = [0u8; 8];
    buf[..POSITION_BYTES].copy_from_slice(head);
    Some((u64::from_le_bytes(buf), rest))
}

/// Writes `position` to `out`, which must be [`POSITION_BYTES`] long.
/// Panics for a position that does not fit: none is cut short silently.
pub fn write_position(out: &mut [u8], position: u64) {
    assert!(position >> (8 * POSITION_BYTES) == 0, "position {position} does not fit {POSITION_BYTES} bytes");
    out.copy_from_slice(&position.to_le_bytes()[..POSITION_BYTES]);
}

pub fn read_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_at_checked(4)?;
    Some((u32::from_le_bytes(head.try_into().unwrap()), rest))
}

pub fn read_u64(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (head, rest) = bytes.split_at_checked(8)?;
    Some((u64::from_le_bytes(head.try_into().unwrap()), rest))
}

pub fn read_digest(bytes: &[u8]) -> Option<(Digest, &[u8])> {
    let (head, rest) = bytes.split_at_checked(DIGEST_BYTES)?;
    Some((digest_from_bytes(head)?, rest))
}

/// Parses `N` canonical field elements from the front of `bytes`, returning
/// them and the remaining slice. Fails on short input or non-canonical values.
pub fn read_fps<const N: usize>(bytes: &[u8]) -> Option<([Fp; N], &[u8])> {
    let (head, rest) = bytes.split_at_checked(N * FP_BYTES)?;
    let mut out = [Fp::ZERO; N];
    for (x, c) in out.iter_mut().zip(head.chunks_exact(FP_BYTES)) {
        *x = Fp::from_le_bytes(c.try_into().unwrap())?;
    }
    Some((out, rest))
}

/// Writes `fps` to the front of `out`, four bytes each, and returns the
/// rest of `out`. Panics if `out` is too short.
pub fn write_fps<'a>(out: &'a mut [u8], fps: &[Fp]) -> &'a mut [u8] {
    let (head, rest) = out.split_at_mut(fps.len() * FP_BYTES);
    for (c, x) in head.chunks_exact_mut(FP_BYTES).zip(fps) {
        c.copy_from_slice(&x.to_le_bytes());
    }
    rest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::P;

    /// Each reader takes its bytes from the front and hands back the rest;
    /// a slice too short, or an element not below the modulus, is refused.
    #[test]
    fn readers_take_from_the_front() {
        let bytes: Vec<u8> = (1..=50).collect();
        assert_eq!(read_u32(&bytes), Some((0x0403_0201, &bytes[4..])));
        assert_eq!(read_u64(&bytes), Some((0x0807_0605_0403_0201, &bytes[8..])));
        assert_eq!((read_u32(&bytes[..3]), read_u64(&bytes[..7])), (None, None));
        let fps = [Fp::new(7), Fp::new(P - 1), Fp::ZERO];
        let mut buf = [0xffu8; 14];
        let rest = write_fps(&mut buf, &fps);
        assert_eq!(rest, &[0xff, 0xff]);
        assert_eq!(read_fps::<3>(&buf), Some((fps, &[0xffu8, 0xff][..])));
        assert_eq!(read_fps::<0>(&buf), Some(([], &buf[..])));
        assert_eq!(read_fps::<3>(&buf[..11]), None);
        // The modulus itself is not an element.
        buf[4..8].copy_from_slice(&P.to_le_bytes());
        assert_eq!(read_fps::<3>(&buf), None);
        assert_eq!(read_fps::<1>(&buf), Some(([fps[0]], &buf[4..])));
        // Positions: six bytes, the largest that fits and the first that does not.
        let most = (1u64 << 48) - 1;
        for position in [0, 1, crate::output::OUTPUT_CAPACITY - 1, crate::output::OUTPUT_CAPACITY, most] {
            let mut p = [0u8; POSITION_BYTES + 1];
            write_position(&mut p[..POSITION_BYTES], position);
            assert_eq!(read_position(&p), Some((position, &[0u8][..])));
        }
        assert_eq!(read_position(&bytes[..POSITION_BYTES - 1]), None);
        let too_far = std::panic::catch_unwind(|| write_position(&mut [0u8; POSITION_BYTES], most + 1));
        assert!(too_far.is_err());
        let d: Digest = core::array::from_fn(|i| Fp::new(i as u32 + 1));
        let mut enc = [0u8; DIGEST_BYTES + 1];
        write_fps(&mut enc, &d);
        assert_eq!(read_digest(&enc), Some((d, &[0u8][..])));
        assert_eq!(read_digest(&enc[..DIGEST_BYTES - 1]), None);
        enc[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(read_digest(&enc), None);
    }
}
