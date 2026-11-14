//! Reading and writing the byte encodings: integers little-endian, field
//! elements in their four-byte canonical form. A reader takes what it
//! reads from the front of a slice and returns the rest, or `None` for a
//! slice too short or an element not below the modulus.

use crate::ext::Fp4;
use crate::hash::Digest;
use crate::poseidon2::{DIGEST, Fp, digest_from_bytes};

/// Serialized size of one field element.
pub const FP_BYTES: usize = 4;
/// Serialized size of a digest.
pub const DIGEST_BYTES: usize = DIGEST * FP_BYTES;

/// Packs up to three bytes (24 bits) into a field element, little-endian;
/// fewer than three are zero padded.
pub fn pack3(bytes: &[u8]) -> Fp {
    let mut v = 0u32;
    for (i, b) in bytes.iter().enumerate() {
        v |= (*b as u32) << (8 * i);
    }
    Fp::new(v)
}

/// The elements `bytes` pack into, three bytes each ([`pack3`]), the last
/// zero padded: `bytes.len().div_ceil(3)` of them, made as they are read.
pub fn packed(bytes: &[u8]) -> impl ExactSizeIterator<Item = Fp> + '_ {
    bytes.chunks(3).map(pack3)
}

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

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn with_capacity(n: usize) -> Writer {
        Writer(Vec::with_capacity(n))
    }

    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub fn fp(&mut self, x: &Fp) {
        self.0.extend_from_slice(&x.to_le_bytes());
    }

    pub fn fps(&mut self, xs: &[Fp]) {
        for x in xs {
            self.fp(x);
        }
    }

    pub fn fp4(&mut self, x: &Fp4) {
        self.fps(&x.0);
    }

    pub fn digest(&mut self, d: &Digest) {
        self.fps(d);
    }

    /// Length-prefixed list of field elements.
    pub fn fp_vec(&mut self, xs: &[Fp]) {
        self.u32(xs.len() as u32);
        self.fps(xs);
    }

    pub fn fp4_vec(&mut self, xs: &[Fp4]) {
        self.u32(xs.len() as u32);
        for x in xs {
            self.fp4(x);
        }
    }

    pub fn digest_vec(&mut self, ds: &[Digest]) {
        self.u32(ds.len() as u32);
        for d in ds {
            self.digest(d);
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    pub fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        #[cfg(test)]
        READS.with(|r| {
            if let Some(v) = r.borrow_mut().as_mut() {
                v.push(b.as_ptr() as usize);
            }
        });
        Some(u32::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// A length prefix bounded by the bytes remaining, to reject absurd
    /// allocations before reading.
    pub fn len(&mut self, item_size: usize) -> Option<usize> {
        let n = self.u32()? as usize;
        if n.checked_mul(item_size.max(1))? > self.0.len() {
            return None;
        }
        Some(n)
    }

    pub fn fp(&mut self) -> Option<Fp> {
        Fp::from_le_bytes(self.take(4)?.try_into().unwrap())
    }

    pub fn fp4(&mut self) -> Option<Fp4> {
        Some(Fp4([self.fp()?, self.fp()?, self.fp()?, self.fp()?]))
    }

    pub fn digest(&mut self) -> Option<Digest> {
        let mut d = [Fp::ZERO; DIGEST];
        for x in d.iter_mut() {
            *x = self.fp()?;
        }
        Some(d)
    }

    pub fn fp_vec(&mut self) -> Option<Vec<Fp>> {
        let n = self.len(4)?;
        (0..n).map(|_| self.fp()).collect()
    }

    pub fn fp4_vec(&mut self) -> Option<Vec<Fp4>> {
        let n = self.len(16)?;
        (0..n).map(|_| self.fp4()).collect()
    }

    pub fn digest_vec(&mut self) -> Option<Vec<Digest>> {
        let n = self.len(32)?;
        (0..n).map(|_| self.digest()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
thread_local! {
    /// Tests: where each `u32` read came from, while [`u32_fields`] records.
    static READS: std::cell::RefCell<Option<Vec<usize>>> = const { std::cell::RefCell::new(None) };
}

/// Tests: the offsets in `bytes` of every `u32` that `decode` reads from
/// them, in order. Every count, length, height, index and flag of the
/// formats here is one, so this finds a format's structural fields without
/// describing the format. Reads from copies of `bytes` are not seen.
#[cfg(test)]
pub(crate) fn u32_fields(bytes: &[u8], decode: impl FnOnce(&[u8])) -> Vec<usize> {
    READS.with(|r| *r.borrow_mut() = Some(Vec::new()));
    decode(bytes);
    let reads = READS.with(|r| r.borrow_mut().take()).unwrap_or_default();
    let base = bytes.as_ptr() as usize;
    let mut out: Vec<usize> = reads.into_iter().filter(|&a| a >= base && a + 4 <= base + bytes.len()).map(|a| a - base).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Tests: every structural field of `bytes` (see [`u32_fields`]) set in
/// turn to each boundary value (0, 1, 2, 31, 32, 33, 63, 64, 255, 256,
/// 2^31, `u32::MAX`, and one either side of its own), and `check` run on
/// the result: `None` if it does not decode, `Some(accepted)` if it does.
/// Returns the mutants that panicked and those that were accepted; both
/// should be empty. Deterministic, unlike random mutation, which rarely
/// lands a chosen value on a chosen field of a large proof.
#[cfg(test)]
pub(crate) fn sweep_fields(bytes: &[u8], check: impl Fn(&[u8]) -> Option<bool>) -> (usize, Vec<String>, Vec<String>) {
    let fields = u32_fields(bytes, |b| {
        check(b);
    });
    let (mut panicked, mut accepted) = (Vec::new(), Vec::new());
    let quiet = crate::test_util::Quiet::new();
    for &at in &fields {
        let own = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let values = [0, 1, 2, 31, 32, 33, 63, 64, 255, 256, 1 << 31, u32::MAX, own.wrapping_add(1), own.wrapping_sub(1)];
        for v in values {
            if v == own {
                continue;
            }
            let mut b = bytes.to_vec();
            b[at..at + 4].copy_from_slice(&v.to_le_bytes());
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&b))) {
                Err(e) => {
                    let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()));
                    panicked.push(format!("u32 at {at} ({own}) set to {v}: {}", msg.unwrap_or_default()));
                }
                Ok(Some(true)) => accepted.push(format!("u32 at {at} ({own}) set to {v}")),
                Ok(_) => {}
            }
        }
    }
    drop(quiet);
    (fields.len(), panicked, accepted)
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
        // Three bytes to an element, little-endian, the last zero padded.
        assert_eq!(pack3(&[1, 2, 3]).to_canonical(), 0x03_0201);
        assert_eq!(pack3(&[0xff, 0xff, 0xff]).to_canonical(), 0xff_ffff);
        assert_eq!((pack3(&[7]).to_canonical(), pack3(&[]).to_canonical()), (7, 0));
        let seven: Vec<u32> = packed(&bytes[..7]).map(|x| x.to_canonical()).collect();
        assert_eq!(seven, [0x03_0201, 0x06_0504, 0x07]);
        assert_eq!((packed(&bytes[..7]).len(), packed(&bytes[..6]).len(), packed(&[]).len()), (3, 2, 0));
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

    #[test]
    fn writer_and_reader_round_trip_and_reject() {
        let mut w = Writer::default();
        w.u32(7);
        w.u64(u64::MAX);
        w.fp4(&Fp4([Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)]));
        w.fp_vec(&[Fp::new(9), Fp::new(10)]);
        w.digest_vec(&[[Fp::new(5); DIGEST]]);
        let bytes = w.finish();
        let mut r = Reader(&bytes);
        assert_eq!(r.u32(), Some(7));
        assert_eq!(r.u64(), Some(u64::MAX));
        assert_eq!(r.fp4(), Some(Fp4([Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)])));
        assert_eq!(r.fp_vec(), Some(vec![Fp::new(9), Fp::new(10)]));
        assert_eq!(r.digest_vec(), Some(vec![[Fp::new(5); DIGEST]]));
        assert!(r.is_empty());
        assert_eq!(r.u32(), None);
        // Non-canonical element and oversized length prefix are rejected.
        let mut r = Reader(&0x7800_0001u32.to_le_bytes());
        assert_eq!(r.fp(), None);
        let mut r = Reader(&u32::MAX.to_le_bytes());
        assert_eq!(r.fp_vec(), None);
    }

    /// The tests' sweep finds every count a decoder reads and tries the
    /// values at its bounds: a decoder that trusts one is found out.
    #[test]
    fn the_sweep_finds_a_trusted_count() {
        let mut w = Writer::default();
        w.fp_vec(&[Fp::new(1), Fp::new(2), Fp::new(3)]);
        w.u32(9);
        let bytes = w.finish();
        let fields = u32_fields(&bytes, |b| {
            let mut r = Reader(b);
            let _ = (r.fp_vec(), r.u32());
        });
        assert_eq!(fields, vec![0, 16]);
        // A careful decoder: nothing but the bytes it was given decodes.
        let careful = |b: &[u8]| {
            let mut r = Reader(b);
            let (v, n) = (r.fp_vec()?, r.u32()?);
            (r.is_empty() && v.len() == 3 && n == 9).then_some(false)
        };
        let (found, panicked, accepted) = sweep_fields(&bytes, careful);
        assert_eq!((found, panicked.len(), accepted.len()), (2, 0, 0));
        // One that accepts any count, and one that indexes by it.
        let (_, panicked, accepted) = sweep_fields(&bytes, |b| Reader(&b[16..]).u32().map(|_| true));
        assert!(panicked.is_empty() && accepted.len() >= 10);
        let (_, panicked, _) = sweep_fields(&bytes, |b| {
            let n = Reader(&b[16..]).u32()? as usize;
            Some([0u8; 16][n] == 1)
        });
        assert!(!panicked.is_empty());
    }
}
