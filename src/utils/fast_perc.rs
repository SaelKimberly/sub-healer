const ACCEPT: usize = 12;
const REJECT: usize = 0;

/// SAFETY: The decode below function relies on the correctness of these
/// equivalence classes.
#[rustfmt::skip]
const CLASSES: [u8; 256] = [
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
   7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
   8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,
];

/// SAFETY: The decode below function relies on the correctness of this state
/// machine.
#[rustfmt::skip]
const STATES_FORWARD: [u8; 108] = [
  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,
  12, 0,  24, 36, 60, 96, 84, 0,  0, 0,  48, 72,
  0,  12, 0,  0,  0,  0,  0,  12, 0, 12, 0,  0,
  0,  24, 0,  0,  0,  0,  0,  24, 0, 24, 0,  0,
  0,  0,  0,  0,  0,  0,  0,  24, 0, 0,  0,  0,
  0,  24, 0,  0,  0,  0,  0,  0,  0, 24, 0,  0,
  0,  0,  0,  0,  0,  0,  0,  36, 0, 36, 0,  0,
  0,  36, 0,  0,  0,  0,  0,  36, 0, 36, 0,  0,
  0,  36, 0,  0,  0,  0,  0,  0,  0, 0,  0,  0,
];
const fn decode_step(state: &mut usize, cp: &mut u32, b: u8) {
    let class = CLASSES[b as usize];
    let b = b as u32;
    if *state == ACCEPT {
        *cp = (0xFF >> class) & b;
    } else {
        *cp = (b & 0b0011_1111) | (*cp << 6);
    }
    *state = STATES_FORWARD[*state + class as usize] as usize;
}

/// Decode a single character from the given slice.
const fn decode(slice: &[u8]) -> (Option<char>, usize) {
    match slice {
        [] => return (None, 0),

        &[
            b'%',
            c1 @ (b'A'..=b'F' | b'a'..=b'f' | b'0'..=b'9'),
            c2 @ (b'A'..=b'F' | b'a'..=b'f' | b'0'..=b'9'),
            ..,
        ] => {
            let c1 = match c1 {
                b'A'..=b'F' => c1 - const { b'A' - 10 },
                b'a'..=b'f' => c1 - const { b'a' - 10 },
                _ => c1 - b'0',
            };
            let c2 = match c2 {
                b'A'..=b'F' => c2 - const { b'A' - 10 },
                b'a'..=b'f' => c2 - const { b'a' - 10 },
                _ => c2 - b'0',
            };
            let c = (c1 << 4) | c2;
            return (Some(c as char), 3);
        }
        &[c @ ..0x80, ..] => {
            return (Some(c as char), 1);
        }
        _ => (),
    }

    let (mut state, mut cp, mut i) = (ACCEPT, 0, 0);
    loop {
        if i == slice.len() {
            break;
        }
        decode_step(&mut state, &mut cp, slice[i]);
        i += 1;

        if state == ACCEPT {
            // SAFETY: This is safe because `decode_step` guarantees that
            // `cp` is a valid Unicode scalar value in an ACCEPT state.
            let ch = unsafe { char::from_u32_unchecked(cp) };
            return (Some(ch), i);
        } else if state == REJECT {
            // At this point, we always want to advance at least one byte.
            return match i.saturating_sub(1) {
                0 => (None, 1),
                n => (None, n),
            };
        }
    }
    (None, i)
}
const fn char_advance(slice: &mut &[u8], state: &mut usize) -> Option<char> {
    let (ch, n) = decode(slice);
    if let Some(c) = ch {
        *slice = unsafe { core::slice::from_raw_parts(slice.as_ptr().add(n), slice.len() - n) };
        *state += n;
        Some(c)
    } else {
        None
    }
}
#[cfg_attr(test, derive(Debug))]
pub(super) struct AutoChars<'a> {
    slice: &'a [u8],
    last_e: usize,
    last_c: Option<char>,
}

impl AutoChars<'_> {
    pub(super) const fn next(&mut self) -> Option<char> {
        if let Some(c) = self.last_c.take() {
            Some(c)
        } else if let Some(c) = char_advance(&mut self.slice, &mut self.last_e) {
            Some(c)
        } else {
            None
        }
    }
}
impl<'a> AutoChars<'a> {
    pub(super) const fn new(slice: &'a [u8]) -> Self {
        Self {
            slice,
            last_e: 0,
            last_c: None,
        }
    }
    pub const fn remaining(&self) -> &'a [u8] {
        self.slice
    }
    pub(super) const fn bytes_read(&self) -> usize {
        self.last_e
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_auto_chars() {
        use super::AutoChars;

        // Test percent-decoding
        let mut ac = AutoChars::new(b"%A5abc");
        assert_eq!(ac.next(), Some('¥'));
        assert_eq!(ac.next(), Some('a'));
        assert_eq!(ac.next(), Some('b'));
        assert_eq!(ac.next(), Some('c'));
        assert_eq!(ac.next(), None);
        assert!(ac.remaining().is_empty());

        // Test raw bytes
        let mut ac = AutoChars::new(b"hello");
        assert_eq!(ac.next(), Some('h'));
        assert_eq!(ac.next(), Some('e'));
        assert_eq!(ac.remaining(), b"llo");
        assert_eq!(ac.bytes_read(), 2);

        // Test invalid percent treated as literal
        let mut ac = AutoChars::new(b"%XY");
        assert_eq!(ac.next(), Some('%'));

        // Test truncated percent
        let mut ac = AutoChars::new(b"%A");
        assert_eq!(ac.next(), Some('%'));

        // Test empty
        let mut ac = AutoChars::new(b"");
        assert_eq!(ac.next(), None);
        assert!(ac.remaining().is_empty());
        assert_eq!(ac.bytes_read(), 0);
    }
}
