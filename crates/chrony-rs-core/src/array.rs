//! Generic dynamic array — a complete port of chrony 4.5 `array.c` (`ARR_*`).
//!
//! chrony's `array.c` is a hand-rolled growable array of fixed-size elements,
//! used throughout the daemon. Rust's `Vec` subsumes the *concept*, but this is a
//! faithful behavioral restoration of chrony's exact API and semantics — including
//! its capacity-doubling/shrinking policy (`realloc_array`) and its
//! **order-preserving** element removal — over a flat `Vec<u8>` keyed by element
//! size. Where chrony hands out raw pointers, this returns byte slices, so the port
//! stays entirely in safe Rust.
//!
//! All 10 functions have counterparts:
//!
//! | chrony `array.c` | here |
//! |------------------|------|
//! | `ARR_CreateInstance` | [`Array::new`] |
//! | `ARR_DestroyInstance` | `Drop` (automatic) |
//! | `ARR_GetNewElement` | [`Array::get_new_element`] |
//! | `ARR_GetElement` | [`Array::get_element`] |
//! | `ARR_GetElements` | [`Array::get_elements`] |
//! | `ARR_AppendElement` | [`Array::append_element`] |
//! | `ARR_RemoveElement` | [`Array::remove_element`] |
//! | `ARR_SetSize` | [`Array::set_size`] |
//! | `ARR_GetSize` | [`Array::size`] |
//! | `realloc_array` | [`Array::realloc_array`] |

/// A growable array of fixed-size (`elem_size`-byte) elements.
#[derive(Debug, Clone, PartialEq)]
pub struct Array {
    /// Backing storage; length is `allocated * elem_size`.
    data: Vec<u8>,
    elem_size: usize,
    /// Number of elements in use (chrony's `used`).
    used: usize,
    /// Capacity in elements (chrony's `allocated`).
    allocated: usize,
}

impl Array {
    /// `ARR_CreateInstance`: an empty array of `elem_size`-byte elements.
    pub fn new(elem_size: usize) -> Self {
        assert!(elem_size > 0, "element size must be positive");
        Array { data: Vec::new(), elem_size, used: 0, allocated: 0 }
    }

    /// `realloc_array`: keep the capacity within `[min_size, 2*min_size]` —
    /// doubling up from 1 when too small, shrinking to exactly `min_size` when more
    /// than double. Faithful to chrony even though capacity is not observable.
    fn realloc_array(&mut self, min_size: usize) {
        if self.allocated >= min_size && self.allocated <= 2 * min_size {
            return;
        }
        if self.allocated < min_size {
            while self.allocated < min_size {
                self.allocated = if self.allocated != 0 { 2 * self.allocated } else { 1 };
            }
        } else {
            self.allocated = min_size;
        }
        self.data.resize(self.allocated * self.elem_size, 0);
    }

    /// `ARR_GetNewElement`: grow by one element and return a mutable slice to it.
    pub fn get_new_element(&mut self) -> &mut [u8] {
        self.used += 1;
        self.realloc_array(self.used);
        let off = (self.used - 1) * self.elem_size;
        &mut self.data[off..off + self.elem_size]
    }

    /// `ARR_GetElement`: a read-only slice of element `index` (panics if out of
    /// range, matching chrony's `assert`).
    pub fn get_element(&self, index: usize) -> &[u8] {
        assert!(index < self.used, "index out of range");
        let off = index * self.elem_size;
        &self.data[off..off + self.elem_size]
    }

    /// A mutable slice of element `index`.
    pub fn get_element_mut(&mut self, index: usize) -> &mut [u8] {
        assert!(index < self.used, "index out of range");
        let off = index * self.elem_size;
        &mut self.data[off..off + self.elem_size]
    }

    /// `ARR_GetElements`: all in-use element bytes as one contiguous slice.
    pub fn get_elements(&self) -> &[u8] {
        &self.data[..self.used * self.elem_size]
    }

    /// `ARR_AppendElement`: copy `element` (must be `elem_size` bytes) onto the end.
    pub fn append_element(&mut self, element: &[u8]) {
        assert_eq!(element.len(), self.elem_size, "element size mismatch");
        let slot = self.get_new_element();
        slot.copy_from_slice(element);
    }

    /// `ARR_RemoveElement`: remove element `index`, shifting later elements down by
    /// one (order-preserving).
    pub fn remove_element(&mut self, index: usize) {
        assert!(index < self.used, "index out of range");
        let es = self.elem_size;
        // Shift [index+1, used) down to [index, used-1).
        if index < self.used - 1 {
            self.data.copy_within((index + 1) * es..self.used * es, index * es);
        }
        self.used -= 1;
        self.realloc_array(self.used);
    }

    /// `ARR_SetSize`: set the element count (new slots hold whatever bytes were
    /// last there, like chrony).
    pub fn set_size(&mut self, size: usize) {
        self.realloc_array(size);
        self.used = size;
    }

    /// `ARR_GetSize`: the number of elements in use.
    pub fn size(&self) -> usize {
        self.used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: treat elements as 4-byte big-endian u32s.
    fn push_u32(a: &mut Array, v: u32) {
        a.append_element(&v.to_be_bytes());
    }
    fn get_u32(a: &Array, i: usize) -> u32 {
        u32::from_be_bytes(a.get_element(i).try_into().unwrap())
    }

    #[test]
    fn append_get_and_size() {
        let mut a = Array::new(4);
        assert_eq!(a.size(), 0);
        for v in [10u32, 20, 30, 40, 50] {
            push_u32(&mut a, v);
        }
        assert_eq!(a.size(), 5);
        assert_eq!(get_u32(&a, 0), 10);
        assert_eq!(get_u32(&a, 4), 50);
        // get_elements returns all bytes in order
        assert_eq!(a.get_elements().len(), 5 * 4);
    }

    #[test]
    fn get_new_element_is_writable() {
        let mut a = Array::new(4);
        a.get_new_element().copy_from_slice(&7u32.to_be_bytes());
        assert_eq!(get_u32(&a, 0), 7);
        a.get_element_mut(0).copy_from_slice(&9u32.to_be_bytes());
        assert_eq!(get_u32(&a, 0), 9);
    }

    #[test]
    fn remove_element_preserves_order() {
        let mut a = Array::new(4);
        for v in [1u32, 2, 3, 4, 5] {
            push_u32(&mut a, v);
        }
        a.remove_element(1); // remove "2" -> [1,3,4,5]
        assert_eq!(a.size(), 4);
        assert_eq!(
            (0..a.size()).map(|i| get_u32(&a, i)).collect::<Vec<_>>(),
            vec![1, 3, 4, 5]
        );
        a.remove_element(3); // remove last "5" -> [1,3,4]
        assert_eq!(
            (0..a.size()).map(|i| get_u32(&a, i)).collect::<Vec<_>>(),
            vec![1, 3, 4]
        );
    }

    #[test]
    fn set_size_and_growth_shrink() {
        let mut a = Array::new(2);
        a.set_size(100);
        assert_eq!(a.size(), 100);
        // write/read at the boundary to prove the buffer really grew
        a.get_element_mut(99).copy_from_slice(&[0xAB, 0xCD]);
        assert_eq!(a.get_element(99), &[0xAB, 0xCD]);
        a.set_size(0);
        assert_eq!(a.size(), 0);
        assert_eq!(a.get_elements().len(), 0);
    }

    #[test]
    #[should_panic(expected = "element size must be positive")]
    fn zero_element_size_panics() {
        Array::new(0);
    }

    /// Differential oracle: replay a scripted op sequence (append / get-new /
    /// order-preserving remove / set-size across the grow and shrink-to-min
    /// boundaries) driven identically through the REAL compiled `array.c`
    /// (`research/oracle/array-c-vectors.txt`), asserting `used`, the exact
    /// `allocated` capacity trajectory (chrony's `realloc_array` doubling-up-from-1
    /// and snap-to-`min_size` policy), and the in-use element bytes after every op.
    ///
    /// `cmp=0` marks `ARR_SetSize` grows, whose freshly-`Realloc`'d slots hold
    /// indeterminate bytes in C (`Vec::resize` zeroes them here), so only `used` and
    /// `allocated` are compared there — the capacity math is what those ops pin.
    #[test]
    fn matches_real_c_array_vectors() {
        let vectors = include_str!("../../../research/oracle/array-c-vectors.txt");
        fn field<'a>(line: &'a str, key: &str) -> &'a str {
            line.split_whitespace()
                .find_map(|t| t.strip_prefix(&format!("{key}=")))
                .unwrap()
        }

        let mut a = Array::new(4);
        let mut n = 0;
        for line in vectors.lines().filter(|l| l.starts_with("OP ")) {
            assert_eq!(field(line, "n").parse::<usize>().unwrap(), n, "step order");
            match field(line, "op") {
                "GETNEW" => {
                    let v: u32 = field(line, "val").parse().unwrap();
                    a.get_new_element().copy_from_slice(&v.to_be_bytes());
                }
                "APPEND" => {
                    let v: u32 = field(line, "val").parse().unwrap();
                    a.append_element(&v.to_be_bytes());
                }
                "REMOVE" => a.remove_element(field(line, "idx").parse().unwrap()),
                "SETSIZE" => a.set_size(field(line, "sz").parse().unwrap()),
                other => panic!("unknown op {other}"),
            }

            assert_eq!(a.used, field(line, "used").parse::<usize>().unwrap(), "op {n}: used");
            assert_eq!(a.allocated, field(line, "alloc").parse::<usize>().unwrap(), "op {n}: alloc");

            if field(line, "cmp") == "1" {
                let want = field(line, "bytes");
                let got: String =
                    a.get_elements().iter().map(|b| format!("{b:02x}")).collect();
                let got = if got.is_empty() { "-".to_string() } else { got };
                assert_eq!(got, want, "op {n}: bytes");
            }
            n += 1;
        }
        assert_eq!(n, 25, "expected 25 recorded ops");
    }
}
