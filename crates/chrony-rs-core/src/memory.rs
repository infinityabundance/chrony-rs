//! Memory allocation wrappers — a port of chrony 4.5 `memory.c` (`Malloc`, `Realloc`, etc.).
//!
//! In chrony, `memory.c` provides xmalloc/xrealloc wrappers that abort on allocation
//! failure. In Rust these are subsumed by the standard library's `Vec`/`Box`/`String`
//! which panic on OOM, so the port is a thin compatibility layer.

/// `Malloc`: allocate a zero-initialised buffer of `count` elements of `size` bytes each.
/// In Rust this is `vec![0u8; count * size]` (panics on OOM, matching chrony's abort).
pub fn malloc(count: usize, size: usize) -> Vec<u8> {
    vec![0u8; count * size]
}

/// `Malloc2`: allocate a zero-initialised buffer of `count * size` bytes, returning
/// a pointer (as a Vec<u8>). Same as `Malloc` with a single argument.
pub fn malloc2(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

/// `Realloc`: resize a buffer to `count * size` bytes, preserving existing content.
/// In Rust this is `Vec::resize` on the existing buffer.
pub fn realloc(buf: &mut Vec<u8>, count: usize, size: usize) {
    let new_len = count * size;
    buf.resize(new_len, 0);
}

/// `Realloc2`: resize a buffer to `size` bytes. Same as `Realloc` with count=1.
pub fn realloc2(buf: &mut Vec<u8>, size: usize) {
    buf.resize(size, 0);
}

/// `Strdup`: duplicate a string. In Rust this is simply `.to_string()`.
pub fn strdup(s: &str) -> String {
    s.to_string()
}

/// `get_array_size`: return the number of elements of type `T` that fit in
/// a buffer of `size` bytes (chrony's `sizeof_array` macro).
pub fn get_array_size<T>(size: usize) -> usize {
    size / core::mem::size_of::<T>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malloc_creates_zeroed_buffer() {
        let b = malloc(3, 4);
        assert_eq!(b.len(), 12);
        assert!(b.iter().all(|&x| x == 0));
    }

    #[test]
    fn malloc2_zeroed() {
        let b = malloc2(10);
        assert_eq!(b.len(), 10);
        assert!(b.iter().all(|&x| x == 0));
    }

    #[test]
    fn realloc_resizes() {
        let mut b = vec![1u8, 2, 3];
        realloc(&mut b, 2, 3);
        assert_eq!(b.len(), 6);
        assert_eq!(b[0], 1);
    }

    #[test]
    fn strdup_duplicates() {
        assert_eq!(strdup("hello"), "hello");
    }

    #[test]
    fn get_array_size_works() {
        assert_eq!(get_array_size::<u32>(8), 2);
        assert_eq!(get_array_size::<u64>(16), 2);
    }
}
