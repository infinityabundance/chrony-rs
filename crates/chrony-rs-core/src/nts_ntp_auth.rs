//! NTS Authenticator and Encrypted Extension Field — a complete port of chrony 4.5
//! `nts_ntp_auth.c` (all 4 functions).
//!
//! # What this module is
//!
//! For NTS-protected NTP (RFC 8915), the request/response carries a single
//! "NTS Authenticator and Encrypted Extension Fields" extension field. This module
//! builds that field ([`generate_auth_ef`]) and parses + decrypts it
//! ([`decrypt_auth_ef`]): it lays out a 4-byte header (nonce length, ciphertext
//! length), the nonce (zero-padded to a 4-byte boundary), and the SIV ciphertext
//! (tag + encrypted inner EFs, padded), with enough total padding to reach a
//! minimum field length and a minimum unpadded nonce length. The packet header and
//! preceding fields are the SIV associated data, so the authenticator covers them.
//!
//! # Adaptations (documented, not silent)
//!
//! * **SIV is injected.** The synthetic-IV AEAD (`SIV_*`) is the crypto boundary;
//!   it is the [`Siv`] trait here. The framing/length arithmetic — the substance of
//!   this file — is reproduced exactly; the AEAD itself is provided by the caller
//!   (a real AES-SIV backend, or a deterministic test cipher).
//! * **Reuses the ported extension-field layer.** Field placement and parsing go
//!   through [`crate::ntp::ext`] (`NEF_AddBlankField` / `NEF_ParseField`), exactly
//!   as chrony composes `ntp_ext.c`.
//! * **Offsets, not pointers.** chrony casts into the packet buffer (`struct
//!   AuthHeader *`, `body + nonce_length + …`); the port computes byte offsets into
//!   the [`NtpPacketBuf`] and uses `split_at_mut` to feed the associated-data and
//!   ciphertext regions to the AEAD without aliasing.
//!
//! # Oracles
//!
//! Differential-tested against the **real compiled `nts_ntp_auth.c`** (+ `ntp_ext.c`):
//! a C generator builds a packet, adds the auth EF for several plaintext / nonce /
//! min-length cases, and records the resulting packet bytes and the decrypt
//! round-trip (`research/oracle/nts_ntp_auth-c-vectors.txt`), using a deterministic
//! toy SIV. The port replays the identical cases with the **same** toy SIV and must
//! produce identical packet bytes and recovered plaintext. A second, independent
//! check verifies the padding arithmetic and a generate→decrypt round-trip. See the
//! tests.

use crate::ntp::ext::{add_blank_field, parse_field, NtpPacketBuf, NtpPacketInfo};

/// chrony `NTP_EF_NTS_AUTH_AND_EEF` (`ntp.h`): the extension-field type.
pub const NTP_EF_NTS_AUTH_AND_EEF: i32 = 0x0404;
/// chrony `NTS_MIN_UNPADDED_NONCE_LENGTH` (`nts_ntp.h`).
pub const NTS_MIN_UNPADDED_NONCE_LENGTH: i32 = 16;

/// The 4-byte `struct AuthHeader` at the start of the EF body.
const AUTH_HEADER_LEN: i32 = 4;

/// The synthetic-IV AEAD chrony uses (`SIV_*` in `siv.h`). Injecting it keeps the
/// framing independent of the cipher (real AES-SIV, or a test cipher).
pub trait Siv {
    /// chrony `SIV_GetMaxNonceLength`.
    fn max_nonce_length(&self) -> i32;
    /// chrony `SIV_GetTagLength`.
    fn tag_length(&self) -> i32;
    /// chrony `SIV_Encrypt`: authenticate `assoc` and encrypt `plaintext` into
    /// `ciphertext` (which is `tag_length + plaintext.len()` bytes). Returns success.
    fn encrypt(&mut self, nonce: &[u8], assoc: &[u8], plaintext: &[u8], ciphertext: &mut [u8])
        -> bool;
    /// chrony `SIV_Decrypt`: verify `assoc` + `ciphertext` and recover `plaintext`.
    fn decrypt(&mut self, nonce: &[u8], assoc: &[u8], ciphertext: &[u8], plaintext: &mut [u8])
        -> bool;
}

/// chrony `get_padding_length`: bytes needed to round `length` up to a multiple of 4.
fn get_padding_length(length: i32) -> i32 {
    if length % 4 != 0 {
        4 - length % 4
    } else {
        0
    }
}

/// chrony `get_padded_length`.
fn get_padded_length(length: i32) -> i32 {
    length + get_padding_length(length)
}

/// chrony `NNA_GenerateAuthEF`: append the NTS auth-and-EEF field to `packet`,
/// encrypting `plaintext` under `siv` with `nonce` (truncated to the SIV/`max`
/// limit). `min_ef_length` requests a minimum total field length. Returns success.
pub fn generate_auth_ef<S: Siv>(
    packet: &mut NtpPacketBuf,
    info: &mut NtpPacketInfo,
    siv: &mut S,
    nonce: &[u8],
    max_nonce_length: i32,
    plaintext: &[u8],
    min_ef_length: i32,
) -> bool {
    let plaintext_length = plaintext.len() as i32;
    if max_nonce_length <= 0 || plaintext_length < 0 {
        return false;
    }

    let assoc_length = info.length;
    let max_siv_nonce_length = siv.max_nonce_length();
    let nonce_length = max_nonce_length.min(max_siv_nonce_length);
    let ciphertext_length = siv.tag_length() + plaintext_length;
    let nonce_padding = get_padding_length(nonce_length);
    let ciphertext_padding = get_padding_length(ciphertext_length);
    let min_ef_length = get_padded_length(min_ef_length);

    let mut auth_length =
        AUTH_HEADER_LEN + nonce_length + nonce_padding + ciphertext_length + ciphertext_padding;
    let mut additional_padding = (min_ef_length - auth_length - 4).max(0);
    additional_padding = (NTS_MIN_UNPADDED_NONCE_LENGTH.min(max_siv_nonce_length)
        - nonce_length
        - nonce_padding)
        .max(additional_padding);
    auth_length += additional_padding;

    let Some(header_off) =
        add_blank_field(packet, info, NTP_EF_NTS_AUTH_AND_EEF, auth_length)
    else {
        return false;
    };

    // Header: nonce_length, ciphertext_length (big-endian u16 each).
    {
        let buf = packet.bytes_mut();
        buf[header_off..header_off + 2].copy_from_slice(&(nonce_length as u16).to_be_bytes());
        buf[header_off + 2..header_off + 4]
            .copy_from_slice(&(ciphertext_length as u16).to_be_bytes());
    }

    let body_off = header_off + AUTH_HEADER_LEN as usize;
    let ciphertext_off = body_off + (nonce_length + nonce_padding) as usize;

    // Layout sanity check (chrony asserts the same).
    debug_assert_eq!(
        header_off + auth_length as usize,
        ciphertext_off + (ciphertext_length + ciphertext_padding + additional_padding) as usize
    );

    // Copy the nonce and zero its padding.
    {
        let buf = packet.bytes_mut();
        buf[body_off..body_off + nonce_length as usize]
            .copy_from_slice(&nonce[..nonce_length as usize]);
        for b in &mut buf[body_off + nonce_length as usize..ciphertext_off] {
            *b = 0;
        }
    }

    // Encrypt: associated data is the packet up to this field; ciphertext goes into
    // the field body. The two regions are disjoint (assoc_length <= ciphertext_off).
    let ok = {
        let (left, right) = packet.bytes_mut().split_at_mut(ciphertext_off);
        let assoc = &left[..assoc_length as usize];
        let ciphertext = &mut right[..ciphertext_length as usize];
        siv.encrypt(&nonce[..nonce_length as usize], assoc, plaintext, ciphertext)
    };
    if !ok {
        info.length = assoc_length;
        info.ext_fields -= 1;
        return false;
    }

    // Zero the ciphertext + additional padding.
    {
        let buf = packet.bytes_mut();
        let pad_start = ciphertext_off + ciphertext_length as usize;
        let pad_end = pad_start + (ciphertext_padding + additional_padding) as usize;
        for b in &mut buf[pad_start..pad_end] {
            *b = 0;
        }
    }

    true
}

/// chrony `NNA_DecryptAuthEF`: parse the auth EF at `ef_start`, verify and decrypt
/// it under `siv`, writing the recovered plaintext into `plaintext_out`. Returns the
/// plaintext length on success.
pub fn decrypt_auth_ef<S: Siv>(
    packet: &NtpPacketBuf,
    info: &NtpPacketInfo,
    siv: &mut S,
    ef_start: i32,
    plaintext_out: &mut [u8],
) -> Option<usize> {
    let buffer_length = plaintext_out.len() as i32;
    if buffer_length < 0 {
        return None;
    }

    let pf = parse_field(packet, info.length, ef_start)?;
    if pf.field_type != NTP_EF_NTS_AUTH_AND_EEF || pf.body_length < AUTH_HEADER_LEN {
        return None;
    }

    let buf = packet.bytes();
    let h = pf.body_offset;
    let nonce_length = u16::from_be_bytes([buf[h], buf[h + 1]]) as i32;
    let ciphertext_length = u16::from_be_bytes([buf[h + 2], buf[h + 3]]) as i32;

    if get_padded_length(nonce_length) + get_padded_length(ciphertext_length) > pf.body_length {
        return None;
    }

    let nonce_off = h + AUTH_HEADER_LEN as usize;
    let ciphertext_off = nonce_off + get_padded_length(nonce_length) as usize;

    let max_siv_nonce_length = siv.max_nonce_length();
    let siv_tag_length = siv.tag_length();

    if nonce_length < 1
        || ciphertext_length < siv_tag_length
        || ciphertext_length - siv_tag_length > buffer_length
    {
        return None;
    }

    if AUTH_HEADER_LEN
        + NTS_MIN_UNPADDED_NONCE_LENGTH.min(max_siv_nonce_length)
        + get_padded_length(ciphertext_length)
        > pf.body_length
    {
        return None;
    }

    let plaintext_length = (ciphertext_length - siv_tag_length) as usize;

    let nonce = &buf[nonce_off..nonce_off + nonce_length as usize];
    let assoc = &buf[..ef_start as usize];
    let ciphertext = &buf[ciphertext_off..ciphertext_off + ciphertext_length as usize];

    if !siv.decrypt(nonce, assoc, ciphertext, &mut plaintext_out[..plaintext_length]) {
        return None;
    }

    Some(plaintext_length)
}

#[cfg(test)]
mod tests;
