//! NTP authentication dispatch — a complete port of chrony 4.5 `ntp_auth.c`
//! (all 17 functions). The capstone that unifies the authentication modes.
//!
//! # What this module is
//!
//! `ntp_auth.c` is the layer that adds and verifies authentication on NTP packets,
//! dispatching by mode: **none**, **symmetric key** (an MD5/CMAC MAC via the key
//! store), **NTS** (the RFC 8915 client/server extension fields), and **MS-SNTP**
//! (asynchronous signing by an external daemon). It is the single place the rest of
//! the daemon calls to authenticate a request or response.
//!
//! This is the convergence of the project's authentication work: it composes the
//! already-ported [`crate::keys`] (symmetric), [`crate::nts_ntp_client`] /
//! [`crate::nts_ntp_server`] (NTS, themselves over [`crate::nts_ntp_auth`] +
//! [`crate::siv_nettle`]). The only external boundary is the MS-SNTP signing daemon
//! (`NSD_SignAndSendPacket`), injected as a closure.
//!
//! # Adaptations (documented, not silent)
//!
//! * **The global key store is threaded as `&mut KeyStore`.** chrony's `keys.c` is a
//!   module global; the symmetric functions here take the store as a parameter.
//! * **The global NTS server is threaded as `&mut NtsServer`.** Likewise for the
//!   server-side request/response functions.
//! * **MS-SNTP signing injected.** `NSD_SignAndSendPacket` is a closure; as in
//!   chrony the MS-SNTP response path always suppresses the original packet (it is
//!   sent asynchronously by the signer), so this returns "not generated".
//!
//! # Oracle
//!
//! The symmetric + none paths (which use the ported MD5 key store) are
//! differential-tested against the **real compiled `ntp_auth.c`** (+ `keys.c`,
//! `hash_intmd5.c`): a C generator builds a request, adds/checks the symmetric MAC
//! on request and response, and reports key info
//! (`research/oracle/ntp_auth-c-vectors.txt`). The port matches the MAC'd packet
//! bytes and the check results. The NTS and MS-SNTP dispatch are covered by Rust
//! tests over the (separately oracle-backed) NTS modules and an injected signer. See
//! the tests.

use crate::keys::KeyStore;
use crate::nts_ntp_client::{AuthReport, NtsClient};
use crate::nts_ntp_server::NtsServer;
use crate::ntp::ext::{NtpPacketBuf, NtpPacketInfo, NTP_MAX_V4_MAC_LENGTH, NTP_PACKET_SIZE};

/// chrony `NTP_AuthMode`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NtpAuthMode {
    /// `NTP_AUTH_NONE`.
    None = 0,
    /// `NTP_AUTH_SYMMETRIC`.
    Symmetric = 1,
    /// `NTP_AUTH_MSSNTP`.
    Mssntp = 2,
    /// `NTP_AUTH_MSSNTP_EXT`.
    MssntpExt = 3,
    /// `NTP_AUTH_NTS`.
    Nts = 4,
}

impl NtpAuthMode {
    fn from_i32(v: i32) -> NtpAuthMode {
        match v {
            1 => NtpAuthMode::Symmetric,
            2 => NtpAuthMode::Mssntp,
            3 => NtpAuthMode::MssntpExt,
            4 => NtpAuthMode::Nts,
            _ => NtpAuthMode::None,
        }
    }
}

/// chrony `NTP_MIN_MAC_LENGTH`.
const NTP_MIN_MAC_LENGTH: i32 = 4 + 16;
/// chrony `NTP_MAX_MAC_LENGTH`.
const NTP_MAX_MAC_LENGTH: i32 = 4 + 64;
/// chrony `NTP_VERSION`.
const NTP_VERSION: i32 = 4;
/// chrony `INACTIVE_AUTHKEY`.
const INACTIVE_AUTHKEY: u32 = 0;

/// The MS-SNTP signing primitive (`NSD_SignAndSendPacket`), injected: sign the
/// response under `key_id` and send it asynchronously. Returns success.
pub type SigndFn<'a> = &'a mut dyn FnMut(u32, &NtpPacketBuf, &NtpPacketInfo) -> bool;

/// chrony `generate_symmetric_auth`: append a symmetric-key MAC to `packet`.
fn generate_symmetric_auth(
    key_id: u32,
    keys: &mut KeyStore,
    packet: &mut NtpPacketBuf,
    info: &mut NtpPacketInfo,
) -> bool {
    if info.length + NTP_MIN_MAC_LENGTH > NTP_PACKET_SIZE {
        return false;
    }
    let mut max_auth_len =
        (if info.version == 4 { NTP_MAX_V4_MAC_LENGTH } else { NTP_MAX_MAC_LENGTH }) - 4;
    max_auth_len = max_auth_len.min(NTP_PACKET_SIZE - info.length - 4);

    let length = info.length as usize;
    let (left, right) = packet.bytes_mut().split_at_mut(length + 4);
    let auth_len =
        keys.generate_key_auth(key_id, &left[..length], &mut right[..max_auth_len as usize]) as i32;
    if auth_len < NTP_MIN_MAC_LENGTH - 4 {
        return false;
    }
    // The 4-byte key id precedes the MAC.
    left[length..length + 4].copy_from_slice(&key_id.to_be_bytes());

    info.mac_start = info.length;
    info.mac_length = 4 + auth_len;
    info.mac_key_id = key_id;
    info.length += info.mac_length;
    true
}

/// chrony `check_symmetric_auth`.
fn check_symmetric_auth(packet: &NtpPacketBuf, info: &NtpPacketInfo, keys: &mut KeyStore) -> bool {
    if info.mac_length < NTP_MIN_MAC_LENGTH {
        return false;
    }
    let trunc_len = if info.version == 4 && info.mac_length <= NTP_MAX_V4_MAC_LENGTH {
        NTP_MAX_V4_MAC_LENGTH
    } else {
        NTP_MAX_MAC_LENGTH
    };
    let start = info.mac_start as usize;
    let auth_len = (info.mac_length - 4) as usize;
    keys.check_key_auth(
        info.mac_key_id,
        &packet.bytes()[..start],
        &packet.bytes()[start + 4..start + 4 + auth_len],
        (trunc_len - 4) as usize,
    )
}

/// An NTP authentication association (chrony's `NAU_Instance_Record`).
pub struct NauInstance {
    mode: NtpAuthMode,
    key_id: u32,
    nts: Option<NtsClient>,
}

impl NauInstance {
    /// chrony `NAU_CreateNoneInstance`.
    pub fn create_none() -> NauInstance {
        NauInstance { mode: NtpAuthMode::None, key_id: INACTIVE_AUTHKEY, nts: None }
    }

    /// chrony `NAU_CreateSymmetricInstance`. (chrony logs a warning if the key is
    /// missing/too short; the warning is the caller's concern here.)
    pub fn create_symmetric(key_id: u32) -> NauInstance {
        NauInstance { mode: NtpAuthMode::Symmetric, key_id, nts: None }
    }

    /// chrony `NAU_CreateNtsInstance`.
    pub fn create_nts(nts: NtsClient) -> NauInstance {
        NauInstance { mode: NtpAuthMode::Nts, key_id: INACTIVE_AUTHKEY, nts: Some(nts) }
    }

    /// chrony `NAU_IsAuthEnabled`.
    pub fn is_auth_enabled(&self) -> bool {
        self.mode != NtpAuthMode::None
    }

    /// chrony `NAU_GetSuggestedNtpVersion`: prefer NTPv3 if a symmetric MAC would be
    /// truncated in NTPv4.
    pub fn suggested_ntp_version(&self, keys: &mut KeyStore) -> i32 {
        if self.mode == NtpAuthMode::Symmetric
            && keys.get_auth_length(self.key_id) + 4 > NTP_MAX_V4_MAC_LENGTH
        {
            return 3;
        }
        NTP_VERSION
    }

    /// chrony `NAU_PrepareRequestAuth`.
    pub fn prepare_request_auth(&mut self) -> bool {
        match self.mode {
            NtpAuthMode::Nts => self.nts.as_mut().unwrap().prepare_for_auth(),
            _ => true,
        }
    }

    /// chrony `NAU_GenerateRequestAuth`.
    pub fn generate_request_auth(
        &mut self,
        keys: &mut KeyStore,
        request: &mut NtpPacketBuf,
        info: &mut NtpPacketInfo,
    ) -> bool {
        match self.mode {
            NtpAuthMode::None => {}
            NtpAuthMode::Symmetric => {
                if !generate_symmetric_auth(self.key_id, keys, request, info) {
                    return false;
                }
            }
            NtpAuthMode::Nts => {
                if !self.nts.as_mut().unwrap().generate_request_auth(request, info) {
                    return false;
                }
            }
            _ => return false,
        }
        info.auth_mode = self.mode as i32;
        true
    }

    /// chrony `NAU_CheckResponseAuth`.
    pub fn check_response_auth(
        &mut self,
        keys: &mut KeyStore,
        response: &NtpPacketBuf,
        info: &NtpPacketInfo,
    ) -> bool {
        if info.auth_mode != self.mode as i32 {
            return false;
        }
        match self.mode {
            NtpAuthMode::None => true,
            NtpAuthMode::Symmetric => {
                info.mac_key_id == self.key_id && check_symmetric_auth(response, info, keys)
            }
            NtpAuthMode::Nts => self.nts.as_mut().unwrap().check_response_auth(response, info),
            _ => false,
        }
    }

    /// chrony `NAU_ChangeAddress`.
    pub fn change_address(&mut self, address: Option<u32>) {
        if self.mode == NtpAuthMode::Nts {
            self.nts.as_mut().unwrap().change_address(address, None);
        }
    }

    /// chrony `NAU_DumpData`: the NTS cookie dump (if any).
    pub fn dump_data(&self) -> Option<String> {
        match self.mode {
            NtpAuthMode::Nts => self.nts.as_ref().unwrap().dump_data(),
            _ => None,
        }
    }

    /// chrony `NAU_GetReport`.
    pub fn get_report(&mut self, keys: &mut KeyStore) -> AuthReport {
        let mut report = AuthReport { mode: self.mode as i32, last_ke_ago: -1.0, ..Default::default() };
        match self.mode {
            NtpAuthMode::None => {}
            NtpAuthMode::Symmetric => {
                report.key_id = self.key_id;
                if let Some((ty, bits)) = keys.get_key_info(self.key_id) {
                    report.key_type = ty;
                    report.key_length = bits;
                }
            }
            NtpAuthMode::Nts => return self.nts.as_mut().unwrap().get_report(),
            _ => {}
        }
        report
    }
}

/// chrony `NAU_CheckRequestAuth` (server side): verify a request's authentication.
/// Returns `(ok, kod)`.
pub fn check_request_auth(
    request: &NtpPacketBuf,
    info: &NtpPacketInfo,
    keys: &mut KeyStore,
    nts_server: &mut NtsServer,
) -> (bool, u32) {
    match NtpAuthMode::from_i32(info.auth_mode) {
        NtpAuthMode::None => (true, 0),
        NtpAuthMode::Symmetric => (check_symmetric_auth(request, info, keys), 0),
        // MS-SNTP requests are not authenticated.
        NtpAuthMode::Mssntp => (true, 0),
        // MS-SNTP extended: not supported yet.
        NtpAuthMode::MssntpExt => (false, 0),
        NtpAuthMode::Nts => nts_server.check_request_auth(request, info),
    }
}

/// chrony `NAU_GenerateResponseAuth` (server side): authenticate a response.
#[allow(clippy::too_many_arguments)]
pub fn generate_response_auth(
    request: &NtpPacketBuf,
    request_info: &NtpPacketInfo,
    response: &mut NtpPacketBuf,
    response_info: &mut NtpPacketInfo,
    keys: &mut KeyStore,
    nts_server: &mut NtsServer,
    signd: SigndFn,
    kod: u32,
) -> bool {
    match NtpAuthMode::from_i32(request_info.auth_mode) {
        NtpAuthMode::None => {}
        NtpAuthMode::Symmetric => {
            if !generate_symmetric_auth(request_info.mac_key_id, keys, response, response_info) {
                return false;
            }
        }
        NtpAuthMode::Mssntp => {
            // Signed asynchronously by ntp_signd; the original is never sent.
            let _ = signd(request_info.mac_key_id, response, response_info);
            return false;
        }
        NtpAuthMode::Nts => {
            if !nts_server.generate_response_auth(request, request_info, response, response_info, kod)
            {
                return false;
            }
        }
        _ => return false,
    }
    response_info.auth_mode = request_info.auth_mode;
    true
}

#[cfg(test)]
mod tests;
