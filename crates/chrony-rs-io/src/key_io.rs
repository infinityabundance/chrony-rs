use std::fs::read;

use chrony_rs_core::keys::KeyStoreBackend;

pub struct RealKeyStore;

impl KeyStoreBackend for RealKeyStore {
    fn read_file(&mut self, name: &str) -> Option<Vec<u8>> {
        read(name).ok()
    }
    fn get_auth_delay(&mut self, _len: i32) -> f64 {
        0.01
    }
}
