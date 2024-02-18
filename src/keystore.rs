use std::{fs, io::Write, os::unix::prelude::PermissionsExt, path::Path};

use thiserror::Error;
use tracing::debug;

use crate::{
    config::Id,
    wireguard::{InvalidKeyError, Key},
};

/// Generate a client key and save it to the key directory.
/// If a key already exists it will be overwritten. Make sure that directory exists.
pub fn generate(id: &Id, data_directory: &Path) -> std::io::Result<Key> {
    debug!("generating key for {}", id);
    let key = Key::generate_random();

    let keystore_path = data_directory.join("keys");
    if !keystore_path.exists() {
        fs::create_dir_all(&keystore_path)?;
    }

    let path = keystore_path.join(id);
    let mut file = fs::File::create(path)?;
    file.write_all(key.private_key_base64().as_bytes())?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)?;

    Ok(key)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot read key file: {0}")]
    IO(#[from] std::io::Error),
    #[error("invalid key: {0}")]
    InvalidKey(#[from] InvalidKeyError),
}

pub fn load(id: &Id, data_directory: &Path) -> Result<Key, Error> {
    let path = data_directory.join("keys").join(id);

    if !path.exists() {
        debug!("no key existing key for {}", id);
        return Ok(generate(id, data_directory)?);
    }

    let encoded_key = fs::read_to_string(path)?;
    Ok(Key::from_base64(&encoded_key)?)
}
