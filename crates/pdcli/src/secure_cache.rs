use std::{path::Path, sync::Arc};

use base64::{Engine as _, engine::general_purpose};
use proton_drive_sdk::cache::{encrypted::EncryptedCacheRepository, sqlite::SqliteCacheRepository};
use proton_sdk_rs2::cache::CacheRepository;
use rand::{TryRng, rngs::SysRng};
use rusqlite::Connection;

use crate::secure_storage::{self, KEYRING_SERVICE};

const ENTITY_CACHE_FILE: &str = "cache.db";
const SECRET_CACHE_FILE: &str = "secret-cache.db";
const SECRET_CACHE_KEY_FILE: &str = "secret-cache.key";
const SECRET_CACHE_KEYRING_ENTRY: &str = "secret-cache-master-key";
const MASTER_KEY_LEN: usize = 32;

pub fn repositories() -> anyhow::Result<(Arc<dyn CacheRepository>, Arc<dyn CacheRepository>)> {
    let config_dir = secure_storage::config_dir()?;
    secure_storage::ensure_private_dir(&config_dir)?;

    let entity_cache_path = config_dir.join(ENTITY_CACHE_FILE);
    purge_legacy_plaintext_secrets(&entity_cache_path)?;
    let entity_cache: Arc<dyn CacheRepository> = Arc::new(SqliteCacheRepository::open_file(
        &entity_cache_path,
        Some(10_000),
    )?);
    secure_storage::harden_private_file(&entity_cache_path)?;

    let secret_cache_path = config_dir.join(SECRET_CACHE_FILE);
    let secret_cache_inner: Arc<dyn CacheRepository> = Arc::new(SqliteCacheRepository::open_file(
        &secret_cache_path,
        Some(5_000),
    )?);
    secure_storage::harden_private_file(&secret_cache_path)?;
    let master_key = load_or_create_secret_cache_key(&config_dir)?;
    let secret_cache: Arc<dyn CacheRepository> = Arc::new(EncryptedCacheRepository::new(
        secret_cache_inner,
        master_key,
    ));

    Ok((entity_cache, secret_cache))
}

fn purge_legacy_plaintext_secrets(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let conn = Connection::open(path)?;
    let removed = match conn.execute(
        "DELETE FROM Entries
         WHERE Key = 'user:current:keys'
            OR Key LIKE 'address:%:keys'
            OR Key LIKE 'account:passphrase:%'
            OR Key LIKE 'share_key_%'
            OR Key LIKE 'folder_secrets_%'
            OR Key LIKE 'file_secrets_%'",
        [],
    ) {
        Ok(removed) => removed,
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message.contains("no such table") =>
        {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    conn.execute(
        "DELETE FROM Tags WHERE Key NOT IN (SELECT Key FROM Entries)",
        [],
    )?;

    if removed > 0 {
        tracing::warn!(
            path = %path.display(),
            entries = removed,
            "removed legacy plaintext secret entries from pdcli metadata cache"
        );
    }

    Ok(())
}

fn load_or_create_secret_cache_key(config_dir: &Path) -> anyhow::Result<Vec<u8>> {
    match load_or_create_secret_cache_key_from_keyring() {
        Ok(key) => return Ok(key),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "OS keyring is not available for pdcli secret-cache encryption key; falling back to a local key file"
            );
        }
    }

    let key_path = config_dir.join(SECRET_CACHE_KEY_FILE);
    if let Ok(encoded) = std::fs::read_to_string(&key_path) {
        return decode_master_key(encoded.trim()).map_err(|error| {
            anyhow::anyhow!(
                "failed to decode local pdcli secret-cache key {}: {error}",
                key_path.display()
            )
        });
    }

    let key = generate_master_key()?;
    let encoded = general_purpose::STANDARD.encode(&key);
    secure_storage::write_private_file(&key_path, encoded.as_bytes())?;
    tracing::warn!(
        path = %key_path.display(),
        "stored pdcli secret-cache encryption key in a local file because no OS keyring is available; install/enable Secret Service, KWallet, GNOME Keyring, Keychain, or Credential Manager for stronger protection"
    );
    Ok(key)
}

fn load_or_create_secret_cache_key_from_keyring() -> anyhow::Result<Vec<u8>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, SECRET_CACHE_KEYRING_ENTRY)?;
    match entry.get_password() {
        Ok(encoded) => decode_master_key(&encoded),
        Err(keyring::Error::NoEntry) => {
            let key = generate_master_key()?;
            entry.set_password(&general_purpose::STANDARD.encode(&key))?;
            tracing::debug!("stored pdcli secret-cache encryption key in OS keyring");
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

fn generate_master_key() -> anyhow::Result<Vec<u8>> {
    let mut key = vec![0u8; MASTER_KEY_LEN];
    SysRng.try_fill_bytes(&mut key)?;
    Ok(key)
}

fn decode_master_key(encoded: &str) -> anyhow::Result<Vec<u8>> {
    let key = general_purpose::STANDARD.decode(encoded)?;
    anyhow::ensure!(
        key.len() >= MASTER_KEY_LEN,
        "pdcli secret-cache key is too short"
    );
    Ok(key)
}
