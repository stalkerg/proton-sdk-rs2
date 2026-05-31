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
const LEGACY_SECRET_PREDICATE: &str = "\
Key = 'user:current:keys'
   OR Key LIKE 'address:%:keys'
   OR Key LIKE 'account:passphrase:%'
   OR Key LIKE 'share_key_%'
   OR Key LIKE 'folder_secrets_%'
   OR Key LIKE 'file_secrets_%'";

pub async fn repositories() -> anyhow::Result<(Arc<dyn CacheRepository>, Arc<dyn CacheRepository>)>
{
    let config_dir = secure_storage::config_dir()?;
    secure_storage::ensure_private_dir(&config_dir)?;

    let entity_cache_path = config_dir.join(ENTITY_CACHE_FILE);
    let legacy_secret_entries = read_legacy_plaintext_secrets(&entity_cache_path)?;

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
    migrate_legacy_plaintext_secrets(&entity_cache_path, &secret_cache, legacy_secret_entries)
        .await?;

    let entity_cache: Arc<dyn CacheRepository> = Arc::new(SqliteCacheRepository::open_file(
        &entity_cache_path,
        Some(10_000),
    )?);
    secure_storage::harden_private_file(&entity_cache_path)?;

    Ok((entity_cache, secret_cache))
}

fn read_legacy_plaintext_secrets(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(path)?;
    let sql = format!("SELECT Key, Value FROM Entries WHERE {LEGACY_SECRET_PREDICATE}");
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(error) if is_no_such_table(&error) => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let rows = match stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?))) {
        Ok(rows) => rows,
        Err(error) if is_no_such_table(&error) => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

async fn migrate_legacy_plaintext_secrets(
    entity_cache_path: &Path,
    secret_cache: &Arc<dyn CacheRepository>,
    entries: Vec<(String, String)>,
) -> anyhow::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let entry_count = entries.len();
    for (key, value) in entries {
        secret_cache.set(&key, value, vec![]).await?;
    }

    let removed = purge_legacy_plaintext_secrets(entity_cache_path)?;
    tracing::warn!(
        path = %entity_cache_path.display(),
        entries = removed,
        "migrated legacy plaintext secret entries to the encrypted pdcli secret cache and removed plaintext copies"
    );

    if removed < entry_count {
        tracing::warn!(
            path = %entity_cache_path.display(),
            expected = entry_count,
            removed,
            "fewer legacy plaintext secret entries were removed than migrated"
        );
    }

    Ok(())
}

fn purge_legacy_plaintext_secrets(path: &Path) -> anyhow::Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    let conn = Connection::open(path)?;
    let sql = format!("DELETE FROM Entries WHERE {LEGACY_SECRET_PREDICATE}");
    let removed = match conn.execute(&sql, []) {
        Ok(removed) => removed,
        Err(error) if is_no_such_table(&error) => return Ok(0),
        Err(error) => return Err(error.into()),
    };

    match conn.execute(
        "DELETE FROM Tags WHERE Key NOT IN (SELECT Key FROM Entries)",
        [],
    ) {
        Ok(_) => {}
        Err(error) if is_no_such_table(&error) => {}
        Err(error) => return Err(error.into()),
    }

    Ok(removed)
}

fn is_no_such_table(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("no such table")
    )
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
