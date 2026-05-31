use proton_sdk_rs2::{ser::StoredCredentials, session::ProtonAPISession};

use crate::secure_storage::{self, KEYRING_SERVICE};

const CRED_FILE: &str = "cred.ron";
const SESSION_KEYRING_ENTRY: &str = "current-session";

fn cred_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(secure_storage::config_dir()?.join(CRED_FILE))
}

pub fn load() -> Option<StoredCredentials> {
    match load_from_keyring() {
        Ok(Some(cred)) => return Some(cred),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                error = %error,
                "OS keyring is not available for pdcli credentials; falling back to legacy plaintext credentials file if present"
            );
        }
    }

    let path = match cred_path() {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(error = %error, "failed to resolve credential path");
            return None;
        }
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return None,
    };
    match ron::from_str(&data) {
        Ok(cred) => {
            tracing::warn!(
                path = %path.display(),
                "loaded pdcli credentials from a plaintext legacy file; they will be migrated to the OS keyring on the next save if available"
            );
            Some(cred)
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "corrupt credentials file");
            None
        }
    }
}

pub fn save(cred: &StoredCredentials) -> anyhow::Result<()> {
    let data = ron::ser::to_string_pretty(cred, ron::ser::PrettyConfig::default())?;

    match save_to_keyring(&data) {
        Ok(()) => {
            if let Ok(path) = cred_path() {
                if std::fs::remove_file(&path).is_ok() {
                    tracing::info!(
                        path = %path.display(),
                        "removed legacy plaintext pdcli credentials after keyring save"
                    );
                }
            }
            tracing::debug!("saved pdcli credentials to OS keyring");
            Ok(())
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "OS keyring is not available; saving pdcli credentials to a plaintext file. Install/enable Secret Service, KWallet, GNOME Keyring, Keychain, or Credential Manager for stronger protection."
            );
            save_to_legacy_file(&data)
        }
    }
}

pub fn save_session_tokens_on_refresh(session: &ProtonAPISession) {
    let mut refreshed = session.token_credential.subscribe_tokens_refreshed();
    let session_id = session.session_id.raw().clone();
    let username = session.username.clone();
    let user_id = session.user_id.raw().clone();
    let scopes = session.scopes.clone();
    let is_waiting_for_second_factor_code = session.is_waiting_for_second_factor_code;
    let password_mode = session.password_mode;

    tokio::spawn(async move {
        while let Ok((access_token, refresh_token)) = refreshed.recv().await {
            let cred = StoredCredentials::new(
                session_id.clone(),
                username.clone(),
                user_id.clone(),
                access_token,
                refresh_token,
                scopes.clone(),
                is_waiting_for_second_factor_code,
                password_mode,
            );
            if let Err(e) = save(&cred) {
                tracing::warn!(error = %e, "failed to persist refreshed session tokens");
            }
        }
    });
}

pub fn remove() {
    match keyring_entry().and_then(|entry| match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error.into()),
    }) {
        Ok(()) => tracing::debug!("removed pdcli credentials from OS keyring"),
        Err(error) => tracing::debug!(
            error = %error,
            "failed to remove pdcli credentials from OS keyring"
        ),
    }

    if let Ok(path) = cred_path() {
        if std::fs::remove_file(&path).is_ok() {
            tracing::debug!(path = %path.display(), "removed plaintext credentials file");
        }
    }
}

fn keyring_entry() -> anyhow::Result<keyring::Entry> {
    Ok(keyring::Entry::new(KEYRING_SERVICE, SESSION_KEYRING_ENTRY)?)
}

fn load_from_keyring() -> anyhow::Result<Option<StoredCredentials>> {
    let entry = keyring_entry()?;
    match entry.get_password() {
        Ok(data) => {
            let cred = ron::from_str(&data)?;
            tracing::debug!("loaded pdcli credentials from OS keyring");
            Ok(Some(cred))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn save_to_keyring(data: &str) -> anyhow::Result<()> {
    keyring_entry()?.set_password(data)?;
    Ok(())
}

fn save_to_legacy_file(data: &str) -> anyhow::Result<()> {
    let dir = secure_storage::config_dir()?;
    secure_storage::ensure_private_dir(&dir)?;
    let path = dir.join(CRED_FILE);
    secure_storage::write_private_file(&path, data.as_bytes())?;
    tracing::warn!(
        path = %path.display(),
        "saved pdcli credentials to plaintext legacy file"
    );
    Ok(())
}
