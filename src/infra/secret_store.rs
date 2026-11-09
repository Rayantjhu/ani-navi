/** The service name under which all secrets are stored. */
const SERVICE_NAME: &str = "ani-navi";
pub const MAL_KEY: &str = "myanimelist";

#[derive(Debug)]
pub enum SecretStoreError {
    Unavailable,
    Backend(String),
}

impl From<keyring::Error> for SecretStoreError {
    fn from(error: keyring::Error) -> Self {
        match error {
            keyring::Error::NoStorageAccess(_) => SecretStoreError::Unavailable,
            _ => SecretStoreError::Backend(error.to_string()),
        }
    }
}

/** `Send + Sync` so a store can be shared with blocking threads (`tokio::task::spawn_blocking`) through an `Arc`. */
pub trait SecretStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError>;

    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError>;
}

pub struct KeyringSecretStore;

impl SecretStore for KeyringSecretStore {
    fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError> {
        let entry = keyring::Entry::new(SERVICE_NAME, key).map_err(SecretStoreError::from)?;

        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretStoreError::from(e)),
        }
    }

    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        keyring::Entry::new(SERVICE_NAME, key)
            .map_err(SecretStoreError::from)?
            .set_password(value)
            .map_err(SecretStoreError::from)
    }
}
