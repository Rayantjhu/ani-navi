use crate::infra::secret_store::SecretStore;
use std::sync::Arc;

pub mod auth;

/** Client for MyAnimeList. Holds what every MAL call needs: the HTTP client and the store for the OAuth tokens. */
pub struct MalClient<S: SecretStore> {
    http_client: reqwest::Client,
    /** In an `Arc`, so blocking store calls can run on another thread without borrowing from the client. */
    secret_store: Arc<S>,
}

impl<S: SecretStore> MalClient<S> {
    pub fn new(http_client: reqwest::Client, secret_store: S) -> Self {
        Self {
            http_client,
            secret_store: Arc::new(secret_store),
        }
    }
}
