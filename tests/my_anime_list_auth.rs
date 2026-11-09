use ani_navi::infra::my_anime_list::MalClient;
use ani_navi::infra::my_anime_list::auth::{AuthConfig, AuthError, BrowserOpener, CallbackReadError, TokenReadError};
use ani_navi::infra::oauth_tokens::OAuthTokens;
use ani_navi::infra::secret_store::{MAL_KEY, SecretStore, SecretStoreError};
use oauth2::RequestTokenError;
use reqwest::Url;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/** Clones share the same memory, so a test can hand one clone to `MalClient` and read the other afterwards. */
#[derive(Clone, Default)]
struct InMemorySecretStore {
    memory: Arc<Mutex<HashMap<String, String>>>,
}

impl SecretStore for InMemorySecretStore {
    fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError> {
        let value = self.memory.lock().expect("Lock is not poisoned").get(key).cloned();
        Ok(value)
    }

    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        self.memory
            .lock()
            .expect("Lock is not poisoned")
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
}

struct FailingSecretStore;

impl SecretStore for FailingSecretStore {
    fn get(&self, _: &str) -> Result<Option<String>, SecretStoreError> {
        Err(SecretStoreError::Backend("test failure".to_string()))
    }

    fn set(&self, _: &str, _: &str) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::Backend("test failure".to_string()))
    }
}

fn fake_browser(paths: Vec<&'static str>) -> (BrowserOpener, UnboundedReceiver<String>) {
    let (tx, rx) = mpsc::unbounded_channel();

    let fake_browser_opener: BrowserOpener = Box::new(move |url| {
        let url = Url::parse(url).expect("Auth URL is valid");
        let query_parameters: HashMap<_, _> = url.query_pairs().collect();
        let state = query_parameters.get("state").expect("Auth URL has a state").to_string();
        let redirect_uri = query_parameters
            .get("redirect_uri")
            .expect("Auth URL has a redirect_uri");

        let redirect_url = Url::parse(redirect_uri).expect("Invalid redirect_uri");
        let host = redirect_url.host().expect("Redirect URI has a host").to_string();
        let port = redirect_url.port().expect("Redirect URI has a port");

        let tx = tx.clone();
        let paths = paths.clone();

        tokio::spawn(async move {
            for path in paths {
                let mut stream = TcpStream::connect((host.as_str(), port))
                    .await
                    .expect("Callback listener accepts");

                if path.is_empty() {
                    // Close the connection when empty.
                    let _ = stream.shutdown().await;
                } else {
                    let request = format!("GET {} HTTP/1.1\r\n\r\n", path.replace("{state}", &state));
                    stream.write_all(request.as_bytes()).await.expect("Request is sent");
                }

                let mut response = String::new();
                let _ = stream.read_to_string(&mut response).await;
                let _ = tx.send(response);
            }
        });
        Ok(())
    });

    (fake_browser_opener, rx)
}

fn test_config(token_url: String, open_browser: BrowserOpener) -> AuthConfig {
    AuthConfig {
        callback_addresses: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
        auth_url: "http://auth.invalid/authorize".to_string(),
        token_url,
        open_browser,
        accept_deadline: Duration::from_secs(2),
        read_timeout: Duration::from_millis(50),
    }
}

async fn mock_token_endpoint(server: &MockServer, response: ResponseTemplate, expected_calls: u64) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("code=test-code"))
        .respond_with(response)
        .expect(expected_calls)
        .mount(server)
        .await;
}

/** For tests that fail before the token request. `.invalid` fails DNS resolution quickly, so a request to it returns
`AuthError::TokenRequest` and the test fails on its `matches!` assertion instead of hanging. */
const UNUSED_TOKEN_URL: &str = "http://token.invalid/token";

/** The `expires_in` of the token responses: 31 days in seconds. */
const EXPIRES_IN: u64 = 2_678_400;

const GENERIC_FAILED_PAGE: &str = include_str!("../src/infra/my_anime_list/auth_pages/generic_failed.html");

fn valid_token_response() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "token_type": "Bearer",
        "expires_in": EXPIRES_IN,
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
    }))
}

fn assert_nothing_stored(secret_store: &InMemorySecretStore) {
    assert_eq!(secret_store.get(MAL_KEY).expect("Fake store succeeds"), None);
}

fn assert_generic_failed_page(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request"), "{response}");
    assert!(response.ends_with(GENERIC_FAILED_PAGE), "{response}");
}

#[tokio::test]
async fn store_tokens_and_return_success_page_when_callback_is_valid() {
    let mock_server = MockServer::start().await;
    let token_url = format!("{}/token", mock_server.uri());

    let (browser_opener, mut rx) = fake_browser(vec!["/callback?code=test-code&state={state}"]);
    let secret_store = InMemorySecretStore::default();
    let http_client = reqwest::Client::new();
    let config = test_config(token_url, browser_opener);

    mock_token_endpoint(&mock_server, valid_token_response(), 1).await;

    let before = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is valid")
        .as_secs();
    MalClient::new(http_client, secret_store.clone())
        .authenticate_with_config(config)
        .await
        .expect("Auth succeeds");
    let after = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is valid")
        .as_secs();

    let tokens_json = secret_store.get(MAL_KEY).expect("Fake store succeeds");
    let tokens: OAuthTokens = serde_json::from_str(&tokens_json.expect("Tokens are stored")).expect("Should be tokens");

    assert_eq!("test-access-token", tokens.access_token);
    assert_eq!("test-refresh-token", tokens.refresh_token);
    assert!((before + EXPIRES_IN..=after + EXPIRES_IN).contains(&tokens.expires_at));
    assert!(rx.recv().await.unwrap().starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn store_tokens_and_return_success_page_when_stray_requests_come_first() {
    let mock_server = MockServer::start().await;
    mock_token_endpoint(&mock_server, valid_token_response(), 1).await;

    // More strays than the accept retry budget, to show strays don't use it up.
    let mut paths = vec!["/favicon.ico", "", "/favicon.ico", "", "/favicon.ico"];
    paths.push("/callback?code=test-code&state={state}");
    let (browser_opener, mut rx) = fake_browser(paths);
    let secret_store = InMemorySecretStore::default();
    let config = test_config(format!("{}/token", mock_server.uri()), browser_opener);

    MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await
        .expect("Auth succeeds");

    assert!(secret_store.get(MAL_KEY).expect("Fake store succeeds").is_some());
    for _ in 0..5 {
        assert!(rx.recv().await.unwrap().starts_with("HTTP/1.1 404 Not Found"));
    }
    assert!(rx.recv().await.unwrap().starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn return_timeout_when_only_stray_requests_arrive() {
    let (browser_opener, mut rx) = fake_browser(vec!["/favicon.ico"; 5]);
    let secret_store = InMemorySecretStore::default();
    let mut config = test_config(UNUSED_TOKEN_URL.to_string(), browser_opener);
    config.accept_deadline = Duration::from_millis(200);

    let result = MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await;

    assert!(matches!(result, Err(AuthError::Timeout)), "{result:?}");
    assert_nothing_stored(&secret_store);
    for _ in 0..5 {
        assert!(rx.recv().await.unwrap().starts_with("HTTP/1.1 404 Not Found"));
    }
}

#[tokio::test]
async fn return_mismatched_state_without_token_request_when_state_is_wrong() {
    let mock_server = MockServer::start().await;
    mock_token_endpoint(&mock_server, valid_token_response(), 0).await;

    let (browser_opener, mut rx) = fake_browser(vec!["/callback?code=test-code&state=wrong-state"]);
    let secret_store = InMemorySecretStore::default();
    let config = test_config(format!("{}/token", mock_server.uri()), browser_opener);

    let result = MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await;

    assert!(
        matches!(result, Err(AuthError::Callback(CallbackReadError::MismatchedState))),
        "{result:?}"
    );
    assert_nothing_stored(&secret_store);
    assert_generic_failed_page(&rx.recv().await.unwrap());
}

#[tokio::test]
async fn return_authorization_failed_with_details_page_when_mal_returns_error() {
    let mock_server = MockServer::start().await;
    mock_token_endpoint(&mock_server, valid_token_response(), 0).await;

    let (browser_opener, mut rx) = fake_browser(vec![
        "/callback?error=access_denied&message=User%20denied%20access&hint=Try%20again",
    ]);
    let secret_store = InMemorySecretStore::default();
    let config = test_config(format!("{}/token", mock_server.uri()), browser_opener);

    let result = MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await;

    assert!(
        matches!(
            result,
            Err(AuthError::Callback(CallbackReadError::AuthorizationFailed(_)))
        ),
        "{result:?}"
    );
    assert_nothing_stored(&secret_store);
    let page = rx.recv().await.unwrap();
    assert!(page.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(page.contains("access_denied"));
    assert!(page.contains("User denied access"));
    assert!(page.contains("Try again"));
}

#[tokio::test]
async fn return_token_request_error_when_token_endpoint_returns_oauth_error() {
    let mock_server = MockServer::start().await;
    let error_response = ResponseTemplate::new(400).set_body_json(serde_json::json!({ "error": "invalid_grant" }));
    mock_token_endpoint(&mock_server, error_response, 1).await;

    let (browser_opener, mut rx) = fake_browser(vec!["/callback?code=test-code&state={state}"]);
    let secret_store = InMemorySecretStore::default();
    let config = test_config(format!("{}/token", mock_server.uri()), browser_opener);

    let result = MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await;

    assert!(
        matches!(
            result,
            Err(AuthError::TokenRequest(RequestTokenError::ServerResponse(_)))
        ),
        "{result:?}"
    );
    assert_nothing_stored(&secret_store);
    assert_generic_failed_page(&rx.recv().await.unwrap());
}

#[tokio::test]
async fn return_missing_refresh_token_when_token_response_has_no_refresh_token() {
    let mock_server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "token_type": "Bearer",
        "expires_in": EXPIRES_IN,
        "access_token": "test-access-token",
    }));
    mock_token_endpoint(&mock_server, response, 1).await;

    let (browser_opener, mut rx) = fake_browser(vec!["/callback?code=test-code&state={state}"]);
    let secret_store = InMemorySecretStore::default();
    let config = test_config(format!("{}/token", mock_server.uri()), browser_opener);

    let result = MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await;

    assert!(
        matches!(result, Err(AuthError::TokenRead(TokenReadError::MissingRefreshToken))),
        "{result:?}"
    );
    assert_nothing_stored(&secret_store);
    assert_generic_failed_page(&rx.recv().await.unwrap());
}

#[tokio::test]
async fn return_secret_store_error_when_store_fails() {
    let mock_server = MockServer::start().await;
    mock_token_endpoint(&mock_server, valid_token_response(), 1).await;

    let (browser_opener, mut rx) = fake_browser(vec!["/callback?code=test-code&state={state}"]);
    let config = test_config(format!("{}/token", mock_server.uri()), browser_opener);

    let result = MalClient::new(reqwest::Client::new(), FailingSecretStore)
        .authenticate_with_config(config)
        .await;

    assert!(
        matches!(&result, Err(AuthError::SecretStore(SecretStoreError::Backend(msg))) if msg == "test failure"),
        "{result:?}"
    );
    assert_generic_failed_page(&rx.recv().await.unwrap());
}

#[tokio::test]
async fn return_browser_inaccessible_when_browser_cannot_be_opened() {
    let browser_opener: BrowserOpener = Box::new(|_| Err("no browser".to_string()));
    let secret_store = InMemorySecretStore::default();
    let config = test_config(UNUSED_TOKEN_URL.to_string(), browser_opener);

    let result = MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await;

    assert!(
        matches!(&result, Err(AuthError::BrowserInaccessible(msg)) if msg == "no browser"),
        "{result:?}"
    );
    assert_nothing_stored(&secret_store);
}

#[tokio::test]
async fn return_timeout_when_nobody_connects() {
    let (browser_opener, mut rx) = fake_browser(vec![]);
    let secret_store = InMemorySecretStore::default();
    let mut config = test_config(UNUSED_TOKEN_URL.to_string(), browser_opener);
    config.accept_deadline = Duration::from_millis(100);

    let result = MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await;

    assert!(matches!(result, Err(AuthError::Timeout)), "{result:?}");
    assert_nothing_stored(&secret_store);
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn return_ports_unavailable_when_all_callback_ports_are_taken() {
    // Keep the listener alive for the whole test so the port stays taken.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("Free port is bound");
    let (browser_opener, mut rx) = fake_browser(vec!["/callback?code=test-code&state={state}"]);
    let secret_store = InMemorySecretStore::default();
    let mut config = test_config(UNUSED_TOKEN_URL.to_string(), browser_opener);
    config.callback_addresses = vec![taken.local_addr().expect("Listener is bound")];

    let result = MalClient::new(reqwest::Client::new(), secret_store.clone())
        .authenticate_with_config(config)
        .await;

    assert!(matches!(result, Err(AuthError::PortsUnavailable)), "{result:?}");
    assert_nothing_stored(&secret_store);
    assert!(rx.recv().await.is_none());
}
