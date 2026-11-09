use crate::infra::my_anime_list::MalClient;
use crate::infra::oauth_tokens::OAuthTokens;
use crate::infra::secret_store::{SecretStore, SecretStoreError};
use crate::infra::{html, local_http, secret_store};
use oauth2::basic::{BasicClient, BasicErrorResponse, BasicTokenResponse};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet, HttpClientError, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RequestTokenError, TokenResponse, TokenUrl,
};
use reqwest::Url;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::time::Instant;

/** The localhost address: `127.0.0.1`. Used to create the TCP listener to receive the auth callback. */
const LOCAL_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

/** Three possible callback addresses with three different ports. When one port is in use, another can be tried. */
const CALLBACK_ADDRESSES: [SocketAddr; 3] = [
    SocketAddr::new(LOCAL_ADDRESS, 28765),
    SocketAddr::new(LOCAL_ADDRESS, 38765),
    SocketAddr::new(LOCAL_ADDRESS, 48765),
];

pub type BrowserOpener = Box<dyn Fn(&str) -> Result<(), String> + Send>;

pub struct AuthConfig {
    pub callback_addresses: Vec<SocketAddr>,
    pub auth_url: String,
    pub token_url: String,
    pub open_browser: BrowserOpener,
    pub accept_deadline: Duration,
    pub read_timeout: Duration,
}

impl AuthConfig {
    pub fn my_anime_list() -> Self {
        Self {
            callback_addresses: CALLBACK_ADDRESSES.to_vec(),
            auth_url: "https://myanimelist.net/v1/oauth2/authorize".to_string(),
            token_url: "https://myanimelist.net/v1/oauth2/token".to_string(),
            // Open the auth URL detached to make sure it cannot block.
            open_browser: Box::new(|url| open::that_detached(url).map_err(|e| e.to_string())),
            accept_deadline: Duration::from_mins(5),
            read_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    PortsUnavailable,
    BrowserInaccessible(String),
    ConnectionFailed(std::io::Error),
    Timeout,
    Callback(CallbackReadError),
    TokenRequest(RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>),
    TokenRead(TokenReadError),
    SecretStore(SecretStoreError),
}

impl<S: SecretStore + 'static> MalClient<S> {
    /** Performs authentication and authorization of MyAnimeList API. */
    pub async fn authenticate(&self) -> Result<(), AuthError> {
        self.authenticate_with_config(AuthConfig::my_anime_list()).await
    }

    pub async fn authenticate_with_config(&self, config: AuthConfig) -> Result<(), AuthError> {
        // Bind the listener first to determine the callback address.
        let tcp_listener = create_tcp_listener(&config.callback_addresses)
            .await
            .ok_or(AuthError::PortsUnavailable)?;

        let addr = tcp_listener.local_addr().expect("Listener is already bound.");
        let oauth_client = create_oauth_client(&addr, config.auth_url, config.token_url);

        // MAL only supports the plain method.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_plain();
        let (auth_url, csrf_state) = oauth_client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .url();

        (config.open_browser)(auth_url.as_str()).map_err(AuthError::BrowserInaccessible)?;

        // Failed requests can be retried.
        let mut accept_retries_left: u8 = 3;
        let deadline = Instant::now() + config.accept_deadline;

        let (mut stream, auth_code) = loop {
            let mut stream = match tokio::time::timeout_at(deadline, tcp_listener.accept()).await {
                Err(_elapsed) => return Err(AuthError::Timeout),
                Ok(Ok((stream, _))) => stream,
                // Accepting can fail on transient system errors, such as too many open files.
                Ok(Err(_)) if accept_retries_left > 0 => {
                    accept_retries_left -= 1;
                    continue;
                }
                Ok(Err(e)) => return Err(AuthError::ConnectionFailed(e)),
            };

            let first_line = tokio::time::timeout(config.read_timeout, BufReader::new(&mut stream).lines().next_line())
                .await
                .ok() // Timed out -> None
                .and_then(Result::ok) // IO error -> None
                .flatten() // EOF -> None
                .unwrap_or_default();

            match read_callback(&first_line, &csrf_state) {
                Ok(code) => break (stream, code),
                // Not a /callback request, e.g. /favicon.ico or a browser preconnect that sends nothing.
                // Browsers do this routinely, so return a 404 and keep waiting until the deadline.
                Err(CallbackReadError::InvalidRequest) => {
                    // Ignore error if writing back to the stream fails.
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    continue;
                }
                Err(e) => {
                    // Ignore error if writing back to the stream fails.
                    let _ = stream.write_all(callback_failed_response(&e).as_bytes()).await;
                    return Err(AuthError::Callback(e));
                }
            }
        };

        let secret_store = Arc::clone(&self.secret_store);
        let (html_result, result) =
            match complete_auth(&self.http_client, auth_code, &oauth_client, pkce_verifier, secret_store).await {
                Ok(()) => (AuthHtmlResult::Success, Ok(())),
                Err(e) => (AuthHtmlResult::GenericFailed, Err(e)),
            };

        let _ = stream.write_all(html_response(html_result).as_bytes()).await;
        result
    }
}

/** Tries to bind a TCP listener to each of the `addresses` in order. The first address that can be bound is returned.
Really useful when multiple return URLs are supported, as authorization doesn't fail when a port turns out to be taken.

Returns `None` if none of the `addresses` can be bound.
*/
async fn create_tcp_listener(addresses: &[SocketAddr]) -> Option<TcpListener> {
    for addr in addresses {
        if let Ok(listener) = TcpListener::bind(addr).await {
            return Some(listener);
        }
    }

    None
}

fn create_oauth_client(callback_addr: &SocketAddr, auth_url: String, token_url: String) -> MalOAuthClient {
    let client_id = ClientId::new(env!("MY_ANIME_LIST_CLIENT_ID").to_string());
    let auth_uri = AuthUrl::new(auth_url).expect("Supplied auth URL is valid");
    let token_uri = TokenUrl::new(token_url).expect("Supplied token URL is valid");
    let redirect_uri = RedirectUrl::new(format!("http://{callback_addr}/callback"))
        .expect("Redirect URL from a bound socket address is valid");

    BasicClient::new(client_id)
        .set_auth_uri(auth_uri)
        .set_token_uri(token_uri)
        .set_redirect_uri(redirect_uri)
}

async fn complete_auth<S: SecretStore + 'static>(
    http_client: &reqwest::Client,
    auth_code: AuthorizationCode,
    oauth_client: &MalOAuthClient,
    pkce_verifier: PkceCodeVerifier,
    secret_store: Arc<S>,
) -> Result<(), AuthError> {
    let token_response = token_request(http_client, oauth_client, auth_code, pkce_verifier)
        .await
        .map_err(AuthError::TokenRequest)?;
    let tokens = tokens_from_token_response(&token_response, SystemTime::now()).map_err(AuthError::TokenRead)?;

    let tokens_json = serde_json::to_string(&tokens).expect("OAuthTokens is a valid JSON struct");

    // Keyring calls are blocking, so run them on tokio's blocking thread pool.
    tokio::task::spawn_blocking(move || secret_store.set(secret_store::MAL_KEY, &tokens_json))
        .await
        // A panic in the store is a bug: re-raise it here instead of turning it into an `AuthError`.
        .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))
        .map_err(AuthError::SecretStore)?;

    Ok(())
}

/** A `BasicClient` with only the auth and token endpoints set.
*/
type MalOAuthClient = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

async fn token_request(
    http_client: &reqwest::Client,
    oauth_client: &MalOAuthClient,
    authorization_code: AuthorizationCode,
    pkce_verifier: PkceCodeVerifier,
) -> Result<BasicTokenResponse, RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>> {
    oauth_client
        .exchange_code(authorization_code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(http_client)
        .await
}

fn callback_failed_response(error: &CallbackReadError) -> String {
    let auth_html_type = match error {
        CallbackReadError::AuthorizationFailed(auth_failed) => AuthHtmlResult::FailedWithMessage(auth_failed),
        _ => AuthHtmlResult::GenericFailed,
    };

    html_response(auth_html_type)
}

#[derive(Debug, PartialEq)]
pub struct AuthFailed {
    error: String,
    message: Option<String>,
    hint: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum CallbackReadError {
    InvalidRequest,
    AuthorizationFailed(AuthFailed),
    MissingAuthorizationCode,
    MissingState,
    MismatchedState,
}

/** Reads the callback's `first_line`. If the path is the `/callback` path, the query parameters
include the `state` and `code`, and the `state` matches the `expected_state`, is the authorization
code returned.
*/
fn read_callback(first_line: &str, expected_state: &CsrfToken) -> Result<AuthorizationCode, CallbackReadError> {
    let path = match first_line.split_whitespace().nth(1) {
        Some(path) => path,
        None => return Err(CallbackReadError::InvalidRequest),
    };

    // The base can be anything, as we just require it to parse the path.
    let url = Url::parse("http://localhost")
        .expect("Hardcoded base URL is valid")
        .join(path)
        .map_err(|_| CallbackReadError::InvalidRequest)?;

    if url.path() != "/callback" {
        return Err(CallbackReadError::InvalidRequest);
    }

    let mut query_parameters: HashMap<String, String> = url.query_pairs().into_owned().collect();

    if let Some(error) = query_parameters.remove("error") {
        let message = query_parameters.remove("message");
        let hint = query_parameters.remove("hint");
        return Err(CallbackReadError::AuthorizationFailed(AuthFailed {
            error,
            message,
            hint,
        }));
    };

    let authorization_code = query_parameters
        .remove("code")
        .map(AuthorizationCode::new)
        .ok_or(CallbackReadError::MissingAuthorizationCode)?;
    let state = query_parameters
        .remove("state")
        .map(CsrfToken::new)
        .ok_or(CallbackReadError::MissingState)?;

    if state.secret() != expected_state.secret() {
        return Err(CallbackReadError::MismatchedState);
    }

    Ok(authorization_code)
}

#[derive(Debug, PartialEq)]
pub enum TokenReadError {
    MissingRefreshToken,
    MissingExpiresIn,
    InvalidExpiry,
}

/** Reads the basic token response and parses it into the access & refresh tokens and calculates
the expiry Unix timestamp.

Returns an error if the refresh token or expiry are missing from the token response.
*/
fn tokens_from_token_response(
    token_response: &BasicTokenResponse,
    now: SystemTime,
) -> Result<OAuthTokens, TokenReadError> {
    let access_token = token_response.access_token().secret();
    let refresh_token = token_response
        .refresh_token()
        .ok_or(TokenReadError::MissingRefreshToken)?
        .secret();
    let expires_in = token_response.expires_in().ok_or(TokenReadError::MissingExpiresIn)?;

    if expires_in.is_zero() {
        return Err(TokenReadError::InvalidExpiry);
    };

    let expires_at = now
        .checked_add(expires_in)
        .ok_or(TokenReadError::InvalidExpiry)?
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is after Unix epoch");

    let tokens = OAuthTokens {
        access_token: access_token.to_string(),
        refresh_token: refresh_token.to_string(),
        expires_at: expires_at.as_secs(),
    };
    Ok(tokens)
}

enum AuthHtmlResult<'a> {
    Success,
    FailedWithMessage(&'a AuthFailed),
    GenericFailed,
}

fn html_response(result: AuthHtmlResult) -> String {
    let (html, status) = match result {
        AuthHtmlResult::Success => (include_str!("auth_pages/success.html").to_string(), "200 OK"),
        AuthHtmlResult::FailedWithMessage(e) => (
            format!(
                include_str!("auth_pages/failed.html"),
                error = html::escape_html(&e.error),
                message = html::escape_html(e.message.as_deref().unwrap_or_default()),
                hint = html::escape_html(e.hint.as_deref().unwrap_or_default()),
            ),
            "400 Bad Request",
        ),
        AuthHtmlResult::GenericFailed => (
            include_str!("auth_pages/generic_failed.html").to_string(),
            "400 Bad Request",
        ),
    };

    local_http::http_response(status, &html)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod read_callback {
        use super::*;

        #[test]
        fn return_invalid_request_when_line_is_empty() {
            assert_eq!(
                read_callback("", &csrf_token("")).unwrap_err(),
                CallbackReadError::InvalidRequest
            );
        }

        #[test]
        fn return_invalid_request_when_line_does_not_have_path() {
            assert_eq!(
                read_callback("GET", &csrf_token("")).unwrap_err(),
                CallbackReadError::InvalidRequest
            );
        }

        #[test]
        fn return_invalid_request_when_path_is_not_callback() {
            assert_eq!(
                read_callback("GET /not-callback?code=a&state=b HTTP/1.1\r\n", &csrf_token("")).unwrap_err(),
                CallbackReadError::InvalidRequest
            );
        }

        #[test]
        fn return_failed_without_message_or_hint_when_error_exists() {
            let first_line = "GET /callback?error=access-denied HTTP/1.1\r\n";

            let expected_auth_failed = AuthFailed {
                error: String::from("access-denied"),
                message: None,
                hint: None,
            };

            assert_eq!(
                read_callback(first_line, &csrf_token("")).unwrap_err(),
                CallbackReadError::AuthorizationFailed(expected_auth_failed)
            );
        }

        #[test]
        fn return_failed_with_message_without_hint_when_error_and_message_exist() {
            let first_line = "GET /callback?error=invalid-request&message=Request%20invalid HTTP/1.1\r\n";

            let expected_auth_failed = AuthFailed {
                error: String::from("invalid-request"),
                message: Some(String::from("Request invalid")),
                hint: None,
            };

            assert_eq!(
                read_callback(first_line, &csrf_token("")).unwrap_err(),
                CallbackReadError::AuthorizationFailed(expected_auth_failed)
            );
        }

        #[test]
        fn return_failed_with_hint_without_message_when_error_and_hint_exist() {
            let first_line = "GET /callback?error=invalid-request&hint=Request%20invalid HTTP/1.1\r\n";

            let expected_auth_failed = AuthFailed {
                error: String::from("invalid-request"),
                message: None,
                hint: Some(String::from("Request invalid")),
            };

            assert_eq!(
                read_callback(first_line, &csrf_token("")).unwrap_err(),
                CallbackReadError::AuthorizationFailed(expected_auth_failed)
            );
        }

        #[test]
        fn return_failed_with_hint_and_message_when_error_message_and_hint_exist() {
            let first_line =
                "GET /callback?error=invalid-request&message=Request%20invalid&hint=Some%20hint HTTP/1.1\r\n";

            let expected_auth_failed = AuthFailed {
                error: String::from("invalid-request"),
                message: Some(String::from("Request invalid")),
                hint: Some(String::from("Some hint")),
            };

            assert_eq!(
                read_callback(first_line, &csrf_token("")).unwrap_err(),
                CallbackReadError::AuthorizationFailed(expected_auth_failed)
            );
        }

        #[test]
        fn return_failed_when_both_error_and_state_are_present() {
            let first_line = "GET /callback?error=stop-it&state=abc HTTP/1.1\r\n";

            let expected_auth_failed = AuthFailed {
                error: String::from("stop-it"),
                message: None,
                hint: None,
            };

            assert_eq!(
                read_callback(first_line, &csrf_token("")).unwrap_err(),
                CallbackReadError::AuthorizationFailed(expected_auth_failed)
            );
        }

        #[test]
        fn return_missing_authorization_code_when_code_is_missing() {
            let first_line = "GET /callback?state=mad3-0p-State HTTP/1.1\r\n";
            assert_eq!(
                read_callback(first_line, &csrf_token("")).unwrap_err(),
                CallbackReadError::MissingAuthorizationCode
            );
        }

        #[test]
        fn return_missing_state_when_state_is_missing() {
            let first_line = "GET /callback?code=mad3-0p-c0d3 HTTP/1.1\r\n";
            assert_eq!(
                read_callback(first_line, &csrf_token("")).unwrap_err(),
                CallbackReadError::MissingState
            );
        }

        #[test]
        fn return_mismatched_state_when_expected_state_does_not_match_state() {
            let first_line = "GET /callback?code=cool-code&state=awesome-state HTTP/1.1\r\n";

            assert_eq!(
                read_callback(first_line, &csrf_token("the-actual-state")).unwrap_err(),
                CallbackReadError::MismatchedState
            )
        }

        #[test]
        fn return_auth_code_when_code_and_state_are_present() -> Result<(), CallbackReadError> {
            let first_line = "GET /callback?code=cool-code&state=awesome-state HTTP/1.1\r\n";

            let authorization_code = read_callback(first_line, &csrf_token("awesome-state"))?;

            assert_eq!("cool-code", authorization_code.secret());

            Ok(())
        }

        fn csrf_token(token: &str) -> CsrfToken {
            CsrfToken::new(token.to_string())
        }
    }

    mod tokens_from_token_response {
        use super::*;
        use oauth2::basic::{BasicTokenResponse, BasicTokenType};
        use oauth2::{AccessToken, EmptyExtraTokenFields, RefreshToken};
        use std::time::Duration;

        #[test]
        fn return_missing_refresh_token_when_refresh_token_is_missing() {
            let token_response = token_response(None, None);

            assert_eq!(
                tokens_from_token_response(&token_response, fixed_now()).unwrap_err(),
                TokenReadError::MissingRefreshToken
            )
        }

        #[test]
        fn return_missing_expires_in_when_expires_in_is_missing() {
            let token_response = token_response(Some("refresh-token"), None);

            assert_eq!(
                tokens_from_token_response(&token_response, fixed_now()).unwrap_err(),
                TokenReadError::MissingExpiresIn
            )
        }

        #[test]
        fn return_invalid_expiry_when_expiry_is_zero() {
            let token_response = token_response(Some("refresh-token"), Some(0));

            assert_eq!(
                tokens_from_token_response(&token_response, fixed_now()).unwrap_err(),
                TokenReadError::InvalidExpiry
            )
        }

        #[test]
        fn return_invalid_expiry_when_expiry_is_too_high() {
            let token_response = token_response(Some("refresh-token"), Some(u64::MAX));

            assert_eq!(
                tokens_from_token_response(&token_response, fixed_now()).unwrap_err(),
                TokenReadError::InvalidExpiry
            )
        }

        #[test]
        fn return_tokens_when_response_is_valid() -> Result<(), TokenReadError> {
            let token_response = token_response(Some("refresh-token"), Some(2_415_600));
            let now = fixed_now();

            let expected_tokens = OAuthTokens {
                access_token: "access-token".to_string(),
                refresh_token: "refresh-token".to_string(),
                expires_at: 3_415_600,
            };

            assert_eq!(tokens_from_token_response(&token_response, now)?, expected_tokens);

            Ok(())
        }

        fn token_response(refresh_token: Option<&str>, expires_in: Option<u64>) -> BasicTokenResponse {
            let mut token_response = BasicTokenResponse::new(
                AccessToken::new("access-token".to_string()),
                BasicTokenType::Bearer,
                EmptyExtraTokenFields {},
            );

            if let Some(token) = refresh_token {
                let some_token = Some(RefreshToken::new(token.to_string()));
                token_response.set_refresh_token(some_token);
            }
            if let Some(expiry) = expires_in {
                let duration = Duration::from_secs(expiry);
                token_response.set_expires_in(Some(&duration));
            }

            token_response
        }

        fn fixed_now() -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
        }
    }

    mod html_response {
        use super::*;

        #[test]
        fn return_ok_with_success_page_when_successful() {
            let response = html_response(AuthHtmlResult::Success);

            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(response.ends_with(include_str!("auth_pages/success.html")));
        }

        #[test]
        fn return_bad_request_with_error_when_failed() {
            let auth_failed = AuthFailed {
                error: "Access denied".to_string(),
                message: Some("Access denied by the user".to_string()),
                hint: Some("The user has denied access".to_string()),
            };

            let response = html_response(AuthHtmlResult::FailedWithMessage(&auth_failed));

            assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
            assert!(response.contains("Access denied"));
            assert!(response.contains("Access denied by the user"));
            assert!(response.contains("The user has denied access"));
            assert!(!response.contains("{error}"));
            assert!(!response.contains("{message}"));
            assert!(!response.contains("{hint}"));
        }

        #[test]
        fn return_bad_request_without_message_or_hint_when_failed() {
            let auth_failed = AuthFailed {
                error: "Access denied".to_string(),
                message: None,
                hint: None,
            };

            let response = html_response(AuthHtmlResult::FailedWithMessage(&auth_failed));

            assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
            assert!(response.contains("Access denied"));
            assert!(!response.contains("{error}"));
            assert!(!response.contains("{message}"));
            assert!(!response.contains("{hint}"));
        }

        #[test]
        fn return_escaped_error_when_error_contains_html() {
            let auth_failed = AuthFailed {
                error: "<script>".to_string(),
                message: None,
                hint: None,
            };

            let response = html_response(AuthHtmlResult::FailedWithMessage(&auth_failed));

            assert!(response.contains("&lt;script&gt;"));
            assert!(!response.contains("<script>"));
        }
    }
}
