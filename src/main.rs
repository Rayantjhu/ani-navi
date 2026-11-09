use ani_navi::infra::my_anime_list::MalClient;
use ani_navi::infra::secret_store::KeyringSecretStore;

#[tokio::main]
async fn main() {
    let http_client = reqwest::Client::builder()
        // Prevent SSRF vulnerabilities from redirects.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should be built");

    let mal_client = MalClient::new(http_client, KeyringSecretStore);
    mal_client.authenticate().await.unwrap();
}
