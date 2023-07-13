use nvd_api::cpe_match::CPEMatchRequest;
use nvd_api::RequestExecutor;
use nvd_models::cpe_match::Response;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

mod config;

#[tokio::test]
async fn integration_cpe_match_request_execute_and_deserialize_correctly() {
    async fn perform_request() -> Result<Response, reqwest::Error> {
        CPEMatchRequest::create(reqwest::Client::new())
            .with_cve_id("CVE-2022-32223".to_owned())
            .execute()
            .await
    }

    let retry_strategy = ExponentialBackoff::from_millis(config::BASE_MS)
        .map(jitter)
        .take(config::RETRIES_TOTAL);

    // Act
    let result = Retry::spawn(retry_strategy, perform_request).await;
    // Assert
    assert_eq!(result.ok().map(|r| r.total_results), Some(6));
}
