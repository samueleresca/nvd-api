use nvd_api::cve_change_history::CVEChangeHistoryRequest;
use nvd_api::RequestExecutor;
use nvd_models::cve_history::Response;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

mod config;

#[tokio::test]
async fn integration_cve_change_history_request_execute_and_deserialize_correctly() {
    async fn perform_request() -> Result<Response, reqwest::Error> {
        CVEChangeHistoryRequest::create(reqwest::Client::new())
            .with_cve_id("CVE-2022-3115".to_owned())
            .execute()
            .await
    }

    let retry_strategy = ExponentialBackoff::from_millis(config::BASE_MS)
        .map(jitter)
        .take(config::RETRIES_TOTAL);
    // Act
    let result = Retry::spawn(retry_strategy, perform_request).await;
    // Assert
    assert_eq!(
        result.ok().map(|r| r.cve_changes.map(|c| c.len())),
        Some(Some(1))
    );
}
