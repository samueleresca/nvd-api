use nvd_api::cpe::CPERequest;
use nvd_api::RequestExecutor;
use nvd_models::cpe::Response;
use tokio_retry::{
    strategy::{jitter, ExponentialBackoff},
    Retry,
};

mod config;

#[tokio::test]
async fn integration_cpe_request_execute_and_deserialize_correctly() {
    async fn perform_request() -> Result<Response, reqwest::Error> {
        CPERequest::create(reqwest::Client::new())
            .with_cpe_match_string("cpe:2.3:o:microsoft:windows_10:1511".to_owned())
            .execute()
            .await
    }

    let retry_strategy = ExponentialBackoff::from_millis(config::BASE_MS)
        .map(jitter)
        .take(config::RETRIES_TOTAL);

    // Act
    let result = Retry::spawn(retry_strategy, perform_request).await;
    // Assert
    assert_eq!(result.ok().map(|r| r.products.len()), Some(3));
}
