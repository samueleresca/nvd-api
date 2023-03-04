use nvd_api::cve_change_history::CVEChangeHistoryRequest;
use nvd_api::RequestExecutor;

#[tokio::test]
async fn integration_cve_change_history_request_execute_and_deserialize_correctly() {
    // Act
    let result = CVEChangeHistoryRequest::create(reqwest::Client::new())
        .with_cve_id("CVE-2022-3115".to_owned())
        .execute()
        .await;

    // Assert
    assert_eq!(
        result.ok().map(|r| r.cve_changes.map(|c| c.len())),
        Some(Some(1))
    );
}
