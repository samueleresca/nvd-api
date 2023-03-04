use nvd_api::cve::CVERequest;
use nvd_api::RequestExecutor;

#[tokio::test]
async fn integration_cve_request_execute_and_deserialize_correctly() {
    // Act
    let result = CVERequest::create(reqwest::Client::new())
        .with_cve_id("CVE-2022-3115".to_owned())
        .execute()
        .await;

    // Assert
    assert_eq!(result.ok().map(|r| r.vulnerabilities.len()), Some(1));
}
