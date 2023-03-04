use nvd_api::cpe_match::CPEMatchRequest;
use nvd_api::RequestExecutor;

#[tokio::test]
async fn integration_cpe_match_request_execute_and_deserialize_correctly() {
    // Act
    let result = CPEMatchRequest::create(reqwest::Client::new())
        .with_cve_id("CVE-2022-32223".to_owned())
        .execute()
        .await;

    // Assert
    assert_eq!(result.ok().map(|r| r.match_strings.len()), Some(6));
}
