use nvd_api::cpe::CPERequest;
use nvd_api::RequestExecutor;

#[tokio::test]
async fn integration_cpe_request_execute_and_deserialize_correctly() {
    // Act
    let result = CPERequest::create(reqwest::Client::new())
        .with_cpe_match_string("cpe:2.3:o:microsoft:windows_10:1511".to_owned())
        .execute()
        .await;

    // Assert
    assert_eq!(result.ok().map(|r| r.products.len()), Some(3));
}
