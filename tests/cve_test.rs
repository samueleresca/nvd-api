use chrono::{DateTime, TimeZone, Utc};
use nvd_api::cve::CVERequest;
use nvd_api::RequestExecutor;
use nvd_models::cve::Response;
use reqwest::Error;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

mod config;

#[tokio::test]
async fn integration_cve_request_execute_and_deserialize_correctly() {
    let retry_strategy = ExponentialBackoff::from_millis(config::BASE_MS)
        .map(jitter)
        .take(config::RETRIES_TOTAL);

    // Act
    async fn perform_cve_request() -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            .with_cve_id("CVE-2022-3115".to_owned())
            .execute()
            .await
    }

    let results = Retry::spawn(retry_strategy.clone(), perform_cve_request).await;

    // Assert
    assert_eq!(results.ok().map(|r| r.vulnerabilities.len()), Some(1));
}

#[tokio::test]
async fn integration_cve_request_by_cvssv3_metric_and_date_range_execute_and_deserialize_correctly()
{
    let start_date: DateTime<Utc> = Utc.with_ymd_and_hms(2022, 1, 1, 0, 0, 0).unwrap();
    let end_date: DateTime<Utc> = Utc.with_ymd_and_hms(2022, 5, 1, 0, 0, 0).unwrap();
    let retry_strategy = ExponentialBackoff::from_millis(config::BASE_MS)
        .map(jitter)
        .take(config::RETRIES_TOTAL);

    // Act

    async fn perform_scope_unchanged_cve_request(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            // CVSS Scope Unchanged (S:U)
            .with_cvss_v3_metrics("S:U".to_string())
            .with_published_date_range(start, end)
            .execute()
            .await
    }

    async fn perform_scope_changed_cve_request(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            // CVSS Scope Unchanged (S:U)
            .with_cvss_v3_metrics("S:C".to_string())
            .with_published_date_range(start, end)
            .execute()
            .await
    }

    let results_scope_unchanged = Retry::spawn(retry_strategy.clone(), || {
        perform_scope_unchanged_cve_request(start_date, end_date)
    })
    .await;
    let results_scope_changed = Retry::spawn(retry_strategy.clone(), || {
        perform_scope_changed_cve_request(start_date, end_date)
    })
    .await;

    // Assert
    assert_eq!(
        results_scope_unchanged.ok().map(|r| r.total_results),
        Some(6602)
    );
    assert_eq!(
        results_scope_changed.ok().map(|r| r.total_results),
        Some(1462)
    );
}

#[tokio::test]
async fn integration_cve_request_by_severity_execute_and_deserialize_correctly() {
    let start_date: DateTime<Utc> = Utc.with_ymd_and_hms(2022, 1, 1, 0, 0, 0).unwrap();
    let end_date: DateTime<Utc> = Utc.with_ymd_and_hms(2022, 5, 1, 0, 0, 0).unwrap();

    let retry_strategy = ExponentialBackoff::from_millis(config::BASE_MS)
        .map(jitter)
        .take(config::RETRIES_TOTAL);

    // Act
    async fn perform_cve_high_request(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            .with_cvss_v3_severity("HIGH".to_string())
            .with_published_date_range(start, end)
            .execute()
            .await
    }

    async fn perform_cve_critical_request(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            .with_cvss_v3_severity("CRITICAL".to_string())
            .with_published_date_range(start, end)
            .execute()
            .await
    }

    async fn perform_total_request(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            .with_published_date_range(start, end)
            .execute()
            .await
    }

    let results_high = Retry::spawn(retry_strategy.clone(), || {
        perform_cve_high_request(start_date, end_date)
    })
    .await;
    let results_critical = Retry::spawn(retry_strategy.clone(), || {
        perform_cve_critical_request(start_date, end_date)
    })
    .await;
    let results_total = Retry::spawn(retry_strategy, || {
        perform_total_request(start_date, end_date)
    })
    .await;

    // Assert
    assert_eq!(results_high.ok().map(|r| r.total_results), Some(3307));
    assert_eq!(results_critical.ok().map(|r| r.total_results), Some(1298));
    assert_eq!(results_total.ok().map(|r| r.total_results), Some(8379));
}
