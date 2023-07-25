use nvd_api::{cve::CVERequest, RequestExecutor};
use nvd_models::cve::Response;
use reqwest::Error;
use tokio_retry::{strategy::{ExponentialBackoff, jitter}, Retry};

extern crate nvd_api;

#[tokio::main]
async fn main() {
    let retry_strategy = ExponentialBackoff::from_millis(5)
        .map(jitter)
        .take(10);

    async fn perform_cve_high_request() -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            .with_cvss_v3_severity("HIGH".to_string())
            .execute()
            .await
    }

    async fn perform_cve_critical_request() -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            .with_cvss_v3_severity("CRITICAL".to_string())
            .execute()
            .await
    }

    let results_high = Retry::spawn(retry_strategy.clone(), perform_cve_high_request).await;
    let results_critical = Retry::spawn(retry_strategy.clone(), perform_cve_critical_request).await;

    println!("Total number of CVEs on NVD with CVSS v3 Severity High {}", results_high
        .ok()
        .map(|r| r.total_results.to_string())
        .unwrap_or("-".to_string()));
    println!("Total number of CVEs on NVD with CVSS v3 Severity Critical {}", results_critical
        .ok()
        .map(|r| r.total_results.to_string())
        .unwrap_or("-".to_string()));
}