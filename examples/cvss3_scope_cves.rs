use nvd_api::{cve::CVERequest, RequestExecutor};
use nvd_models::cve::Response;
use reqwest::Error;
use tokio_retry::{
    strategy::{jitter, ExponentialBackoff},
    Retry,
};

extern crate nvd_api;

#[tokio::main]
async fn main() {
    let retry_strategy = ExponentialBackoff::from_millis(5).map(jitter).take(10);

    async fn perform_scope_unchanged_cve_request() -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            // CVSS Scope Unchanged (S:U)
            .with_cvss_v3_metrics("S:U".to_string())
            .execute()
            .await
    }

    async fn perform_scope_changed_cve_request() -> Result<Response, Error> {
        CVERequest::create(reqwest::Client::new())
            // CVSS Scope Changed (S:C)
            .with_cvss_v3_metrics("S:C".to_string())
            .execute()
            .await
    }

    let results_scope_unchanged =
        Retry::spawn(retry_strategy.clone(), perform_scope_unchanged_cve_request).await;
    let results_scope_changed =
        Retry::spawn(retry_strategy.clone(), perform_scope_changed_cve_request).await;

    println!(
        "Total number of CVEs on NVD with Scope:Unchanged {}",
        results_scope_unchanged
            .ok()
            .map(|r| r.total_results)
            .unwrap()
    );
    println!(
        "Total number of CVEs on NVD with Scope:Changed {}",
        results_scope_changed.ok().map(|r| r.total_results).unwrap()
    );
}
