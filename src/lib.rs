pub mod cve_api;

use cve_api::CVERequest;

fn main() {
    let result = CVERequest::create(reqwest::Client::new()).with_cpe_name("test".to_owned());
}
