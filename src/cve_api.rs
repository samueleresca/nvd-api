use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use nvd_models::cve_api::Response;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

pub enum VersionType {
    Including,
    Excluding,
}

impl fmt::Display for VersionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VersionType::Including => write!(f, "including"),
            VersionType::Excluding => write!(f, "excluding"),
        }
    }
}

#[async_trait]
trait Request<T> {
    // Associated function signature; `Self` refers to the implementor type.
    async fn execute(&self) -> Result<T, reqwest::Error>;
}

const DELIMITER: &str = "&";
const ASSIGNER: &str = "=";
const CVE_API_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'#');

fn build_kv(name: &str, value: &str) -> String {
    let mut str: String = String::from(name);
    str.push_str(ASSIGNER);
    str.push_str(value);
    str.push_str(DELIMITER);

    str
}

fn build_single(name: &str) -> String {
    let mut str: String = String::from(name);
    str.push_str(DELIMITER);

    str
}

pub struct CVEClient;

impl CVEClient {}

pub struct CVERequest {
    http_client: reqwest::Client,
    api_key: Option<String>,
    base_url: String,

    cpe_name: Option<String>,
    cve_id: Option<String>,
    cvss_v2_metrics: Option<String>, // TODO: Replace with Strong Typed
    cvss_v2_severity: Option<String>,
    cvss_v3_metrics: Option<String>, // TODO: Replace with Strong Typed
    cvss_v3_severity: Option<String>,
    cwe_id: Option<String>,
    has_cert_alerts: Option<bool>,
    has_cert_notes: Option<bool>,
    hasKev: Option<bool>,
    hasOval: Option<bool>,
    isVulnerable: Option<bool>,
    keywordExactMatch: Option<bool>,
    keywordSearch: Option<String>,
    lastModStartDate: Option<DateTime<Utc>>,
    lastModEndDate: Option<DateTime<Utc>>,
    noRejected: Option<bool>,
    pubStartDate: Option<DateTime<Utc>>,
    pubEndDate: Option<DateTime<Utc>>,
    resultPerPage: Option<u32>,
    startIndex: Option<u32>,
    sourceIdentifier: Option<String>,
    versionStart: Option<String>,
    versionStartType: Option<VersionType>,
    versionEnd: Option<String>,
    versionEndType: Option<VersionType>,
    virtualMatchString: Option<String>,
}

impl CVERequest {
    pub fn create(http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            base_url: CVE_API_BASE_URL.to_owned(),
            api_key: None,
            cpe_name: None,
            cve_id: None,
            cvss_v2_metrics: None,
            cvss_v2_severity: None,
            cvss_v3_metrics: None,
            cvss_v3_severity: None,
            cwe_id: None,
            has_cert_alerts: None,
            has_cert_notes: None,
            hasKev: None,
            hasOval: None,
            isVulnerable: None,
            keywordExactMatch: None,
            keywordSearch: None,
            lastModStartDate: None,
            lastModEndDate: None,
            noRejected: None,
            pubStartDate: None,
            pubEndDate: None,
            resultPerPage: None,
            startIndex: None,
            sourceIdentifier: None,
            versionStart: None,
            versionStartType: None,
            versionEnd: None,
            versionEndType: None,
            virtualMatchString: None,
        }
    }

    pub fn with_cpe_name(mut self, cpeName: String) -> Self {
        self.cpe_name = Some(cpeName);
        self
    }

    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    pub fn override_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    pub fn with_cve_id(mut self, cve_id: String) -> Self {
        self.cve_id = Some(cve_id);
        self
    }

    pub fn with_cvss_v2_metrics(mut self, cvss_v2_metrics: String) -> Self {
        self.cvss_v2_metrics = Some(cvss_v2_metrics);
        self
    }

    pub fn with_cvss_v2_severity(mut self, cvss_v2_severity: String) -> Self {
        self.cvss_v2_severity = Some(cvss_v2_severity);
        self
    }

    pub fn with_cvss_v3_metrics(mut self, cvss_v3_metrics: String) -> Self {
        self.cvss_v3_metrics = Some(cvss_v3_metrics);
        self
    }

    pub fn with_cvss_v3_severity(mut self, cvss_v3_severity: String) -> Self {
        self.cvss_v3_severity = Some(cvss_v3_severity);
        self
    }

    pub fn with_cwe_id(mut self, cwe_id: String) -> Self {
        self.cwe_id = Some(cwe_id);
        self
    }

    pub fn has_cert_alerts(mut self) -> Self {
        self.has_cert_alerts = Some(true);
        self
    }

    pub fn has_cert_notes(mut self) -> Self {
        self.has_cert_notes = Some(true);
        self
    }

    pub fn has_kev(mut self) -> Self {
        self.hasKev = Some(true);
        self
    }

    pub fn has_oval(mut self) -> Self {
        self.hasOval = Some(true);
        self
    }

    pub fn is_vulnerable_to_cpe(mut self, cpe_name: String) -> Self {
        self.isVulnerable = Some(true);
        self.cpe_name = Some(cpe_name);
        self
    }

    pub fn with_keyword(mut self, keyword_search: String, exact_match: bool) -> Self {
        self.keywordExactMatch = if exact_match { Some(true) } else { None };
        self.keywordSearch = Some(keyword_search);
        self
    }

    pub fn with_last_modified_date_range(
        mut self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Self {
        self.lastModStartDate = Some(start);
        self.lastModEndDate = Some(end);
        self
    }

    pub fn is_not_rejected(mut self) -> Self {
        self.noRejected = Some(true);
        self
    }

    pub fn with_published_date_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.pubStartDate = Some(start);
        self.pubEndDate = Some(end);
        self
    }

    pub fn result_per_page(mut self, page_limit: u32) -> Self {
        self.resultPerPage = Some(page_limit);
        self
    }

    pub fn with_start_index(mut self, start_index: u32) -> Self {
        self.startIndex = Some(start_index);
        self
    }

    pub fn with_source_identifier(mut self, source_identifier: String) -> Self {
        self.sourceIdentifier = Some(source_identifier);
        self
    }

    pub fn with_version_end(mut self, version_end: String, version_type: VersionType) -> Self {
        self.versionEnd = Some(version_end);
        self.versionEndType = Some(version_type);
        self
    }

    pub fn with_version_start(mut self, version_start: String, version_type: VersionType) -> Self {
        self.versionStart = Some(version_start);
        self.versionStartType = Some(version_type);
        self
    }

    pub fn with_virtual_match_string(mut self, virtual_match_string: String) -> Self {
        self.virtualMatchString = Some(virtual_match_string);
        self
    }
}

impl fmt::Display for CVERequest {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut str: String = String::new();

        match &self.cpe_name {
            Some(value) => {
                str.push_str(&build_kv("cpeName", value));
            }
            _ => {}
        }

        match &self.cve_id {
            Some(value) => {
                str.push_str(&build_kv("cveId", value));
            }
            _ => {}
        }

        match &self.cvss_v2_metrics {
            Some(value) => {
                str.push_str(&build_kv("cvssV2Metrics", value));
            }
            _ => {}
        }

        match &self.cvss_v2_severity {
            Some(value) => {
                str.push_str(&build_kv("cvssV2Severity", value));
            }
            _ => {}
        }

        match &self.cvss_v3_metrics {
            Some(value) => {
                str.push_str(&build_kv("cvssV3Metrics", value));
            }
            _ => {}
        }

        match &self.cvss_v3_severity {
            Some(value) => {
                str.push_str(&build_kv("cvssV3Severity", value));
            }
            _ => {}
        }

        match &self.cwe_id {
            Some(value) => {
                str.push_str(&build_kv("cweId", value));
            }
            _ => {}
        }

        match self.has_cert_alerts {
            Some(_) => {
                str.push_str(&build_single("hasCertAlerts"));
            }
            _ => {}
        }

        match self.has_cert_notes {
            Some(_) => {
                str.push_str(&build_single("hasCertNotes"));
            }
            _ => {}
        }

        match self.hasKev {
            Some(_) => {
                str.push_str(&build_single("hasKev"));
            }
            _ => {}
        }

        match self.hasOval {
            Some(_) => {
                str.push_str(&build_single("hasOval"));
            }
            _ => {}
        }

        match self.isVulnerable {
            Some(_) => {
                str.push_str(&build_single("isVulnerable"));
            }
            _ => {}
        }

        match self.keywordExactMatch {
            Some(_) => {
                str.push_str(&build_single("keywordExactMatch"));
            }
            _ => {}
        }

        match &self.keywordSearch {
            Some(value) => {
                str.push_str(&build_kv("keywordSearch", value));
            }
            _ => {}
        }

        match self.lastModStartDate {
            Some(value) => {
                str.push_str(&build_kv("lastModStartDate", &value.to_rfc3339()));
            }
            _ => {}
        }

        match self.lastModEndDate {
            Some(value) => {
                str.push_str(&build_kv("lastModEndDate", &value.to_rfc3339()));
            }
            _ => {}
        }

        match self.noRejected {
            Some(_) => {
                str.push_str(&build_single("noRejected"));
            }
            _ => {}
        }

        match self.pubStartDate {
            Some(value) => {
                str.push_str(&build_kv("pubStartDate", &value.to_rfc3339()));
            }
            _ => {}
        }

        match self.pubEndDate {
            Some(value) => {
                str.push_str(&build_kv("pubEndDate", &value.to_rfc3339()));
            }
            _ => {}
        }

        match self.resultPerPage {
            Some(value) => {
                str.push_str(&build_kv("resultPerPage", &value.to_string()));
            }
            _ => {}
        }

        match self.startIndex {
            Some(value) => {
                str.push_str(&build_kv("startIndex", &value.to_string()));
            }
            _ => {}
        }

        match &self.sourceIdentifier {
            Some(value) => {
                str.push_str(&build_kv("sourceIdentifier", value));
            }
            _ => {}
        }

        match &self.versionStart {
            Some(value) => {
                str.push_str(&build_kv("versionStart", value));
            }
            _ => {}
        }

        match &self.versionStartType {
            Some(value) => {
                str.push_str(&build_kv("versionStartType", &value.to_string()));
            }
            _ => {}
        }

        match &self.versionEnd {
            Some(value) => {
                str.push_str(&build_kv("versionEnd", value));
            }
            _ => {}
        }

        match &self.versionEndType {
            Some(value) => {
                str.push_str(&build_kv("versionEndType", &value.to_string()));
            }
            _ => {}
        }

        match &self.virtualMatchString {
            Some(value) => {
                str.push_str(&build_kv("virtualMatchString", value));
            }
            _ => {}
        }

        if !str.is_empty() {
            let result = &str[0..str.len() - 1];
            write!(fmt, "{}", result);
        }

        Ok(())
    }
}

#[async_trait]
impl Request<Response> for CVERequest {
    async fn execute(&self) -> Result<Response, reqwest::Error> {
        let data = &self.to_string();

        let encoder = utf8_percent_encode(data, FRAGMENT);
        let encoded_data: String = encoder.collect();
        let full_url = self.base_url.to_owned() + "?" + &encoded_data;
        let mut builder = self.http_client.get(full_url);

        match &self.api_key {
            Some(v) => {
                builder = builder.header("api_key", v.to_string());
            }
            None => {}
        }

        Ok(builder.send().await?.json::<Response>().await?)
    }
}

fn main() {
    let _req = CVERequest::create(reqwest::Client::new())
        .with_cvss_v2_metrics("".to_string())
        .with_cvss_v3_severity("".to_string());
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn cve_request_encoding_works_when_empty() {
        let result = CVERequest::create(reqwest::Client::new()).to_string();
        assert_eq!("", result)
    }
    #[test]
    fn cve_request_encoding_works() {
        let result = CVERequest::create(reqwest::Client::new())
            .with_cve_id("CVE-1993-3".to_owned())
            .with_cvss_v2_metrics("cvssV2Metrics_value".to_owned())
            .with_cvss_v2_severity("cvssV2Severity_value".to_owned())
            .with_cvss_v3_metrics("cvssV3Metrics_value".to_owned())
            .with_cvss_v3_severity("cvssV3Severity_value".to_owned())
            .with_cwe_id("cwe_id_value".to_owned())
            .has_cert_alerts()
            .has_cert_notes()
            .has_kev()
            .has_oval()
            .is_vulnerable_to_cpe("cpe_name".to_owned())
            .with_keyword("keyword_value".to_owned(), true)
            .is_not_rejected()
            .result_per_page(31)
            .with_start_index(1)
            .with_source_identifier("source_indentifier_value".to_owned())
            .with_version_start("0.0.1".to_owned(), VersionType::Excluding)
            .with_version_end("0.0.2".to_owned(), VersionType::Including)
            .with_virtual_match_string("match_string".to_owned())
            .to_string();

        assert_eq!(
            "\
        cpeName=cpe_name&cveId=CVE-1993-3\
        &cvssV2Metrics=cvssV2Metrics_value\
        &cvssV2Severity=cvssV2Severity_value\
        &cvssV3Metrics=cvssV3Metrics_value\
        &cvssV3Severity=cvssV3Severity_value\
        &cweId=cwe_id_value\
        &hasCertAlerts\
        &hasCertNotes\
        &hasKev\
        &hasOval\
        &isVulnerable\
        &keywordExactMatch\
        &keywordSearch=keyword_value\
        &noRejected\
        &resultPerPage=31\
        &startIndex=1\
        &sourceIdentifier=source_indentifier_value\
        &versionStart=0.0.1\
        &versionStartType=excluding\
        &versionEnd=0.0.2\
        &versionEndType=including\
        &virtualMatchString=match_string\
        ",
            result
        );
    }

    #[tokio::test]
    async fn cve_request_execute_and_deserialize_correctly() {
        // Arrange
        let mock_server = MockServer::start().await;
        let test_data: String = fs::read_to_string("src/test_data/response.json").unwrap();

        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(test_data))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Act
        let result = CVERequest::create(reqwest::Client::new())
            .override_base_url(mock_server.uri().to_string())
            .with_cve_id("CVE-1993-3".to_owned())
            .execute()
            .await;

        // Assert
        assert!(result.is_ok());
        
        let vulnerabilities = result.ok().unwrap().vulnerabilities;
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].cve.id, "CVE-2019-1010218");
    }

    #[tokio::test]
    async fn cve_request_handle_4xx_error() {
        // Arrange
        let mock_server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Act
        let result = CVERequest::create(reqwest::Client::new())
            .override_base_url(mock_server.uri().to_string())
            .with_cve_id("CVE-1993-3".to_owned())
            .execute()
            .await;

        // Assert
        assert!(result.is_err());
    }
}
