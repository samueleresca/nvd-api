use core::fmt;

use crate::{RequestExecutor, ASSIGNER, BASE_URL, DELIMITER};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use nvd_models::cve_history::Response;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum Event {
    #[serde(rename = "Initial Analysis")]
    InitialAnalysis,
    #[serde(rename = "Reanalysis")]
    Reanalysis,
    #[serde(rename = "CVE Modified")]
    CVEModified,
    #[serde(rename = "Modified Analysis")]
    ModifiedAnalysis,
    #[serde(rename = "CVE Translated")]
    CVETranslated,
    #[serde(rename = "Vendor Comment")]
    VendorComment,
    #[serde(rename = "CVE Source Update")]
    CVESourceUpdate,
    #[serde(rename = "CPE Deprecation Remap")]
    CPEDeprecationRemap,
    #[serde(rename = "CWE Remap")]
    CWERemap,
    #[serde(rename = "CVE Rejected")]
    CVERejected,
    #[serde(rename = "CVE Unrejected")]
    CVEUnrejected,
}

#[async_trait]
impl RequestExecutor<Response> for CVEChangeHistoryRequest {
    fn get_base_url(&self) -> &String {
        &self.base_url
    }

    fn get_http_client(&self) -> &Client {
        &self.http_client
    }

    fn get_api_key(&self) -> &Option<String> {
        &self.api_key
    }
}

pub struct CVEChangeHistoryRequest {
    http_client: reqwest::Client,
    api_key: Option<String>,
    base_url: String,

    cve_id: Option<String>,
    change_start_date: Option<DateTime<Utc>>,
    change_end_date: Option<DateTime<Utc>>,
    result_per_page: Option<u32>,
    start_index: Option<u32>,
}
impl CVEChangeHistoryRequest {
    pub fn create(http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            base_url: BASE_URL.to_owned() + "cvehistory/2.0",
            api_key: None,
            cve_id: None,
            change_start_date: None,
            change_end_date: None,
            result_per_page: None,
            start_index: None,
        }
    }

    pub fn with_cve_id(mut self, cve_id: String) -> Self {
        self.cve_id = Some(cve_id);
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

    pub fn with_change_range(
        mut self,
        change_start_date: DateTime<Utc>,
        change_end_date: DateTime<Utc>,
    ) -> Self {
        self.change_start_date = Some(change_start_date);
        self.change_end_date = Some(change_end_date);
        self
    }

    pub fn with_result_per_page(mut self, result_per_page: u32) -> Self {
        self.result_per_page = Some(result_per_page);
        self
    }

    pub fn with_start_index(mut self, start_index: u32) -> Self {
        self.start_index = Some(start_index);
        self
    }
}

impl fmt::Display for CVEChangeHistoryRequest {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut str: String = String::new();

        fn add_field<T: std::fmt::Display>(
            dest: &mut String,
            field_value: Option<&T>,
            field_name: &str,
        ) {
            if let Some(value) = field_value {
                dest.push_str(field_name);
                dest.push_str(ASSIGNER);
                dest.push_str(&value.to_string());
                dest.push_str(DELIMITER);
            };
        }

        add_field(&mut str, self.cve_id.as_ref(), "cveId");
        add_field(
            &mut str,
            self.change_start_date.map(|d| d.to_rfc3339()).as_ref(),
            "changeStartDate",
        );
        add_field(
            &mut str,
            self.change_end_date.map(|d| d.to_rfc3339()).as_ref(),
            "changeEndDate",
        );
        add_field(&mut str, self.start_index.as_ref(), "startIndex");
        add_field(&mut str, self.result_per_page.as_ref(), "resultsPerPage");

        if !str.is_empty() {
            let res = &str[0..str.len() - 1];
            write!(fmt, "{}", res)?
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::TimeZone;
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn cve_change_history_request_encoding_works_when_empty() {
        let result = CVEChangeHistoryRequest::create(reqwest::Client::new()).to_string();
        assert_eq!("", result)
    }

    #[test]
    fn cve_change_history_request_encoding_works() {
        let result = CVEChangeHistoryRequest::create(reqwest::Client::new())
            .with_cve_id("CVE-1993-3".to_owned())
            .with_change_range(
                Utc.with_ymd_and_hms(2023, 11, 12, 0, 0, 0).unwrap(),
                Utc.with_ymd_and_hms(2023, 11, 14, 0, 0, 0).unwrap(),
            )
            .with_start_index(1)
            .with_result_per_page(4)
            .to_string();

        assert_eq!(
            "\
        cveId=CVE-1993-3\
        &changeStartDate=2023-11-12T00:00:00+00:00\
        &changeEndDate=2023-11-14T00:00:00+00:00\
        &startIndex=1\
        &resultsPerPage=4\
        ",
            result
        );
    }

    #[tokio::test]
    async fn cve_change_history_request_execute_and_deserialize_correctly() {
        // Arrange
        let mock_server = MockServer::start().await;
        let test_data: String =
            fs::read_to_string("src/test_data/cve_change_history.json").unwrap();

        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(test_data))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Act
        let result = CVEChangeHistoryRequest::create(reqwest::Client::new())
            .override_base_url(mock_server.uri().to_string())
            .with_cve_id("CVE-1993-3".to_owned())
            .execute()
            .await;

        // Assert
        assert_eq!(
            result.ok().map(|r| r.cve_changes.map(|cc| cc.len())),
            Some(Some(1))
        );
    }
}
