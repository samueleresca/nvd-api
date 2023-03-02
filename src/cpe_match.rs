use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use std::fmt;

use crate::common::{RequestExecutor, ASSIGNER, CVE_API_BASE_URL, DELIMITER};
use uuid::Uuid;

use nvd_models::cpe_match::Response;

pub struct CPEMatchRequest {
    http_client: reqwest::Client,
    api_key: Option<String>,
    base_url: String,

    cve_id: Option<String>,
    last_mod_start_date: Option<DateTime<Utc>>,
    last_mod_end_date: Option<DateTime<Utc>>,
    match_criteria_id: Option<Uuid>,
    match_string_search: Option<String>,
    result_per_page: Option<u32>,
    start_index: Option<u32>,
}

#[async_trait]
impl RequestExecutor<Response> for CPEMatchRequest {
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

impl CPEMatchRequest {
    pub fn create(http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            base_url: CVE_API_BASE_URL.to_owned(),
            api_key: None,
            cve_id: None,
            last_mod_start_date: None,
            last_mod_end_date: None,
            match_criteria_id: None,
            match_string_search: None,
            result_per_page: None,
            start_index: None,
        }
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

    pub fn with_match_string_search(mut self, match_string_search: String) -> Self {
        self.match_string_search = Some(match_string_search);
        self
    }

    pub fn with_last_modified_date_range(
        mut self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Self {
        self.last_mod_start_date = Some(start);
        self.last_mod_end_date = Some(end);
        self
    }

    pub fn with_match_criteria_id(mut self, match_criteria_id: Uuid) -> Self {
        self.match_criteria_id = Some(match_criteria_id);
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

impl fmt::Display for CPEMatchRequest {
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
            self.last_mod_start_date.map(|d| d.to_rfc3339()).as_ref(),
            "lastModStartDate",
        );
        add_field(
            &mut str,
            self.last_mod_end_date.map(|d| d.to_rfc3339()).as_ref(),
            "lastModEndDate",
        );
        add_field(&mut str, self.match_criteria_id.as_ref(), "matchCriteriaId");
        add_field(
            &mut str,
            self.match_string_search.as_ref(),
            "matchStringSearch",
        );
        add_field(&mut str, self.result_per_page.as_ref(), "resultsPerPage");
        add_field(&mut str, self.start_index.as_ref(), "startIndex");

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
    fn cpe_match_request_encoding_works_when_empty() {
        let result = CPEMatchRequest::create(reqwest::Client::new()).to_string();
        assert_eq!("", result)
    }

    #[test]
    fn cpe_match_request_encoding_works() {
        let result = CPEMatchRequest::create(reqwest::Client::new())
            .with_cve_id("Test".to_owned())
            .with_last_modified_date_range(
                Utc.with_ymd_and_hms(2023, 11, 12, 0, 0, 0).unwrap(),
                Utc.with_ymd_and_hms(2023, 11, 14, 0, 0, 0).unwrap(),
            )
            .with_match_criteria_id(Uuid::nil())
            .with_match_string_search("matchStringSearch".to_owned())
            .with_start_index(1)
            .with_result_per_page(4)
            .to_string();

        assert_eq!(
            "\
        cveId=Test\
        &lastModStartDate=2023-11-12T00:00:00+00:00\
        &lastModEndDate=2023-11-14T00:00:00+00:00\
        &matchCriteriaId=00000000-0000-0000-0000-000000000000\
        &matchStringSearch=matchStringSearch\
        &resultsPerPage=4\
        &startIndex=1\
        ",
            result
        );
    }

    #[tokio::test]
    async fn cpe_match_request_execute_and_deserialize_correctly() {
        // Arrange
        let mock_server = MockServer::start().await;
        let test_data: String = fs::read_to_string("src/test_data/cpe_match.json").unwrap();

        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(test_data))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Act
        let result = CPEMatchRequest::create(reqwest::Client::new())
            .override_base_url(mock_server.uri().to_string())
            .execute()
            .await;
        // Assert
        assert_eq!(result.ok().map(|r| r.match_strings.len()), Some(1));
    }
}
