use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use std::fmt;

use crate::{RequestExecutor, ASSIGNER, BASE_URL, DELIMITER};
use uuid::Uuid;

use nvd_models::cpe::Response;

pub struct CPERequest {
    http_client: reqwest::Client,
    api_key: Option<String>,
    base_url: String,

    cpe_name_id: Option<String>,
    cpe_match_string: Option<String>,
    keyword_exact_match: Option<bool>,
    keyword_search: Option<String>,
    last_mod_start_date: Option<DateTime<Utc>>,
    last_mod_end_date: Option<DateTime<Utc>>,
    match_criteria_id: Option<Uuid>,
    result_per_page: Option<u32>,
    start_index: Option<u32>,
}

#[async_trait]
impl RequestExecutor<Response> for CPERequest {
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

impl CPERequest {
    pub fn create(http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            base_url: BASE_URL.to_owned() + "cpes/2.0",
            api_key: None,

            cpe_name_id: None,
            cpe_match_string: None,
            keyword_exact_match: None,
            keyword_search: None,
            last_mod_start_date: None,
            last_mod_end_date: None,
            match_criteria_id: None,
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

    pub fn with_cpe_name_id(mut self, cpe_name_id: String) -> Self {
        self.cpe_name_id = Some(cpe_name_id);
        self
    }

    pub fn with_cpe_match_string(mut self, cpe_match_string: String) -> Self {
        self.cpe_match_string = Some(cpe_match_string);
        self
    }

    pub fn with_keyword(mut self, keyword_search: String, exact_match: bool) -> Self {
        self.keyword_exact_match = if exact_match { Some(true) } else { None };
        self.keyword_search = Some(keyword_search);
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

impl fmt::Display for CPERequest {
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

        fn add_bool_field(dest: &mut String, field_value: Option<&bool>, field_name: &str) {
            if field_value.is_some() {
                dest.push_str(field_name);
                dest.push_str(DELIMITER);
            };
        }

        add_field(&mut str, self.cpe_name_id.as_ref(), "cpeNameId");
        add_field(&mut str, self.cpe_match_string.as_ref(), "cpeMatchString");
        add_bool_field(
            &mut str,
            self.keyword_exact_match.as_ref(),
            "keywordExactMatch",
        );
        add_field(&mut str, self.keyword_search.as_ref(), "keywordSearch");
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
    fn cpe_request_encoding_works_when_empty() {
        let result = CPERequest::create(reqwest::Client::new()).to_string();
        assert_eq!("", result)
    }

    #[test]
    fn cpe_request_encoding_works() {
        let result = CPERequest::create(reqwest::Client::new())
            .with_cpe_name_id("Test".to_owned())
            .with_cpe_match_string("Test".to_owned())
            .with_keyword("keyword test".to_owned(), true)
            .with_match_criteria_id(Uuid::nil())
            .with_last_modified_date_range(
                Utc.with_ymd_and_hms(2023, 11, 12, 0, 0, 0).unwrap(),
                Utc.with_ymd_and_hms(2023, 11, 14, 0, 0, 0).unwrap(),
            )
            .with_start_index(1)
            .with_result_per_page(4)
            .to_string();

        assert_eq!(
            "\
        cpeNameId=Test\
        &cpeMatchString=Test\
        &keywordExactMatch\
        &keywordSearch=keyword test\
        &lastModStartDate=2023-11-12T00:00:00+00:00\
        &lastModEndDate=2023-11-14T00:00:00+00:00\
        &matchCriteriaId=00000000-0000-0000-0000-000000000000\
        &resultsPerPage=4\
        &startIndex=1\
        ",
            result
        );
    }

    #[tokio::test]
    async fn cpe_request_execute_and_deserialize_correctly() {
        // Arrange
        let mock_server = MockServer::start().await;
        let test_data: String = fs::read_to_string("src/test_data/cpe.json").unwrap();

        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(test_data))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Act
        let result = CPERequest::create(reqwest::Client::new())
            .override_base_url(mock_server.uri().to_string())
            .with_match_criteria_id(
                Uuid::parse_str("36FBCF0F-8CEE-474C-8A04-5075AF53FAF4").unwrap(),
            )
            .execute()
            .await;

        // Assert
        assert_eq!(result.ok().map(|r| r.products.len()), Some(1));
    }
}
