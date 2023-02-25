use chrono::{DateTime, Utc};

#[allow(dead_code)]
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
    match_criteria_id: Option<String>,
    result_per_page: Option<u32>,
    start_index: Option<u32>,
}
