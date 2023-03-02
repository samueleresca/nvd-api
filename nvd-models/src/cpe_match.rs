use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "def_cpe_name")]
#[serde(deny_unknown_fields)]
pub struct DefCpeName {
    #[serde(rename = "cpeName")]
    pub cpe_name: String,
    #[serde(rename = "cpeNameId")]
    pub cpe_name_id: String,
}
#[doc = " CPE match string or range"]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "def_match_data")]
#[serde(deny_unknown_fields)]
pub struct DefMatchData {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cpeLastModified")]
    pub cpe_last_modified: Option<String>,
    pub created: String,
    pub criteria: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    #[serde(rename = "matchCriteriaId")]
    pub match_criteria_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<Vec<DefCpeName>>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "def_matchstring")]
#[serde(deny_unknown_fields)]
pub struct DefMatchstring {
    #[serde(rename = "matchString")]
    pub match_string: DefMatchData,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub format: String,
    #[doc = " Array of CPE match strings"]
    #[serde(rename = "matchStrings")]
    pub match_strings: Vec<DefMatchstring>,
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    pub timestamp: String,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    pub version: String,
}
