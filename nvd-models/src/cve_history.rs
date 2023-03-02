use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "changeItem")]
#[serde(deny_unknown_fields)]
pub struct ChangeItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(rename = "cveChangeId")]
    pub cve_change_id: String,
    #[serde(rename = "cveId")]
    pub cve_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<Detail>>,
    #[serde(rename = "eventName")]
    pub event_name: String,
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: String,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "defChange")]
#[serde(deny_unknown_fields)]
pub struct DefChange {
    pub change: ChangeItem,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "detail")]
#[serde(deny_unknown_fields)]
pub struct Detail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "newValue")]
    pub new_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "oldValue")]
    pub old_value: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct Response {
    #[doc = "Array of CVE Changes"]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cveChanges")]
    pub cve_changes: Option<Vec<DefChange>>,
    pub format: String,
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    pub timestamp: String,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    pub version: String,
}
