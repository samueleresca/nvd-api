use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct DefCpeCpeItemDeprecatedBy {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cpeName")]
    pub cpe_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cpeNameId")]
    pub cpe_name_id: Option<String>,
}
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct DefCpeCpeItemDeprecates {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cpeName")]
    pub cpe_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cpeNameId")]
    pub cpe_name_id: Option<String>,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DefCpeCpe {
    #[serde(rename = "cpeName")]
    pub cpe_name: String,
    #[serde(rename = "cpeNameId")]
    pub cpe_name_id: String,
    pub created: String,
    pub deprecated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "deprecatedBy")]
    pub deprecated_by: Option<Vec<DefCpeCpeItemDeprecatedBy>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecates: Option<Vec<DefCpeCpeItemDeprecates>>,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<DefReference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub titles: Option<Vec<DefTitle>>,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "defCpe")]
#[serde(deny_unknown_fields)]
pub struct DefCpe {
    pub cpe: DefCpeCpe,
}
#[doc = " Internet resource for CPE"]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "defReference")]
#[serde(deny_unknown_fields)]
pub struct DefReference {
    #[serde(rename = "ref")]
    pub ref_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub type_: Option<String>,
}
#[doc = " Human readable title for CPE"]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "defTitle")]
#[serde(deny_unknown_fields)]
pub struct DefTitle {
    pub lang: String,
    pub title: String,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub format: String,
    #[doc = " NVD feed array of CPE"]
    pub products: Vec<DefCpe>,
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    pub timestamp: String,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    pub version: String,
}