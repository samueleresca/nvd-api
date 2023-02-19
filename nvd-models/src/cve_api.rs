#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "config")]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negate: Option<bool>,
    pub nodes: Vec<Node>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
}
#[doc = " CPE match string or range"]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "cpe_match")]
#[serde(deny_unknown_fields)]
pub struct CpeMatch {
    pub criteria: String,
    #[serde(rename = "matchCriteriaId")]
    pub match_criteria_id: String,
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
    pub vulnerable: bool,
}
pub type CveId = String;
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CveItemMetrics {
    #[doc = " CVSS V2.0 score."]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssMetricV2")]
    pub cvss_metric_v2: Option<Vec<CvssV2>>,
    #[doc = " CVSS V3.0 score."]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssMetricV30")]
    pub cvss_metric_v30: Option<Vec<CvssV30>>,
    #[doc = " CVSS V3.1 score."]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssMetricV31")]
    pub cvss_metric_v31: Option<Vec<CvssV31>>,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "cve_item")]
#[serde(deny_unknown_fields)]
pub struct CveItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cisaActionDue")]
    pub cisa_action_due: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cisaExploitAdd")]
    pub cisa_exploit_add: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cisaRequiredAction")]
    pub cisa_required_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cisaVulnerabilityName")]
    pub cisa_vulnerability_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configurations: Option<Vec<Config>>,
    pub descriptions: Vec<LangString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "evaluatorComment")]
    pub evaluator_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "evaluatorImpact")]
    pub evaluator_impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "evaluatorSolution")]
    pub evaluator_solution: Option<String>,
    pub id: CveId,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    #[doc = " Metric scores for a vulnerability as found on NVD."]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<CveItemMetrics>,
    pub published: String,
    pub references: Vec<Reference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "vendorComments")]
    pub vendor_comments: Option<Vec<VendorComment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "vulnStatus")]
    pub vuln_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weaknesses: Option<Vec<Weakness>>,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "cvss-v2")]
#[serde(deny_unknown_fields)]
pub struct CvssV2 {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "acInsufInfo")]
    pub ac_insuf_info: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    #[serde(rename = "cvssData")]
    pub cvss_data: CvssV20Json,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<DefSubscore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "impactScore")]
    pub impact_score: Option<DefSubscore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "obtainAllPrivilege")]
    pub obtain_all_privilege: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "obtainOtherPrivilege")]
    pub obtain_other_privilege: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "obtainUserPrivilege")]
    pub obtain_user_privilege: Option<bool>,
    pub source: String,
    #[serde(rename = "type")]
    pub type_: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "userInteractionRequired")]
    pub user_interaction_required: Option<bool>,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "cvss-v30")]
#[serde(deny_unknown_fields)]
pub struct CvssV30 {
    #[serde(rename = "cvssData")]
    pub cvss_data: CvssV30Json,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<DefSubscore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "impactScore")]
    pub impact_score: Option<DefSubscore>,
    pub source: String,
    #[serde(rename = "type")]
    pub type_: serde_json::Value,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "cvss-v31")]
#[serde(deny_unknown_fields)]
pub struct CvssV31 {
    #[serde(rename = "cvssData")]
    pub cvss_data: CvssV31Json,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<DefSubscore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "impactScore")]
    pub impact_score: Option<DefSubscore>,
    pub source: String,
    #[serde(rename = "type")]
    pub type_: serde_json::Value,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "def_cve_item")]
#[serde(deny_unknown_fields)]
pub struct DefCveItem {
    pub cve: CveItem,
}
#[doc = "CVSS subscore."]
pub type DefSubscore = f64;
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "lang_string")]
#[serde(deny_unknown_fields)]
pub struct LangString {
    pub lang: String,
    pub value: String,
}
#[doc = "Defines a configuration node in an NVD applicability statement."]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "node")]
#[serde(deny_unknown_fields)]
pub struct Node {
    #[serde(rename = "cpeMatch")]
    pub cpe_match: Vec<CpeMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negate: Option<bool>,
    pub operator: String,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "reference")]
#[serde(deny_unknown_fields)]
pub struct Reference {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    pub url: String,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "vendorComment")]
#[serde(deny_unknown_fields)]
pub struct VendorComment {
    pub comment: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    pub organization: String,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename = "weakness")]
#[serde(deny_unknown_fields)]
pub struct Weakness {
    pub description: Vec<LangString>,
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    pub format: String,
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    pub timestamp: String,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    pub version: String,
    #[doc = " NVD feed array of CVE"]
    pub vulnerabilities: Vec<DefCveItem>,
}
