#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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
} 


pub struct CVEChangeHistoryRequest {
    cveId: Option<String>,
    change_start_date: Option<DateTime<Utc>>,
    change_end_date: Option<DateTime<Utc>>,
    result_per_page: Option<u32>,
    start_index: Option<u32>,
}