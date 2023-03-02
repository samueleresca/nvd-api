use serde::{Deserialize, Serialize};

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
#[doc = "CPE match string or range"]
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
    #[doc = "CVSS V2.0 score."]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssMetricV2")]
    pub cvss_metric_v2: Option<Vec<CvssV2>>,
    #[doc = "CVSS V3.0 score."]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssMetricV30")]
    pub cvss_metric_v30: Option<Vec<CvssV30>>,
    #[doc = "CVSS V3.1 score."]
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
    #[doc = "Metric scores for a vulnerability as found on NVD."]
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
    pub cvss_data: Option<v2::CVSS>,
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
    pub cvss_data: v3_x::CVSS,
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
    pub cvss_data: v3_x::CVSS,
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
pub struct Response {
    pub format: String,
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    pub timestamp: String,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    pub version: String,
    #[doc = "NVD feed array of CVE"]
    pub vulnerabilities: Vec<DefCveItem>,
}

pub mod v3_x {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum AttackVectorType {
        #[serde(rename = "NETWORK")]
        Network,
        #[serde(rename = "ADJACENT_NETWORK")]
        AdjacentNetwork,
        #[serde(rename = "LOCAL")]
        Local,
        #[serde(rename = "PHYSICAL")]
        Physical,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ModifiedAttackVectorType {
        #[serde(rename = "NETWORK")]
        Network,
        #[serde(rename = "ADJACENT_NETWORK")]
        AdjacentNetwork,
        #[serde(rename = "LOCAL")]
        Local,
        #[serde(rename = "PHYSICAL")]
        Physical,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ModifiedAttackComplexityType {
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum AttackComplexityType {
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "LOW")]
        Low,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ModifiedPrivilegesRequiredType {
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "NONE")]
        None,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum PrivilegesRequiredType {
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "NONE")]
        None,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum UserInteractionType {
        #[serde(rename = "REQUIRED")]
        Required,
        #[serde(rename = "NONE")]
        None,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ModifiedUserInteractionType {
        #[serde(rename = "REQUIRED")]
        Required,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
        #[serde(rename = "NONE")]
        None,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ScopeType {
        #[serde(rename = "UNCHANGED")]
        Unchanged,
        #[serde(rename = "CHANGED")]
        Changed,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ModifiedScopeType {
        #[serde(rename = "UNCHANGED")]
        Unchanged,
        #[serde(rename = "CHANGED")]
        Changed,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum CiaType {
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "NONE")]
        None,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ModifiedCiaType {
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "NONE")]
        None,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ExploitCodeMaturityType {
        #[serde(rename = "UNPROVEN")]
        Unproven,
        #[serde(rename = "PROOF_OF_CONCEPT")]
        ProofOfConcept,
        #[serde(rename = "FUNCTIONAL")]
        Functional,
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum RemediationLevelType {
        #[serde(rename = "OFFICIAL_FIX")]
        OfficialFix,
        #[serde(rename = "TEMPORARY_FIX")]
        TemporaryFix,
        #[serde(rename = "WORKAROUND")]
        Workaround,
        #[serde(rename = "UNAVAILABLE")]
        Unavailable,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum ConfidenceType {
        #[serde(rename = "UNKNOWN")]
        Unknown,
        #[serde(rename = "REASONABLE")]
        Reasonable,
        #[serde(rename = "CONFIRMED")]
        Confirmed,
        #[serde(rename = "UNAVAILABLE")]
        Unavailable,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum CiaRequirementType {
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "MEDIUM")]
        Medium,
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub enum SeverityType {
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "MEDIUM")]
        Medium,
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "NONE")]
        None,
        #[serde(rename = "CRITICAL")]
        Critical,
    }

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub struct CVSS {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "attackComplexity")]
        pub attack_complexity: Option<AttackComplexityType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "attackVector")]
        pub attack_vector: Option<AttackVectorType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "availabilityImpact")]
        pub availability_impact: Option<CiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "availabilityRequirement")]
        pub availability_requirement: Option<CiaRequirementType>,
        #[serde(rename = "baseScore")]
        pub base_score: Option<f32>,
        #[serde(rename = "baseSeverity")]
        pub base_severity: SeverityType,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "confidentialityImpact")]
        pub confidentiality_impact: Option<CiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "confidentialityRequirement")]
        pub confidentiality_requirement: Option<CiaRequirementType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "environmentalScore")]
        pub environmental_score: Option<f32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "environmentalSeverity")]
        pub environmental_severity: Option<SeverityType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "exploitCodeMaturity")]
        pub exploit_code_maturity: Option<ExploitCodeMaturityType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "integrityImpact")]
        pub integrity_impact: Option<CiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "integrityRequirement")]
        pub integrity_requirement: Option<CiaRequirementType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "modifiedAttackComplexity")]
        pub modified_attack_complexity: Option<ModifiedAttackComplexityType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "modifiedAttackVector")]
        pub modified_attack_vector: Option<ModifiedAttackVectorType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "modifiedAvailabilityImpact")]
        pub modified_availability_impact: Option<ModifiedCiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "modifiedConfidentialityImpact")]
        pub modified_confidentiality_impact: Option<ModifiedCiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "modifiedIntegrityImpact")]
        pub modified_integrity_impact: Option<ModifiedCiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "modifiedPrivilegesRequired")]
        pub modified_privileges_required: Option<ModifiedPrivilegesRequiredType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "modifiedScope")]
        pub modified_scope: Option<ModifiedScopeType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "modifiedUserInteraction")]
        pub modified_user_interaction: Option<ModifiedUserInteractionType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "privilegesRequired")]
        pub privileges_required: Option<PrivilegesRequiredType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "remediationLevel")]
        pub remediation_level: Option<RemediationLevelType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "reportConfidence")]
        pub report_confidence: Option<ConfidenceType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub scope: Option<ScopeType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "temporalScore")]
        pub temporal_score: Option<f32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "temporalSeverity")]
        pub temporal_severity: Option<SeverityType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "userInteraction")]
        pub user_interaction: Option<UserInteractionType>,
        #[serde(rename = "vectorString")]
        pub vector_string: String,
        #[doc = "CVSS Version"]
        pub version: String,
    }
}

pub mod v2 {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "accessComplexityType")]
    pub enum AccessComplexityType {
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "MEDIUM")]
        Medium,
        #[serde(rename = "LOW")]
        Low,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "accessVectorType")]
    pub enum AccessVectorType {
        #[serde(rename = "NETWORK")]
        Network,
        #[serde(rename = "ADJACENT_NETWORK")]
        AdjacentNetwork,
        #[serde(rename = "LOCAL")]
        Local,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "authenticationType")]
    pub enum AuthenticationType {
        #[serde(rename = "MULTIPLE")]
        Multiple,
        #[serde(rename = "SINGLE")]
        Single,
        #[serde(rename = "NONE")]
        None,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "ciaRequirementType")]
    pub enum CiaRequirementType {
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "MEDIUM")]
        Medium,
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "ciaType")]
    pub enum CiaType {
        #[serde(rename = "NONE")]
        None,
        #[serde(rename = "PARTIAL")]
        Partial,
        #[serde(rename = "COMPLETE")]
        Complete,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "collateralDamagePotentialType")]
    pub enum CollateralDamagePotentialType {
        #[serde(rename = "NONE")]
        None,
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "LOW_MEDIUM")]
        LowMedium,
        #[serde(rename = "MEDIUM_HIGH")]
        MediumHigh,
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "exploitabilityType")]
    pub enum ExploitabilityType {
        #[serde(rename = "UNPROVEN")]
        Unproven,
        #[serde(rename = "PROOF_OF_CONCEPT")]
        ProofOfConcept,
        #[serde(rename = "FUNCTIONAL")]
        Functional,
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "remediationLevelType")]
    pub enum RemediationLevelType {
        #[serde(rename = "OFFICIAL_FIX")]
        OfficialFix,
        #[serde(rename = "TEMPORARY_FIX")]
        TemporaryFix,
        #[serde(rename = "WORKAROUND")]
        Workaround,
        #[serde(rename = "UNAVAILABLE")]
        Unavailable,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "reportConfidenceType")]
    pub enum ReportConfidenceType {
        #[serde(rename = "UNCONFIRMED")]
        Unconfirmed,
        #[serde(rename = "UNCORROBORATED")]
        Uncorroborated,
        #[serde(rename = "CONFIRMED")]
        Confirmed,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }
    pub type ScoreType = f64;
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    #[serde(rename = "targetDistributionType")]
    pub enum TargetDistributionType {
        #[serde(rename = "NONE")]
        None,
        #[serde(rename = "LOW")]
        Low,
        #[serde(rename = "MEDIUM")]
        Medium,
        #[serde(rename = "HIGH")]
        High,
        #[serde(rename = "NOT_DEFINED")]
        NotDefined,
    }
    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub struct CVSS {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "accessComplexity")]
        pub access_complexity: Option<AccessComplexityType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "accessVector")]
        pub access_vector: Option<AccessVectorType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub authentication: Option<AuthenticationType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "availabilityImpact")]
        pub availability_impact: Option<CiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "availabilityRequirement")]
        pub availability_requirement: Option<CiaRequirementType>,
        #[serde(rename = "baseScore")]
        pub base_score: ScoreType,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "collateralDamagePotential")]
        pub collateral_damage_potential: Option<CollateralDamagePotentialType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "confidentialityImpact")]
        pub confidentiality_impact: Option<CiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "confidentialityRequirement")]
        pub confidentiality_requirement: Option<CiaRequirementType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "environmentalScore")]
        pub environmental_score: Option<ScoreType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exploitability: Option<ExploitabilityType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "integrityImpact")]
        pub integrity_impact: Option<CiaType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "integrityRequirement")]
        pub integrity_requirement: Option<CiaRequirementType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "remediationLevel")]
        pub remediation_level: Option<RemediationLevelType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "reportConfidence")]
        pub report_confidence: Option<ReportConfidenceType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "targetDistribution")]
        pub target_distribution: Option<TargetDistributionType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "temporalScore")]
        pub temporal_score: Option<ScoreType>,
        #[serde(rename = "vectorString")]
        pub vector_string: String,
        #[doc = "CVSS Version"]
        pub version: String,
    }
}
