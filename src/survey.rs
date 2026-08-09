use crate::corpus::Evidence;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// Read off published documentation. The only source this file has.
    Documentation,
    /// Measured against running endpoints under the authorization gate.
    LiveProbe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeskVerdict {
    Qualified,
    Conditional,
    NonQualifying,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RowVerdict {
    Satisfied,
    ClientDependent,
    Fails,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub sector: String,
    pub provider: String,
    pub endpoint: String,
    pub c1: RowVerdict,
    pub c2: RowVerdict,
    pub c3: RowVerdict,
    pub c4: RowVerdict,
    pub hypothesis: DeskVerdict,
    /// The `results/` file holding the probe run this row came from. Absent
    /// for every documentation-derived row, and **required** before the file
    /// may declare itself live — otherwise "measured" is a claim anyone can
    /// make by editing two lines of TOML.
    #[serde(default)]
    pub probe_report: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Survey {
    pub source: Source,
    pub verified_live: bool,
    pub note: String,
    #[serde(default)]
    pub endpoint: Vec<Row>,
}

#[derive(Debug, thiserror::Error)]
pub enum SurveyError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "this survey declares `source = \"documentation\"` and `verified_live = true`, \
         which cannot both be so. A documentation review is not a measurement, and \
         nothing in this repository may present one as the other."
    )]
    UnearnedVerification,
    #[error(
        "this survey claims live verification, but the row for `{provider}` names no \
         `probe_report`. A row is measured when a probe run says so, not when the \
         file says so."
    )]
    RowWithoutEvidence { provider: String },
}

impl Survey {
    pub fn validate(&self) -> Result<(), SurveyError> {
        if self.verified_live && self.source != Source::LiveProbe {
            return Err(SurveyError::UnearnedVerification);
        }
        // Declaring `source = "live-probe"` is not evidence either. Every row
        // has to name the probe run it came from, so the promotion path is a
        // measurement rather than two edited lines of TOML.
        if self.verified_live {
            for r in &self.endpoint {
                if r.probe_report.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(SurveyError::RowWithoutEvidence {
                        provider: r.provider.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// `DeskStudy` unless the rows were genuinely probed. There is no path
    /// through this function that returns anything stronger by accident.
    pub fn evidence(&self) -> Evidence {
        if self.verified_live && self.source == Source::LiveProbe {
            Evidence::LiveProbed
        } else {
            Evidence::DeskStudy
        }
    }

    /// Printed above every rendering of this table, in every format.
    pub fn banner(&self) -> String {
        if self.evidence() == Evidence::LiveProbed {
            return format!(
                "MEASURED against live endpoints. n = {}.",
                self.endpoint.len()
            );
        }
        format!(
            "HYPOTHESIS, NOT DATA. These {} classifications are derived from published \
             documentation and have not been measured against a running endpoint. C1 and \
             C4 are properties of an implementation, which no document reveals. The sample \
             was chosen for sector coverage, so it is a convenience sample and the shares \
             below are not a population estimate. Verifying these rows by live probing is \
             work this repository has not done.",
            self.endpoint.len()
        )
    }

    pub fn counts(&self) -> Vec<(DeskVerdict, usize)> {
        [
            DeskVerdict::Qualified,
            DeskVerdict::Conditional,
            DeskVerdict::NonQualifying,
        ]
        .into_iter()
        .map(|v| {
            (
                v,
                self.endpoint.iter().filter(|r| r.hypothesis == v).count(),
            )
        })
        .collect()
    }
}

pub fn load(path: &Path) -> Result<Survey, SurveyError> {
    let text = std::fs::read_to_string(path).map_err(|source| SurveyError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let s: Survey = toml::from_str(&text).map_err(|source| SurveyError::Parse {
        path: path.display().to_string(),
        source,
    })?;
    s.validate()?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: &str = r#"
source = "documentation"
verified_live = false
note = "n"
[[endpoint]]
sector = "s"
provider = "p"
endpoint = "POST /x"
c1 = "fails"
c2 = "fails"
c3 = "fails"
c4 = "fails"
hypothesis = "non-qualifying"
"#;

    #[test]
    fn a_documentation_survey_is_always_desk_study_evidence() {
        let s: Survey = toml::from_str(MIN).unwrap();
        assert_eq!(s.evidence(), Evidence::DeskStudy);
    }

    #[test]
    fn declaring_a_live_source_is_not_evidence_of_one() {
        // The hole the first invariant leaves: `source = "live-probe"` plus
        // `verified_live = true` would otherwise load cleanly and print
        // "MEASURED against live endpoints", with no probe anywhere.
        let src = MIN
            .replace("source = \"documentation\"", "source = \"live-probe\"")
            .replace("verified_live = false", "verified_live = true");
        let s: Survey = toml::from_str(&src).unwrap();
        assert!(matches!(
            s.validate(),
            Err(SurveyError::RowWithoutEvidence { .. })
        ));
        assert_eq!(
            s.evidence(),
            Evidence::LiveProbed,
            "before validation, it would claim this"
        );
        // With a report named, it is allowed — and only then.
        let src = format!("{src}probe_report = \"results/probe-p.json\"\n");
        let s: Survey = toml::from_str(&src).unwrap();
        assert!(s.validate().is_ok());
    }

    #[test]
    fn a_documentation_source_cannot_claim_live_verification() {
        // The one invariant that matters. A row promoted to LiveProbed
        // without a probe is the failure mode this whole module exists to
        // prevent, so it is refused at load time rather than at print time.
        let src = MIN.replace("verified_live = false", "verified_live = true");
        let s: Survey = toml::from_str(&src).unwrap();
        assert!(matches!(
            s.validate(),
            Err(SurveyError::UnearnedVerification)
        ));
    }

    #[test]
    fn the_banner_names_the_sample_and_refuses_the_word_result() {
        let s: Survey = toml::from_str(MIN).unwrap();
        let b = s.banner();
        assert!(b.contains("HYPOTHESIS"), "{b}");
        assert!(b.contains("not a population estimate"), "{b}");
        assert!(b.contains("convenience sample"), "{b}");
    }

    #[test]
    fn the_shipped_survey_has_the_twenty_four_rows_the_desk_study_classified() {
        let s = load(std::path::Path::new("survey/desk-study.toml")).unwrap();
        assert_eq!(s.endpoint.len(), 24);
        assert_eq!(s.source, Source::Documentation);
        assert!(!s.verified_live);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn the_shipped_counts_match_the_desk_study_split() {
        let s = load(std::path::Path::new("survey/desk-study.toml")).unwrap();
        let counts = s.counts();
        let get = |v: DeskVerdict| {
            counts
                .iter()
                .find(|(k, _)| *k == v)
                .map(|(_, n)| *n)
                .unwrap_or(0)
        };
        // 4 / 7 / 13, from counting the desk study's own 24-row table.
        //
        // Its prose says 4 / 6 / 14 — "25.0% (6 out of 24)" and "58.3% (14 out
        // of 24)" — and P02 inherits those figures. The table does not support
        // them: Square is a Conditional row the 25% count omits and the 58%
        // count then absorbs. The rows are right and the arithmetic over them
        // is wrong.
        //
        // Transcribe the table. Do not adjust a row to reach 14. This is the
        // "no number in the paper can drift from the code that produced it"
        // discipline doing its job on its first use, and the correction is a
        // small result of its own.
        assert_eq!(get(DeskVerdict::Qualified), 4);
        assert_eq!(get(DeskVerdict::Conditional), 7);
        assert_eq!(get(DeskVerdict::NonQualifying), 13);
        assert_eq!(s.endpoint.len(), 4 + 7 + 13);
    }

    #[test]
    fn every_row_names_a_provider_and_an_endpoint() {
        let s = load(std::path::Path::new("survey/desk-study.toml")).unwrap();
        for r in &s.endpoint {
            assert!(!r.provider.trim().is_empty());
            assert!(!r.endpoint.trim().is_empty(), "{}", r.provider);
        }
    }

    #[test]
    fn a_malformed_survey_errors_rather_than_panicking() {
        for bad in [
            "",
            "source = 5",
            "source = \"telepathy\"\nverified_live = false\nnote = \"n\"",
        ] {
            assert!(toml::from_str::<Survey>(bad).is_err(), "{bad:?}");
        }
    }
}
