//! Management of release notes.
//!
//! The release notes are formatted in RST.  We have some primitive
//! parsing of these, mostly about detecting ones that are present, and
//! determine if they are placeholders.  We'll use the simple rule that if
//! there is a list of something after an CVE section, then that CVE has
//! information published about it.

use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::{
        BufRead,
        BufReader,
    },
};

lazy_static! {
    static ref CVE_RE: Regex = Regex::new(r"^CVE-(\d\d\d\d)-(\d+)( .*)?$").unwrap();
}

/// All of the vulnerabilities listed in the vulnerabilities file.
#[derive(Debug)]
pub struct Rnotes(BTreeMap<CveNum, RnoteState>);

/// A CVE number.  The 'extra' information for now is any freeform text
/// that is part of the name.  This can be used to mention external CVEs
/// for example.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CveNum {
    year: usize,
    number: usize,
    extra: String,
}

impl CveNum {
    /// Try to decode a CveNumber from a string containing one.  Returns
    /// Some if a valid CVE number was found.
    fn from_line(line: &str) -> Option<CveNum> {
        CVE_RE.captures(line).map(|cap| CveNum {
            year: cap.get(1).unwrap().as_str().parse().unwrap(),
            number: cap.get(2).unwrap().as_str().parse().unwrap(),
            extra: "".to_string(),
        })
    }
}

/// The state that an rnote can be in.  It is not present in the map if it
/// is missing entirely.  Reserved indicates that this issue is still under
/// embargo (or at least hasn't been updated in the vulnerability file).
/// Published indicates there is information about the vulnerability.
#[derive(Debug)]
pub enum RnoteState {
    Reserved,
    Published,
}

impl Rnotes {
    pub fn load() -> Result<Rnotes> {
        let mut result = Rnotes(BTreeMap::new());

        let mut last_cve = None;
        let mut state = RnoteState::Reserved;
        let mut vulnerabilities = env::var("ZEPHYR_BASE").unwrap_or(String::from("../../zephyr"));
        vulnerabilities.push_str("/doc/security/vulnerabilities.rst");

        for line in BufReader::new(File::open(vulnerabilities)?).lines() {
            let line = line?;
            if let Some(cve) = CveNum::from_line(&line) {
                result.push(&mut last_cve, state);
                state = RnoteState::Reserved;
                last_cve = Some(cve);
            } else if line.starts_with("- ") {
                state = RnoteState::Published;
            }
        }
        result.push(&mut last_cve, state);

        Ok(result)
    }

    fn push(&mut self, cve: &mut Option<CveNum>, state: RnoteState) {
        if let Some(cve) = cve.take() {
            self.0.insert(cve, state);
        }
    }

    /// Lookup a description of the rnote state of an rnote for a given
    /// CVE.
    pub fn lookup(&self, cve: &str) -> String {
        if let Some(cve) = CveNum::from_line(cve) {
            if let Some(state) = self.0.get(&cve) {
                format!("{:?}", state)
            } else {
                "None".to_string()
            }
        } else {
            "???".to_string()
        }
    }
}
