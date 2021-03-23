//! Collecting information about github alerts.
//!
//! As of this time, there is no API to query github alerts.  As such, 
//! the alert information must be stored in a separate file, in Markdown, on the private wiki of
//! zephyrproject-rtos/swg-docs.wiki.
//! We're fairly picky about the formatting, and parts of the document that don't match the regexps
//! below will be flagged, and should be fixed.

use anyhow::{anyhow, Result};
use config::Config;
use crate::{
    git::CmdRepository,
    github::Github,
    zepsec::PullRequest,
};
use git2::Repository;
use regex::Regex;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
};

pub struct Advisory {
    entries: Vec<Entry>,
    github: Arc<Github>,
    cmd_git: CmdRepository,
}

#[derive(Debug)]
pub struct Entry {
    pub title: String,
    pub ghsa: String,
    pub created: String,
    pub cve: String,
    pub cvss: (String, String, String),
    pub zepsec: Option<usize>,
    pub branch: Vec<(String, MaybePr)>,
    pub embargo: String,
}

#[derive(Default, Debug)]
struct Builder {
    title: Option<String>,
    ghsa: Option<String>,
    created: Option<String>,
    cve: Option<String>,
    cvss: Option<(String, String, String)>,
    zepsec: Option<usize>,
    branch: Vec<(String, MaybePr)>,
    embargo: Option<String>,
}

#[derive(Debug)]
pub enum MaybePr {
    Tbd,
    Na,
    Pr(PullRequest),
}

static GHSA_BASE: &str = "https://github.com/zephyrproject-rtos/zephyr/security/advisories";

macro_rules! setopt {
    ($dest:expr, $field:ident, $value:expr) => {
        if let Some(ref mut inside) = $dest {
            if inside.$field.is_some() {
                return Err(anyhow!("Duplicate field {}", stringify!($dest)));
            } else {
                inside.$field = Some($value);
            }
        } else {
            return Err(anyhow!("Fields occur before first heading"));
        }
    };
}

impl Advisory {
    pub fn new(config: &Config) -> Result<Advisory> {
        let path = config.get_str("advisory.file")?;
        let git = Repository::init(config.get_str("zephyr.repo")?)?;
        let cmd_git = CmdRepository::new(&git);

        let header_re = Regex::new(r"^## \[(GHSA(-[0-9a-z]{4}){3})\]\([^\)]+\): (.*)")?;
        let created_re = Regex::new(r"^- created: (\d{4}-\d\d-\d\d)$")?;
        let cve_re = Regex::new(r"^- (CVE-\d{4}-\d+)$")?;
        let cvss_re = Regex::new(r"^- (\d+\.\d+) (Low|Moderate|High|Critical) (CVSS.*)")?;
        let branch_re = Regex::new(r"^- (master|v\d+(\.\d+)+(-branch)?): (\[#(\d+)\]|TBD|NA)")?;
        let zepsec_re = Regex::new(r"^- ZEPSEC-(\d+)$")?;
        let embargo_re = Regex::new(r"^- embargo: (\d{4}-\d\d-\d\d)$")?;
        let thanks_re = Regex::new(r"^- thanks: (.*)")?;
        let invalid_re = Regex::new(r"^- (.*)")?;

        let mut builder: Option<Builder> = None;
        let mut result = Vec::new();

        for line in BufReader::new(File::open(&path)?).lines() {
            let line = line?;
            if let Some(m) = header_re.captures(&line) {
                if let Some(builder) = builder.take() {
                    // println!("Ship: {:#?}", builder.into_entry());
                    result.push(builder.into_entry()?);
                }
                builder = Some(Builder::default());
                setopt!(builder, title, m.get(3).unwrap().as_str().into());
                setopt!(builder, ghsa, m.get(1).unwrap().as_str().into());
                // println!("Header: {:?}", m.get(1).unwrap().as_str());
                // println!("Title: {:?}", m.get(3).unwrap().as_str());
            } else if let Some(m) = created_re.captures(&line) {
                setopt!(builder, created, m.get(1).unwrap().as_str().into());
                // println!("Created: {:?}", m.get(1).unwrap().as_str());
            } else if let Some(m) = cve_re.captures(&line) {
                setopt!(builder, cve, m.get(1).unwrap().as_str().into());
                // println!("CVE: {:?}", m.get(1).unwrap().as_str());
            } else if let Some(m) = cvss_re.captures(&line) {
                setopt!(builder, cvss,
                    (m.get(1).unwrap().as_str().into(),
                    m.get(2).unwrap().as_str().into(),
                    m.get(3).unwrap().as_str().into()));
                // println!("cvss: {:?}, {:?}, {:?}",
                //     m.get(1).unwrap().as_str(),
                //     m.get(2).unwrap().as_str(),
                //     m.get(3).unwrap().as_str(),
                //     );
            } else if let Some(m) = branch_re.captures(&line) {
                if let Some(ref mut builder) = builder {
                    let pr = if let Some(num) = m.get(5) {
                        let pr = PullRequest {
                            user: "zephyrproject-rtos".into(),
                            repo: "zephyr".into(),
                            pr: num.as_str().parse()?,
                        };
                        MaybePr::Pr(pr)
                    } else {
                        match m.get(4).unwrap().as_str() {
                            "TBD" => MaybePr::Tbd,
                            "NA" => MaybePr::Na,
                            _ => unreachable!(),
                        }
                    };
                    builder.branch.push((
                        m.get(1).unwrap().as_str().into(),
                        pr));
                } else {
                    return Err(anyhow!("Fields occur before first heading"));
                }
                // println!("branch: {:?}, {:?}",
                //     m.get(1).unwrap().as_str(),
                //     m.get(5).unwrap_or_else(|| m.get(4).unwrap()).as_str(),
                //     );
            } else if let Some(m) = zepsec_re.captures(&line) {
                setopt!(builder, zepsec,
                    m.get(1).unwrap().as_str().parse().unwrap());
                // println!("ZEPSEC: {:?}", m.get(1).unwrap().as_str());
            } else if let Some(m) = embargo_re.captures(&line) {
                setopt!(builder, embargo, m.get(1).unwrap().as_str().into());
                // println!("embargo: {:?}", m.get(1).unwrap().as_str());
            } else if let Some(_) = thanks_re.captures(&line) {
                // println!("thanks: {:?}", m.get(1).unwrap().as_str());
            } else if let Some(m) = invalid_re.captures(&line) {
                log::error!("invalid: {:?}", m.get(1).unwrap().as_str());
            } else {
                // println!("line: {:?}", line);
            }
        }

        if let Some(builder) = builder.take() {
            // println!("Ship: {:#?}", builder.into_entry());
            result.push(builder.into_entry()?);
        }

        // Sort everything by CVE number.
        result.sort_by_key(|e| crate::zepsec::cvevalue(&e.cve));

        // println!("Ship: {:#?}", result);
        Ok(Advisory {
            entries: result,
            github: Arc::new(Github::new(config)?),
            cmd_git,
        })
    }

    // Report on entries that are TBD:
    pub fn report_tbd(&self) {
        println!("## Backports needing to be started");
        println!();
        println!("GHSA|CVE|branch");
        println!("---|---|---");
        for adv in &self.entries {
            for b in &adv.branch {
                if b.1.is_tbd() {
                    println!("[{}]({}/{})|{}|{}", adv.ghsa, GHSA_BASE, adv.ghsa, adv.cve, b.0);
                }
            }
        }
        println!();
    }

    // Report on the status of all PRs.
    pub async fn report_unreleased(&self) -> Result<()> {
        let all_prs: Vec<_> = self.entries.iter()
            .flat_map(|adv| adv.branch.iter()
                .flat_map(|b| b.1.get_pr()))
            .cloned()
            .collect();
        let all_prs = self.github.clone().bulk_get_pr(&all_prs).await?;
        let simple_re = Regex::new(r"^v\d+\.\d+\.\d+$")?;

        println!("## Backports not released");
        println!();
        println!("GHSA|CVE|branch|pr|state");
        println!("---|---|---|---|---");
        for adv in &self.entries {
            for b in &adv.branch {
                if let Some(pr) = b.1.get_pr() {
                    let minfo = all_prs.get(&pr.pr).unwrap();
                    let state = if minfo.merged {
                        let contains = self.cmd_git.tag_contains(&minfo.merge_commit_sha).await?;
                        let contains: Vec<_> = contains.iter()
                            .filter(|f| simple_re.is_match(f))
                            .collect();
                        if let Some(first) = contains.iter().next() {
                            format!("{}", first)
                        } else {
                            "Unreleased".into()
                        // } else {
                            // Unsure what order these come back in.  We can print the earliest
                            // version that is not an rc.
                            /*
                            format!("{}", SliceFmt(&contains
                                .iter()
                                .filter(|f| simple_re.is_match(f))
                                .collect::<Vec<_>>()))
                            */

                        }
                    } else {
                        "Review".into()
                    };
                    println!("[{}]({}/{})|{}|{}|[#{}]({})|{}",
                        adv.ghsa,
                        GHSA_BASE,
                        adv.ghsa,
                        adv.cve,
                        b.0,
                        pr.pr,
                        pr.url(),
                        state);
                }
            }
        }
        println!();
        Ok(())
    }
}

impl Builder {
    fn into_entry(self) -> Result<Entry> {
        Ok(Entry {
            title: self.title.ok_or_else(|| anyhow!("Missing title"))?,
            ghsa: self.ghsa.ok_or_else(|| anyhow!("Missing ghsa"))?,
            created: self.created.ok_or_else(|| anyhow!("Missing created"))?,
            cve: self.cve.ok_or_else(|| anyhow!("Missing cve"))?,
            cvss: self.cvss.ok_or_else(|| anyhow!("Missing cvss"))?,
            zepsec: self.zepsec,
            branch: self.branch,
            embargo: self.embargo.ok_or_else(|| anyhow!("Missing embargo"))?,
        })
    }
}

impl MaybePr {
    #[allow(dead_code)]
    pub fn is_tbd(&self) -> bool {
        matches!(self, MaybePr::Tbd)
    }

    #[allow(dead_code)]
    pub fn is_na(&self) -> bool {
        matches!(self, MaybePr::Na)
    }

    pub fn get_pr(&self) -> Option<&PullRequest> {
        match self {
            MaybePr::Pr(ref pr) => Some(pr),
            _ => None,
        }
    }
}
