//! Library for queries to Zepsec.

use anyhow::{anyhow, Result};
use chrono::NaiveDate;
use config::Config;
use lazy_static::lazy_static;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
// use serde_json::Value;
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    sync::{
        Arc,
        Mutex,
    },
};

use crate::auth::Auth;

static HOST: &str = "zephyrprojectsec.atlassian.net";
fn url(cmd: &str) -> String {
    format!("https://{}/rest/api/2/{}", HOST, cmd)
}

// Query type for search.
#[derive(Debug, Deserialize)]
struct SearchResult {
    issues: Vec<Issue>,
    #[serde(rename = "maxResults")]
    max_results: usize,
    #[serde(rename = "startAt")]
    start_at: usize,
    total: usize,
}

// Query type for "comment"
#[derive(Debug, Deserialize)]
struct CommentResult {
    comments: Vec<Comment>,
    #[serde(rename = "maxResults")]
    max_results: usize,
    #[serde(rename = "startAt")]
    start_at: usize,
    total: usize,
}

#[derive(Debug)]
pub struct Info {
    /// The client, so additional queries can be made using the same
    /// potential connection.
    client: Option<Client>,

    /// The auth data.
    auth: Auth,

    /// The issues themselves.  This is a mapping from the JIRA key to the
    /// issue itself.
    pub issues: BTreeMap<String, Issue>,

    /// We look up links lazily (since it is fairly slow, and we're likely
    /// only to need information about a subset of the issues).  This map
    /// from key to link info (which are Strings currently), will be filled
    /// with a vec of the links.
    links: Arc<Mutex<BTreeMap<String, Vec<String>>>>,

    /// Comments are looked up asynchronously.
    comments: Arc<Mutex<BTreeMap<String, Vec<Comment>>>>,
}

#[derive(Debug)]
pub struct MissingInfo {
    pub key: String,
    pub cve: String,
}

#[derive(Debug)]
pub struct EmbargoInfo {
    pub key: String,
    pub cve: String,
    pub embargo_date: NaiveDate,
}

#[derive(Debug, Deserialize)]
pub struct Issue {
    pub fields: SubIssue,
    pub key: String,
    #[serde(rename = "self")]
    url: String,
}

#[derive(Debug, Deserialize)]
pub struct SubIssue {
    description: Option<String>,
    pub summary: String,
    #[serde(rename = "customfield_10035")]
    pub cve: Option<String>,

    issuetype: IssueType,

    #[serde(rename = "customfield_10051")]
    embargo_date: Option<NaiveDate>,

    pub versions: Vec<Version>,
    #[serde(rename = "fixVersions")]
    pub fix_versions: Vec<Version>,
    pub status: Status,
    subtasks: Vec<Subtask>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Comment {
    pub author: Author,
    pub body: String,
    pub created: String,
}

// Enough information about the author
#[derive(Clone, Debug, Deserialize)]
pub struct Author {
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Deserialize)]
pub struct IssueType {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct Version {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct Status {
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct Subtask {
    key: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkOuter {
    object: LinkInner,
}

#[derive(Debug, Deserialize)]
struct LinkInner {
    url: String,
    // object: LinkObject,
}

#[derive(Debug, Deserialize)]
struct LinkObject {
    url: String,
}

/// An issue with associated links.
#[derive(Debug)]
pub struct IssueLinks<'a> {
    pub issue: &'a Issue,
    pub links: Vec<PullRequest>,
}

/// A single github link, decoded.
#[derive(Clone, Debug)]
pub struct PullRequest {
    pub user: String,
    pub repo: String,
    pub pr: usize,
}

/// For debugging, query and write the json data to a file.
pub async fn debug_load(config: &Config) -> Result<()> {
    let auth = Auth::from_config(config, "zepsec")?;
    let client = Client::new();
    let start = 1;
    let mut out = File::create("zepsec-debug.json")?;
    loop {
        let start_text = format!("{}", start);
        let resp = client
            .get(&url("search"))
            .basic_auth(&auth.login, Some(&auth.password))
            .query(&[("jql", "project=\"ZEPSEC\""), ("startAt", &start_text),
                // ("expand", "changelog"),
                // ("fields", "comments"),
            ])
            .send().await?
            .json::<serde_json::Value>().await?;
        serde_json::to_writer_pretty(&mut out, &resp)?;
        break;
    }

    Ok(())
}

impl Info {
    // Load the basic info from JIRA.  This fills in everything that can be
    // determined by a single search query.
    pub async fn load(config: &Config) -> Result<Info> {
        let auth = Auth::from_config(config, "zepsec")?;
        let client = Client::new();
        let mut result = vec![];
        let mut start = 0;
        loop {
            let start_text = format!("{}", start);
            let mut resp = client
                .get(&url("search"))
                .basic_auth(&auth.login, Some(&auth.password))
                .query(&[("jql", "project=\"ZEPSEC\""), ("startAt", &start_text),
                    ("fields", "description,summary,issuetype,customfield_10035,customfield_10051,versions,fixVersions,status,subtasks"),
                ])
                .send()
                .await?
                .json::<SearchResult>()
                .await?;
            let count = resp.issues.len();
            result.append(&mut resp.issues);
            // println!("count: {}, max: {}, total: {}", count, resp.max_results, resp.total);
            start += count;

            // If the reply was fewer than requested, there aren't any more.
            if count < resp.max_results {
                break;
            }
        }
        // println!("{} issues", result.len());
        // println!("{:#?}", result);

        // Convert the result into a map.
        Ok(Info {
            auth: auth,
            client: Some(client),
            issues: result.into_iter().map(|i| (i.key.clone(), i)).collect(),
            links: Arc::new(Mutex::new(BTreeMap::new())),
            comments: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    // Lookup the external links for a single issue.
    async fn lookup_link(&self, key: &str) -> Result<Vec<String>> {
        let resp = self
            .client
            .as_ref()
            .unwrap()
            .get(&url(&format!("issue/{}/remotelink", key)))
            .basic_auth(&self.auth.login, Some(&self.auth.password))
            .send()
            .await?
            .json::<Vec<LinkOuter>>()
            .await?;
        Ok(resp.into_iter().map(|l| l.object.url).collect())
    }

    /// Cached version of the lookup.  Note that this clones the result.
    pub async fn get_link(&self, key: &str) -> Result<Vec<String>> {
        // This has to be '.unwrap()' instead of '?' because the
        // PoisonError that .lock() can return is not Send, and therefore
        // the result cannot be captured within the Future.  A poisoned
        // lock here would result in a panic anyway, so little harm comes
        // from this.
        if let Some(v) = self.links.lock().unwrap().get(key) {
            return Ok(v.clone());
        }

        let v = self.lookup_link(key).await?;

        // We release the lock, which might allow for another thread to
        // also look up a given entry.  If single threaded, this won't ever
        // happen, and if multi threaded, the returned data (which
        // shouldn't be changing), would result in a few extra queries,
        // likely more than being made up for by the concurrent queries.
        self.links.lock().unwrap().insert(key.into(), v.clone());
        Ok(v)
    }

    /// Get a list of github links.
    pub async fn get_github_links(&self, key: &str) -> Result<Vec<PullRequest>> {
        let links = self.get_link(key).await?;
        Ok(links
            .into_iter()
            .flat_map(|l| PullRequest::parse(&l))
            // .filter(|l| l.starts_with("https://github.com"))
            .collect())
    }

    /// Look up all of the issue links, in parallel.  This needs the Info
    /// as an Arc so that the results can be returned.
    pub async fn concurrent_get_links(self: Arc<Info>) -> Result<()> {
        let children: Vec<_> = self
            .issues
            .keys()
            .map(|key| {
                let key = key.clone();
                let info = self.clone();
                tokio::spawn(async move { info.get_link(&key).await })
            })
            .collect();

        for child in children {
            let _ = child.await?;
        }
        Ok(())
    }

    /// Retrieve all issues that have a CVE but don't have an embargo date.
    pub fn missing_embargo(&self) -> Result<Vec<MissingInfo>> {
        let mut result: Vec<_> = self
            .issues
            .values()
            .filter(|issue| issue.fields.cve.is_some() && issue.fields.embargo_date.is_none())
            .map(|issue| MissingInfo {
                key: issue.key.clone(),
                cve: issue.fields.cve.as_ref().unwrap().clone(),
            })
            .collect();

        // This sort isn't perfect, as it will put CVEs with more digits
        // after earlier ones.  Now that CVEs regularly get 5 digits, this
        // can be misleading.
        result.sort_by(|a, b| a.cve.cmp(&b.cve));

        Ok(result)
    }

    /// Retrieve all issues that have a CVE with an embargo date.
    pub fn embargo_dates(&self) -> Result<Vec<EmbargoInfo>> {
        let mut result: Vec<_> = self
            .issues
            .values()
            .filter(|issue| issue.fields.cve.is_some() && issue.fields.embargo_date.is_some())
            .map(|issue| EmbargoInfo {
                key: issue.key.clone(),
                cve: issue.fields.cve.as_ref().unwrap().clone(),
                embargo_date: issue.fields.embargo_date.as_ref().unwrap().clone(),
            })
            .collect();

        // This sort isn't perfect, as it will put CVEs with more digits
        // after earlier ones.  Now that CVEs regularly get 5 digits, this
        // can be misleading.
        result.sort_by(|a, b| a.embargo_date.cmp(&b.embargo_date));

        Ok(result)
    }

    /// Retrieve all issues that are considered open, and have at least one
    /// remote link to a github issue.
    pub async fn issues_with_prs<'a>(&'a self) -> Result<Vec<IssueLinks<'a>>> {
        let mut result = vec![];
        for issue in self.issues.values() {
            if issue.fields.status.name == "Rejected" {
                continue;
            }
            let links = self.get_github_links(&issue.key).await?;
            if links.len() == 0 {
                continue;
            }

            result.push(IssueLinks { issue, links });
        }
        result.sort_by_key(|il| keyvalue(&il.issue.key));
        Ok(result)
    }

    /// Retrieve the comments associated with the given issue.
    async fn fetch_comments(&self, key: &str) -> Result<Vec<Comment>> {
        let mut result = vec![];
        let mut start = 0;
        loop {
            let start_text = format!("{}", start);
            let mut resp = self.client.as_ref().unwrap()
                .get(&url(&format!("issue/{}/comment", key)))
                .basic_auth(&self.auth.login, Some(&self.auth.password))
                .query(&[("startAt", &start_text)])
                .send().await?
                .json::<CommentResult>().await?;
            let count = resp.comments.len();
            result.append(&mut resp.comments);
            start += count;

            if count < resp.max_results {
                break;
            }
        }
        Ok(result)
    }

    /// Pull in the comments for all issues.
    pub async fn fetch_all_comments(self: Arc<Info>) -> Result<()> {
        let children: Vec<_> = self
            .issues
            .keys()
            .map(|key| {
                let key = key.clone();
                let info = self.clone();
                tokio::spawn(async move {
                    match info.fetch_comments(&key).await {
                        Ok(comments) => {
                            info.comments.lock().unwrap().insert(key, comments);
                        }
                        Err(e) => log::error!("Error fetching comments: {:?}", e),
                    }
                })
            })
            .collect();

        // Run all of the queries to completion.
        for child in children {
            let _ = child.await?;
        }

        Ok(())
    }

    /// Retrieve the comments for a given issue.  If `fetch_all_comments`
    /// has been run, this should return quickly, otherwise, it will
    /// involve a query to JIRA.  Note that the comments will be cloned for
    /// the return.
    #[allow(dead_code)]
    pub async fn get_comments(&self, key: &str) -> Result<Vec<Comment>> {
        if let Some(v) = self.comments.lock().unwrap().get(key) {
            return Ok(v.to_vec());
        }

        let v = self.fetch_comments(key).await?;

        // The lock is released, but multiple fetches should return the
        // same data.
        self.comments.lock().unwrap().insert(key.into(), v.clone());
        Ok(v)
    }

    /// Get the subtasks associated with a given task.
    pub fn subtasks(&self, key: &str) -> Result<Vec<&Issue>> {
        let item = match self.issues.get(key) {
            Some(item) => item,
            None => return Err(anyhow!("Issue not found: {}", key)),
        };

        let mut result = vec![];
        for sub in &item.fields.subtasks {
            if let Some(item) = self.issues.get(&sub.key) {
                result.push(item);
            } else {
                log::warn!("Unable to find subtask: {}", sub.key);
            }
        }
        Ok(result)
    }

    /// Get reverences to the data, organized by issue, and then by backport.
    pub fn get_backports(&self) -> Result<Vec<BackPort>> {
        let mut result: Vec<_> = self.issues.values()
            .filter(|s| s.fields.issuetype.name == "Bug")
            .map(|s| BackPort {
                issue: s,
                // TODO: The unwrap is unfriendly.
                backports: self.subtasks(&s.key).unwrap(),
            })
            .collect();

        result.sort_by_key(|il| keyvalue(&il.issue.key));

        Ok(result)
    }
}

#[derive(Debug)]
pub struct BackPort<'a> {
    pub issue: &'a Issue,
    pub backports: Vec<&'a Issue>,
}

lazy_static! {
    static ref PR_RE: Regex =
        Regex::new(r"^https://github.com/([^/]+)/([^/]+)/pull/(\d+)$").unwrap();
}

impl PullRequest {
    fn parse(url: &str) -> Option<PullRequest> {
        PR_RE.captures(url).map(|cap| PullRequest {
            user: cap.get(1).unwrap().as_str().to_string(),
            repo: cap.get(2).unwrap().as_str().to_string(),
            pr: cap.get(3).unwrap().as_str().parse().unwrap(),
        })
    }

    pub fn url(&self) -> String {
        format!("https://github.com/{}/{}/pull/{}", self.user, self.repo, self.pr)
    }
}

impl SubIssue {
    /// Represent the fix versions in a human readable manner.
    pub fn clean_fix_versions(&self) -> String {
        let mut result = String::new();

        for pos in 0..self.fix_versions.len() {
            if pos > 0 {
                result.push_str(", ");
            }
            if pos > 0 && pos == self.fix_versions.len() - 1 {
                // Insert Oxford comma debate here.
                result.push_str("and ");
            }
            result.push_str(&self.fix_versions[pos].name);
        }

        if result.is_empty() {
            result.push_str("none");
        }

        result
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// A wrapper to compactly Display vecs.
pub struct SliceFmt<'a, V>(pub &'a [V]);

impl<'a, V> fmt::Display for SliceFmt<'a, V>
where V: fmt::Display
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() == 1 {
            write!(f, "{}", self.0[0])
        } else {
            // write!(f, "[")?;
            for i in 0 .. self.0.len() {
                if i > 0 {
                    write!(f, ",")?;
                }
                write!(f, "{}", self.0[i])?;
            }
            // write!(f, "]")
            Ok(())
        }
    }
}

// Decompose a JIRA issue number so that numbers are sorted properly.
pub fn keyvalue(text: &str) -> (&str, usize) {
    let fields: Vec<&str> = text.split('-').collect();
    assert_eq!(fields.len(), 2);
    let num: usize = fields[1].parse().expect("JIRA issue to be AAAAA-nn");
    (fields[0], num)
}

// Decompose a CVE so it can sort properly.
pub fn cvevalue(text: &str) -> (usize, usize) {
    let fields: Vec<&str> = text.split('-').collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "CVE");
    let year: usize = fields[1].parse().expect("CVE year must be digits");
    let num: usize = fields[2].parse().expect("CVE number must be digits");
    (year, num)
}
