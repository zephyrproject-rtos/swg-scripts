//! Library for queries to Zepsec.

use anyhow::{anyhow, Result};
use chrono::NaiveDate;
use netrc::{Machine, Netrc};
use reqwest::Client;
use serde::{Deserialize};
// use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::File,
    io::BufReader,
    sync::{Arc, Mutex},
};

// Grumble, netrc doesn't implement StdError for its Error type.
// And, it can't handle comments in the file.  Looks rather pointless as a
// crate, doesn't it.

static HOST: &str = "zephyrprojectsec.atlassian.net";
fn url(cmd: &str) -> String {
    format!("https://{}/rest/api/2/{}", HOST, cmd)
}

fn netrc() -> Result<Machine> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Unable to read home directory"))?;
    let netrc = home.join(".netrc");

    let rc = match Netrc::parse(BufReader::new(File::open(&netrc)?)) {
        Ok(r) => r,
        Err(e) => return Err(anyhow!("Error opening .netrc: {:?}", e)),
    };

    let mut host = None;
    for h in &rc.hosts {
        if h.0 == HOST {
            host = Some(&h.1);
            break
        }
    }
    let host = host.ok_or_else(|| anyhow!("Machine not found in .netrc: {:?}", HOST))?;

    // Ugh, they don't even define Clone for the Machine type.
    Ok(Machine {
        login: host.login.clone(),
        password: host.password.clone(),
        account: host.account.clone(),
        port: host.port.clone(),
    })
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

#[derive(Debug)]
pub struct Info {
    /// The client, so additional queries can be made using the same
    /// potential connection.
    client: Option<Client>,

    /// The auth data.
    auth: Machine,

    /// The issues themselves.  This is a mapping from the JIRA key to the
    /// issue itself.
    pub issues: BTreeMap<String, Issue>,

    /// We look up links lazily (since it is fairly slow, and we're likely
    /// only to need information about a subset of the issues).  This map
    /// from key to link info (which are Strings currently), will be filled
    /// with a vec of the links.
    links: Arc<Mutex<BTreeMap<String, Vec<String>>>>,
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
    fields: SubIssue,
    key: String,
    #[serde(rename = "self")]
    url: String,
}

#[derive(Debug, Deserialize)]
struct SubIssue {
    description: Option<String>,
    summary: String,
    #[serde(rename = "customfield_10035")]
    cve: Option<String>,

    #[serde(rename = "customfield_10051")]
    embargo_date: Option<NaiveDate>,

    versions: Vec<Version>,
    #[serde(rename = "fixVersions")]
    fix_versions: Vec<Version>,
    status: Status,
    subtasks: Vec<Subtask>,
}

#[derive(Debug, Deserialize)]
struct Version {
    name: String,
}

#[derive(Debug, Deserialize)]
struct Status {
    name: String,
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

impl Info {
    // Load the basic info from JIRA.  This fills in everything that can be
    // determined by a single search query.
    pub async fn load() -> Result<Info> {
        let auth = netrc()?;
        let client = Client::new();
        let mut result = vec![];
        let mut start = 1;
        loop {
            let start_text = format!("{}", start);
            let mut resp = client.get(&url("search"))
                .basic_auth(&auth.login, auth.password.as_ref())
                .query(&[("jql", "project=\"ZEPSEC\""), ("startAt", &start_text)])
                .send()
                .await?
                .json::<SearchResult>().await?;
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
        })
    }

    // Lookup the external links for a single issue.
    async fn lookup_link(&self, key: &str) -> Result<Vec<String>> {
        let resp = self.client.as_ref().unwrap().get(&url(&format!("issue/{}/remotelink", key)))
            .basic_auth(&self.auth.login, self.auth.password.as_ref())
            .send()
            .await?
            .json::<Vec<LinkOuter>>().await?;
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

    /// Look up all of the issue links, in parallel.  This needs the Info
    /// as an Arc so that the results can be returned.
    pub async fn concurrent_get_links(self: Arc<Info>) -> Result<()> {
        let children: Vec<_> = self.issues.keys().map(|key| {
            let key = key.clone();
            let info = self.clone();
            tokio::spawn(async move {
                info.get_link(&key).await
            })
        }).collect();

        for child in children {
            let _ = child.await?;
        }
        Ok(())
    }

    /// Retrieve all issues that have a CVE but don't have an embargo date.
    pub fn missing_embargo(&self) -> Result<Vec<MissingInfo>> {
        let mut result: Vec<_> = self.issues.values()
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
        let mut result: Vec<_> = self.issues.values()
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
}
