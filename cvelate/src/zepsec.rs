//! Library for queries to Zepsec.

use anyhow::{anyhow, Result};
use netrc::{Machine, Netrc};
use serde::{Deserialize};
// use serde_json::Value;
use std::{
    fs::File,
    io::BufReader,
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

#[derive(Debug, Deserialize)]
struct Issue {
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

pub async fn run() -> Result<()> {
    let auth = netrc()?;
    let client = reqwest::Client::new();
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
        println!("count: {}, max: {}, total: {}", count, resp.max_results, resp.total);
        start += count;

        // If the reply was fewer than requested, there aren't any more.
        if count < resp.max_results {
            break;
        }
    }
    println!("{} issues", result.len());
    println!("{:#?}", result);
    Ok(())
}
