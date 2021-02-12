//! Library for querying github

use anyhow::Result;
use config::Config;
use reqwest::Client;
use serde::Deserialize;
// use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Arc,
};

use crate::zepsec::PullRequest;

use crate::auth::Auth;

#[allow(unused)]
static HOST: &str = "api.github.com";

#[derive(Debug)]
pub struct Github {
    client: Client,
    auth: Auth
}

/// Simple information about what has merged.
#[derive(Debug, Deserialize)]
pub struct MergeInfo {
    pub title: String,
    pub issue_url: String,
    pub merge_commit_sha: String,
    pub merged: bool,
    pub number: usize,
    pub state: String,
}

impl Github {
    pub fn new(config: &Config) -> Result<Github> {
        let auth = Auth::from_config(config, "github")?;
        let client = Client::new();

        Ok(Github { client, auth })
    }

    /// Synthesize a url for a pr.
    fn pr_url(&self, pr: &PullRequest) -> String {
        format!("https://api.github.com/repos/{}/{}/pulls/{}",
            pr.user, pr.repo, pr.pr)
    }

    /// Get the basic PR information.
    pub async fn get_pr(&self, pr: &PullRequest) -> Result<MergeInfo> {
        let resp = self.client.get(&self.pr_url(pr))
            .basic_auth(&self.auth.login, Some(&self.auth.password))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "https://github.com/zephyrproject-rtos/swg-tools")
            .send()
            .await?;
        // println!("Headers: {:#?}", resp.headers());
        // println!("resp: {:#?}", resp.json::<Value>().await?);
        let info = resp.json::<MergeInfo>().await?;
        // println!("info: {:#?}", info);
        Ok(info)
    }

    /// Perform a bulk query of issues, returning a map of the results.
    pub async fn bulk_get_pr(self: Arc<Github>, prs: &[PullRequest]) ->
        Result<HashMap<usize, MergeInfo>>
    {
        let children: Vec<_> = prs.iter().map(|key| {
            let key = key.clone();
            let gh = self.clone();
            tokio::spawn(async move {
                let value = gh.get_pr(&key).await.unwrap();
                (key.pr, value)
            })
        }).collect();
        let mut result = HashMap::new();

        for child in children {
            let (key, value) = child.await?;
            result.insert(key, value);
        }
        Ok(result)
    }
}
