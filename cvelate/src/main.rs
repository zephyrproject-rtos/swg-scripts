use anyhow::Result;

use crate::advisory::Advisory;
use crate::cve::{
    Cve,
    Cves,
};
use crate::git::CmdRepository;
use crate::github::Github;
use crate::rnotes::Rnotes;
use clap::{
    App,
    load_yaml,
};
use crate::zepsec::PullRequest;
use chrono::Local;
use config::Config;
use git2::Repository;
use prettytable::{
    cell,
    format,
    row,
    Table,
};
use semver::Version;
// use regex::Regex;
use std::{
    collections::BTreeMap,
    sync::Arc,
};

mod advisory;
mod auth;
mod cve;
mod git;
mod github;
mod report;
mod rnotes;
mod zepsec;

static ZEPSEC_URL: &'static str = "https://zephyrprojectsec.atlassian.net/browse";

struct FullInfo {
    cves: Cves,
    info: Arc<zepsec::Info>,
    #[allow(unused)]
    github: Arc<Github>,
    #[allow(dead_code)]
    git: Repository,
    cmd_git: CmdRepository,
}

#[tokio::main]
async fn main() -> Result<()> {
    // TODO: Consider async_log to help.  For now, just use regular
    // logging.
    env_logger::init();

    let yaml = load_yaml!("cli.yaml");
    let matches = App::from_yaml(yaml).get_matches();

    // Load the config data.
    let cfile = matches.value_of("config").unwrap_or(".cvelate");
    let config = load_config(cfile)?;

    if let Some(_) = matches.subcommand_matches("cve") {
        FullInfo::new(&config).await?.cve_report().await?;
    } else if let Some(_) = matches.subcommand_matches("missing") {
        FullInfo::new(&config).await?.missing_embargo().await?;
    } else if let Some(_) = matches.subcommand_matches("embargo") {
        FullInfo::new(&config).await?.embargo().await?;
    } else if let Some(_) = matches.subcommand_matches("rnotes") {
        FullInfo::new(&config).await?.rnotes().await?;
    } else if let Some(_) = matches.subcommand_matches("merged") {
        FullInfo::new(&config).await?.merged().await?;
    } else if let Some(_) = matches.subcommand_matches("alerts") {
        FullInfo::new(&config).await?.alerts().await?;
    } else if let Some(_) = matches.subcommand_matches("backports") {
        FullInfo::new(&config).await?.backports().await?;
    } else if let Some(_) = matches.subcommand_matches("gh-status") {
        let adv = Advisory::new(&config)?;
        adv.report_tbd();
        adv.report_unreleased().await?;
    } else if let Some(_) = matches.subcommand_matches("debug-query") {
        zepsec::debug_load(&config).await?;
    } else {
        println!("Usage: {}", matches.usage());
    }

    Ok(())
}

impl FullInfo {
    async fn new(config: &Config) -> Result<FullInfo> {
        log::info!("Reading CVE database");
        let cves = Cves::fetch().await?;
        log::info!("Reading JIRA Issues");
        let info = Arc::new(zepsec::Info::load(config).await?);
        log::info!("Loading JIRA remotelinks");
        info.clone().concurrent_get_links().await?;
        let github = Arc::new(Github::new(config)?);
        let git = Repository::init(config.get_str("zephyr.repo")?)?;
        let cmd_git = CmdRepository::new(&git);
        Ok(FullInfo {
            cves,
            info,
            github,
            git,
            cmd_git,
        })
    }

    async fn cve_report(&self) -> Result<()> {
        log::info!("TODO: Report");
        report::make()?;
        Ok(())
    }

    async fn missing_embargo(&self) -> Result<()> {
        let missing = self.info.missing_embargo()?;
        println!("{:#?}", missing);
        Ok(())
    }

    async fn embargo(&self) -> Result<()> {
        let now = Local::now().naive_local().date();
        let mut past = false;
        let notes = Rnotes::load()?;

        let by_cve: BTreeMap<&str, &Cve> = self
            .cves
            .cve_ids
            .iter()
            .map(|c| (c.cve_id.as_str(), c))
            .collect();
        let embargo = self.info.embargo_dates()?;

        let mut tab = Table::new();
        tab.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        tab.set_titles(row!["Issue", "Embargo", "State", "CVE", "rnotes"]);
        for emb in &embargo {
            let ent = by_cve
                .get(emb.cve.as_str())
                .map(|c| format!("{:?}", c.state))
                .unwrap_or_else(|| "*None*".to_string());

            if !past && emb.embargo_date >= now {
                past = true;
                tab.add_row(row!["-----", "-------", "-----", "---", "------"]);
            }

            let rstate = notes.lookup(&emb.cve);
            tab.add_row(row![emb.key, emb.embargo_date, ent, emb.cve, rstate]);
        }
        let _ = tab.print_term(term::stdout().unwrap().as_mut())?;
        Ok(())
    }

    async fn rnotes(&self) -> Result<()> {
        let now = Local::now().naive_local().date();
        let notes = Rnotes::load()?;

        let embargo = self.info.embargo_dates()?;

        for emb in &embargo {
            let future = emb.embargo_date >= now;

            let rstate = notes.lookup(&emb.cve);
            if rstate == "Published" {
                continue;
            }
            // TODO: Parse CVE, and print canonical version without
            // extension.
            println!("{}", emb.cve);
            println!("-------------------");
            if future {
                println!("");
                println!("Under embargo until {}", emb.embargo_date);
                println!("");
            } else {
                println!("");
                println!("{}", self.info.issues[&emb.key].fields.summary);
                println!("");
                println!("This has been fixed in ???");
                println!("{:#?}", self.info.issues[&emb.key].fields.fix_versions);
                println!("");

                // First link is to the CVE database itself.
                println!(
                    "- `{} <https://cve.mitre.org/cgi-bin/cvename.cgi?name={}>`_",
                    emb.cve, emb.cve
                );
                println!("");

                // Second link is to the ZEPSEC bug tracker.
                println!("- `Zephyr project bug tracker {}", emb.key);
                println!(
                    "  <https://zephyrprojectsec.atlassian.net/browse/{}>`_",
                    emb.key
                );
                println!("");

                // Find all of the github links, and figure out what branch
                // they are on.
                // TODO: Figure out the branch.
                for link in self.info.get_link(&emb.key).await? {
                    println!("- `PR??? fix for v?.?.?");
                    println!("  <{}>`_", link);
                    println!("");
                }
                // println!("{} ({:?}) (future:{:?})", emb.cve, rstate, future);
            }
        }

        Ok(())
    }

    /// Generate a report of active issues (ones with links to github) that
    /// and compare what JIRA thinks about "fixed version", with where they
    /// were actually merged.
    async fn merged(&self) -> Result<()> {
        let issues = self.info.issues_with_prs().await?;
        // Collect all of the github PRs.
        let prs: BTreeMap<_, _> = issues
            .iter()
            .flat_map(|i| {
                i.links
                    .iter()
                    .filter(|l| l.user == "zephyrproject-rtos" && l.repo == "zephyr")
            })
            .map(|i| (i.pr, i.clone()))
            .collect();

        // Until BTreemap::info_values() is stable, we need to clone the
        // items.
        let prs: Vec<PullRequest> = prs.values().cloned().collect();

        log::info!("Getting {} PRs from github", prs.len());
        let prs = self.github.clone().bulk_get_pr(&prs).await?;
        for item in &issues {
            println!(
                "{:?}: {:?}",
                item.issue.key,
                item.links.iter().map(|i| i.pr).collect::<Vec<_>>()
            );
            println!("      fix (JIRA): {:?}",
                item.issue.fields.fix_versions
                    .iter()
                    .map(|v| &v.name)
                    .collect::<Vec<_>>());
            for pr in &item.links {
                // println!("{:#?}", prs.get(&pr.pr));

                // Try to lookup the commit.
                if let Some(minfo) = prs.get(&pr.pr) {
                    if !minfo.merged {
                        continue;
                    }

                    // Look up what tags contain this.
                    let contains = self.cmd_git.tag_contains(&minfo.merge_commit_sha).await?;
                    // println!("contains: {:?}", contains);
                    let mut versions = vec![];
                    for tag in &contains {
                        // // The tags start with either "v" or "zephyr-v",
                        // which we need to remove.
                        let tag = if tag.starts_with("v") {
                            &tag[1..]
                        } else if tag.starts_with("zephyr-v") {
                            &tag[8..]
                        } else {
                            tag
                        };

                        // Skip any that have a pre or build present.
                        if let Ok(ver) = Version::parse(tag) {
                            if ver.pre.len() > 0 || ver.build.len() > 0 {
                                continue;
                            }
                            // println!("  {:?}", ver);
                            versions.push(ver);
                        } else {
                            println!("  Unable to parse: {:?}", tag);
                        }
                    }

                    versions.sort();
                    if let Some(ver) = versions.iter().next() {
                        println!("             {:-6} merged: v{}", pr.pr, ver);
                    }

                    // Lookup what branches contain this (but only if there
                    // are no tags.
                    if versions.len() == 0 {
                        let contains = self.cmd_git.branch_contains(&minfo.merge_commit_sha).await?;
                        println!("branches: {:?}", contains);
                    }

                    // println!("versions: {:?}", versions);

                    /*
                    let oid = git2::Oid::from_str(&minfo.merge_commit_sha)?;
                    // TODO: Handle this failing.
                    let commit = self.git.find_object(oid, Some(git2::ObjectType::Commit))?;
                    // println!("commit: {:?}", commit);
                    let opts = git2::DescribeOptions::new();
                    // opts.describe_all();
                    let desc = commit.describe(&opts)?;
                    // println!("commit: {:?}", desc.format(None));
                    */
                }
            }
        }
        Ok(())
    }

    /// Generate a report of alerts that need to be sent.
    async fn alerts(&self) -> Result<()> {
        self.info.clone().fetch_all_comments().await?;
        /*
        let mut count = 0;
        for key in self.info.issues.keys() {
            let cblock = self.info.get_comments(key).await?;
            count += cblock.len();
        }
        */

        let embargo = self.info.embargo_dates()?;
        let now = Local::now().naive_local().date();

        for emb in &embargo {
            if emb.embargo_date < now {
                // Skip issues that have already passed embargo.
                continue;
            }

            /* TODO: figure out state from comments. */

            let issue = &self.info.issues[&emb.key];
            println!("## CVE {}: {}", emb.cve, issue.fields.summary);
            println!("");
            println!("- [Zephyr tracking {}]({}/{})", emb.key, ZEPSEC_URL, emb.key);
            println!("- Embargo: {}", emb.embargo_date);
            println!("");
            if issue.fields.fix_versions.len() == 0 {
                // TODO: Find links and post.
                println!("Fixes have not been released");
            } else {
                println!("Fixes have been released in {}", issue.fields.clean_fix_versions());
            }
            println!("");
            let links = self.info.get_github_links(&emb.key).await?;
            if !links.is_empty() {
                println!("The issue is addressed in the following pull requests");
                println!("");
                for link in &links {
                    println!("- [#{}]({})", link.pr, link.url());
                }
                println!("");
            }

            // Process the subtasks.
            let mut visited = false;
            for sub in self.info.subtasks(&emb.key)? {
                println!("- {}", sub.fields.summary);
                let links = self.info.get_github_links(&sub.key).await?;
                for link in &links {
                    println!("  - [#{}]({})", link.pr, link.url());
                }
                visited = true;
            }
            if visited {
                println!("");
            }
        }
        Ok(())
    }

    /// Generate a report on issues and backport completion.
    async fn backports(&self) -> Result<()> {
        let bps = self.info.get_backports()?;

        // Scan for backports that don't have An affects-version set.
        let mut all_bps: Vec<&zepsec::Issue> = bps.iter()
            .flat_map(|b| b.backports.iter())
            .cloned()
            // Don't show the ones that are Public or have been Rejected.
            // Release ones should move to Public, once the CVE is released.
            .filter(|b| b.fields.status.name != "Rejected" &&
                b.fields.status.name != "Public")
            .collect();
        all_bps.sort_by_key(|b| zepsec::keyvalue(&b.key));

        println!("---- Backport issue status");
        for bp in &all_bps {
            println!("{} {} ({})", bp.key, bp.fields.status,
                zepsec::SliceFmt(&bp.fields.versions));
            for lnk in self.info.get_github_links(&bp.key).await? {
                println!("        {}", lnk.url());
            }
        }

        println!("---- Issues with incorrect backports");
        for bp in &bps {
            // Skip those that are Rejected.  Don't skip Public because the backports still may
            // need to be done.
            if bp.issue.fields.status.name == "Rejected" {
                continue;
            }

            println!("{} (af:{} fix:{}): {}", bp.issue.key,
                zepsec::SliceFmt(&bp.issue.fields.versions),
                zepsec::SliceFmt(&bp.issue.fields.fix_versions),
                bp.issue.fields.cve
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("None"));
            /*
                bp.backports.iter().map(|s| &s.key)
                    .collect::<Vec<_>>());
            */
            for bpp in &bp.backports {
                let status = format!("{}", bpp.fields.status);
                println!("        {} {:<8} af:{} fix:{}",
                    bpp.key,
                    status,
                    zepsec::SliceFmt(&bpp.fields.versions),
                    zepsec::SliceFmt(&bpp.fields.fix_versions));
            }
        }
        Ok(())
    }
}

fn load_config(name: &str) -> Result<Config> {
    let mut settings = Config::default();
    settings
        .merge(config::File::with_name(name))?
        .merge(config::Environment::with_prefix("CVELATE"))?;

    Ok(settings)
}
