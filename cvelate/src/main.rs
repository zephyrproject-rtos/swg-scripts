use anyhow::Result;

use chrono::Local;
use config::Config;
use crate::cve::{
    Cves, Cve,
};
use crate::rnotes::Rnotes;
use prettytable::{
    format,
    Table,
    cell, row,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
};

mod cve;
mod report;
mod rnotes;
mod zepsec;

struct FullInfo {
    cves: Cves,
    info: Arc<zepsec::Info>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // TODO: Consider async_log to help.  For now, just use regular
    // logging.
    env_logger::init();

    // Load the config data.
    let config = load_config()?;

    // For now, expect a single argument, which is a command to perform.
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        log::error!("Usage: {} command", args[0]);
        log::error!("");
        log::error!("Commands:");
        log::error!("    cve - Report on CVE status.");
        return Ok(());
    }

    match args[1].as_str() {
        "cve" => FullInfo::new(&config).await?.cve_report().await?,
        "missing" => FullInfo::new(&config).await?.missing_embargo().await?,
        "embargo" => FullInfo::new(&config).await?.embargo().await?,
        "rnotes" => FullInfo::new(&config).await?.rnotes().await?,
        cmd => {
            log::error!("Unknown command: {:?}", cmd);
            return Ok(());
        }
    }

    /*
    // CVE fetch.
    if false {
        let data = Cves::fetch().await?;
        println!("data: {:#?}", data);
    }

    // Query JIRA.
    if false {
        let info = Arc::new(zepsec::Info::load().await?);
        println!("issues: {}", info.issues.len());
        // println!("issues: {:#?}", info.issues);

        info.clone().concurrent_get_links().await?;
        for key in info.issues.keys() {
            let link = info.get_link(key).await?;
            println!("2nd: {:?}: {:?}", key, link);
        }
    }

    // Report
    if true {
        report::make()?;
    }
    */

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
        Ok(FullInfo{ cves, info })
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

        let by_cve: BTreeMap<&str, &Cve> = self.cves.cve_ids
            .iter()
            .map(|c| (c.cve_id.as_str(), c))
            .collect();
        let embargo = self.info.embargo_dates()?;

        let mut tab = Table::new();
        tab.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        tab.set_titles(row!["Issue", "Embargo", "State", "CVE", "rnotes"]);
        for emb in &embargo {
            let ent = by_cve.get(emb.cve.as_str())
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
                println!("- `{} <https://cve.mitre.org/cgi-bin/cvename.cgi?name={}>`_",
                    emb.cve, emb.cve);
                println!("");

                // Second link is to the ZEPSEC bug tracker.
                println!("- `Zephyr project bug tracker {}", emb.key);
                println!("  <https://zephyrprojectsec.atlassian.net/browse/{}>`_", emb.key);
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
}

fn load_config() -> Result<Config> {
    let mut settings = Config::default();
    settings
        .merge(config::File::with_name(".cvelate"))?
        .merge(config::Environment::with_prefix("CVELATE"))?;

    Ok(settings)
}
