use anyhow::Result;

use chrono::Local;
use crate::cve::{
    Cves, Cve,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
};

mod cve;
mod report;
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
        "cve" => FullInfo::new().await?.cve_report().await?,
        "missing" => FullInfo::new().await?.missing_embargo().await?,
        "embargo" => FullInfo::new().await?.embargo().await?,
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
    async fn new() -> Result<FullInfo> {
        log::info!("Reading CVE database");
        let cves = Cves::fetch().await?;
        log::info!("Reading JIRA Issues");
        let info = Arc::new(zepsec::Info::load().await?);
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

        let by_cve: BTreeMap<String, &Cve> = self.cves.cve_ids
            .iter()
            .map(|c| (c.cve_id.clone(), c))
            .collect();
        let embargo = self.info.embargo_dates()?;
        println!("Issue      | Embargo    | State    | CVE");
        println!("-----------+------------+----------+--------------");
        for emb in &embargo {
            let ent = by_cve.get(&emb.cve)
                .map(|c| format!("{:?}", c.state))
                .unwrap_or_else(|| "*None*".to_string());

            if !past && emb.embargo_date >= now {
                past = true;
                println!("-----------+------------+----------+--------------");
            }
            println!("{:-10} | {:-12} | {:-8} | {}", emb.key, emb.embargo_date, ent, emb.cve);
        }
        Ok(())
    }
}
