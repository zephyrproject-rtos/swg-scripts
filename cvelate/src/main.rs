use anyhow::Result;

use crate::cve::{
    Cves,
};
use std::{
    sync::Arc,
};

mod cve;
mod zepsec;

#[tokio::main]
async fn main() -> Result<()> {
    // CVE fetch.
    if false {
        let data = Cves::fetch().await?;
        println!("data: {:#?}", data);
    }

    // Query JIRA.
    if true {
        let info = Arc::new(zepsec::Info::load().await?);
        println!("issues: {}", info.issues.len());
        // println!("issues: {:#?}", info.issues);

        info.clone().concurrent_get_links().await?;
        for key in info.issues.keys() {
            let link = info.get_link(key).await?;
            println!("2nd: {:?}: {:?}", key, link);
        }
    }

    Ok(())
}
