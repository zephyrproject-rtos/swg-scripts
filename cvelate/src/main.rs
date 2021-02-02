use anyhow::Result;

use crate::cve::{
    Cves,
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
        let info = zepsec::Info::load().await?;
        println!("issues: {}", info.issues.len());
    }

    Ok(())
}
