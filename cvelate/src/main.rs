use anyhow::Result;

use crate::cve::{
    Cves,
};

mod cve;

#[tokio::main]
async fn main() -> Result<()> {
    let data = Cves::fetch().await?;
    println!("data: {:#?}", data);
    Ok(())
}
