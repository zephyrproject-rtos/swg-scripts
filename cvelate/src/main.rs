use anyhow::Result;

use chrono::{DateTime, Utc};
use tokio::{
    io::AsyncReadExt,
    process::Command,
};
use serde::{
    de::{self, Deserialize, Deserializer},
};
use std::{
    fmt::Display,
    process::Stdio,
    result,
    str::FromStr,
};

#[derive(Debug, serde::Deserialize)]
struct Wrapper {
    cve_ids: Vec<Cve>,
}

#[derive(Debug, serde::Deserialize)]
struct Cve {
    cve_id: String,
    #[serde(deserialize_with = "from_str")]
    cve_year: u32,
    owning_cna: String,
    requested_by: Requestor,
    reserved: DateTime<Utc>,
    state: CveState,
    time: CMod,
}

#[derive(Debug, serde::Deserialize)]
struct Requestor {
    cna: String,
    user: String,
}

#[derive(Debug, serde::Deserialize)]
struct CMod {
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, serde::Deserialize)]
enum CveState {
    #[serde(rename = "PUBLIC")]
    Public,
    #[serde(rename = "RESERVED")]
    Reserved,
    #[serde(rename = "REJECT")]
    Reject,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Run the cve program.
    let mut cmd = Command::new("cve");

    cmd.stdout(Stdio::piped());

    let mut child = cmd
        .arg("list")
        .arg("--raw")
        .spawn()?;

    let mut stdout = child.stdout.take().expect("child set");

    // Spawn a child to get the results.
    tokio::spawn(async move {
        let status = child.wait().await
            .expect("child error");
        println!("Child status: {}", status);
    });

    let mut buffer = vec![];
    stdout.read_to_end(&mut buffer).await?;
    let data: Wrapper = serde_json::from_slice(&buffer)?;
    println!("data: {:#?}", data);
    Ok(())
}

fn from_str<'de, T, D>(deserializer: D) -> result::Result<T, D::Error>
    where T: FromStr,
          T::Err: Display,
          D: Deserializer<'de>
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(de::Error::custom)
}
