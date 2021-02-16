use anyhow::Result;
use chrono::{
    DateTime,
    Utc,
};
use serde::de::{
    self,
    Deserialize,
    Deserializer,
};
use std::{
    fmt::Display,
    process::Stdio,
    result,
    str::FromStr,
};
use tokio::{
    io::AsyncReadExt,
    process::Command,
};

#[derive(Debug, serde::Deserialize)]
pub struct Cves {
    pub cve_ids: Vec<Cve>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Cve {
    pub cve_id: String,
    #[serde(deserialize_with = "from_str")]
    pub cve_year: u32,
    pub owning_cna: String,
    pub requested_by: Requestor,
    pub reserved: DateTime<Utc>,
    pub state: CveState,
    pub time: CMod,
}

#[derive(Debug, serde::Deserialize)]
pub struct Requestor {
    pub cna: String,
    pub user: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct CMod {
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, serde::Deserialize)]
pub enum CveState {
    #[serde(rename = "PUBLIC")]
    Public,
    #[serde(rename = "RESERVED")]
    Reserved,
    #[serde(rename = "REJECT")]
    Reject,
}

impl Cves {
    pub async fn fetch() -> Result<Cves> {
        // Run the cve program.
        let mut cmd = Command::new("cve");

        cmd.stdout(Stdio::piped());

        let mut child = cmd.arg("list").arg("--raw").spawn()?;

        let mut stdout = child.stdout.take().expect("child set");

        // Spawn a child to get the results.
        tokio::spawn(async move {
            let status = child.wait().await.expect("child error");
            if !status.success() {
                log::error!("Error running cve tool: {:?}", status);
            }
        });

        let mut buffer = vec![];
        stdout.read_to_end(&mut buffer).await?;
        let data: Cves = serde_json::from_slice(&buffer)?;
        Ok(data)
    }
}

fn from_str<'de, T, D>(deserializer: D) -> result::Result<T, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(de::Error::custom)
}
