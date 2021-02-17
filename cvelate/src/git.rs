//! Direct git operations.
//!
//! There are some features of libgit2 that haven't been implemented yet,
//! including `git tag --contains <sha>`.  We will implement this by simply
//! invoking this as a git command.

use anyhow::Result;
use git2::Repository;
use std::{
    path::PathBuf,
    process::Stdio,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{
        Command,
    },
};

pub struct CmdRepository(PathBuf);

impl CmdRepository {
    pub fn new(repo: &Repository) -> CmdRepository {
        CmdRepository(repo.path().to_path_buf())
    }

    pub async fn tag_contains(&self, sha: &str) -> Result<Vec<String>> {
        let mut cmd = Command::new("git");
        cmd.stdout(Stdio::piped());
        cmd.arg("tag");
        cmd.arg("--contains");
        cmd.arg(sha);
        cmd.current_dir(&self.0);

        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take().expect("child set");

        // Spawn a child to get the results.
        tokio::spawn(async move {
            let status = child.wait().await.expect("child error");
            if !status.success() {
                log::error!("Error running git: {:?}", status);
            }
        });

        let mut result: Vec<String> = vec![];
        let mut lines = BufReader::new(stdout).lines();
        while let Some(line) = lines.next_line().await? {
            result.push(line);
        }
        Ok(result)
    }
}
