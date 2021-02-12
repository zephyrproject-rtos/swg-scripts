//! Authentication information.

use anyhow::Result;
use config::Config;

#[derive(Debug)]
pub struct Auth {
    pub login: String,
    pub password: String,
}

impl Auth {
    pub fn from_config(config: &Config, section: &str) -> Result<Auth> {
        let login = config.get_str(&format!("{}.login", section))?;
        let password = config.get_str(&format!("{}.password", section))?;
        Ok(Auth { login, password })
    }
}
