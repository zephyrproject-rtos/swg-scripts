//! Report generators.

use anyhow::Result;
use prettytable::{
    cell,
    row,
    // Cell, Row,
    Table,
};

pub fn make() -> Result<()> {
    let mut tab = Table::new();

    tab.add_row(row!["CVE", "github"]);
    tab.add_row(row!["CVE-2020-3301\nalt", "23091"]);
    tab.add_row(row!["CVE-2020-3302", "23092"]);

    let _ = tab.print_term(term::stdout().unwrap().as_mut())?;
    Ok(())
}
