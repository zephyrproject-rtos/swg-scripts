use curl::easy::Easy;
use anyhow::Result;
use scraper::{Html, Selector};
use std::{
    fs::File,
    io::Write,
    path::Path,
    str,
};

const PROJECT: &str = "zephyrproject-rtos";
const REPO: &str = "zephyr";
const GITHUB: &str = "https://github.com";

fn main() -> Result<()> {
    let mut easy = Easy::new();

    easy.cookie_file("cookies-github-com.txt")?;

    let advs = Advisory::get_list(&mut easy)?;
    println!("Got {} advisories", advs.len());
    println!("{:#?}", advs);

    Ok(())
}

#[derive(Debug)]
struct Advisory {
    name: String,
    url: String,
    description: String,
}

impl Advisory {
    /// Query the main advisories index, and get a list of all relevant advisories on the project.
    fn get_list(easy: &mut Easy) -> Result<Vec<Advisory>> {
        let mut result = vec![];

        let mut next_url = Some(advisory_url(1));

        while let Some(url) = next_url {
            println!("Url: {}", url);
            easy.url(&url)?;
            let mut buf = Vec::new();
            {
                let mut transfer = easy.transfer();
                transfer.write_function(|data| {
                    buf.extend_from_slice(data);
                    Ok(data.len())
                })?;
                transfer.perform()?;
            }
            let text = str::from_utf8(&buf)?;

            let doc = Html::parse_document(&text);

            let sel = Selector::parse("a.Link--primary").unwrap();

            for elt in doc.select(&sel) {
                let mut description = String::new();
                for t in elt.text() {
                    if !description.is_empty() {
                        description.push('\n');
                    }
                    description.push_str(t.trim());
                }
                let url = elt.value().attr("href").expect("href in a");
                let name = &url[url.len() - 19 .. url.len()];
                result.push(Advisory {
                    name: name.to_owned(),
                    url: url.to_owned(),
                    description,
                });
            }

            // Extract the next page link from the paginator.
            let sel = Selector::parse("div.pagination a.next_page").unwrap();

            next_url = None;
            for elt in doc.select(&sel) {
                next_url = Some(format!("{}{}",
                        GITHUB,
                        elt.value().attr("href").expect("a in href").to_owned()));
            }
        }

        Ok(result)
    }
}

/// Generate an advisory url for a given page.
fn advisory_url(page: usize) -> String {
    format!("{}/{}/{}/security/advisories?page={}&state=published",
        GITHUB, PROJECT, REPO, page)
}

/// Dump some data to the given file.
#[allow(dead_code)]
fn dump<P: AsRef<Path>>(p: P, data: &[u8]) -> Result<()> {
    File::create(p)?.write_all(data)?;
    Ok(())
}
