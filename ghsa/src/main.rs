use curl::easy::Easy;
use anyhow::{anyhow, Result};
use scraper::{
    ElementRef,
    Html,
    html::Select,
    Selector,
};
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
    // println!("{:#?}", advs);

    let () = advs[0].fetch(&mut easy)?;

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
            let text = easy.fetch(&url)?;

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

    /// Given an advisory fetch it and return the extracted data.
    fn fetch(&self, easy: &mut Easy) -> Result<()> {
        let text = easy.fetch(&format!("{}{}", GITHUB, self.url))?;
        // dump("ghsa1.html", text.as_bytes())?;
        let doc = Html::parse_document(&text);

        // Get the GHSA name.
        let sel = Selector::parse("div.TableObject-item--primary span").unwrap();
        let elt = single(doc.select(&sel))?;
        let name = text1(elt)?;
        println!("name: {:?}", name);

        // Affects and fixed versions.
        let sel = Selector::parse("div.f4").unwrap();
        let elts: Result<Vec<&str>> = doc.select(&sel).map(|elt| text1(elt)).collect();
        let elts = elts?;

        let affects = elts[0].to_owned();
        let fixed = elts[1].to_owned();
        println!("affects: {}", affects);
        println!("fixed: {}", fixed);
        Ok(())
    }
}

/// Given an elt iterator, ensure that it has a single return value, otherwise return an error.
fn single<'a, 'b>(mut elts: Select<'a, 'b>) -> Result<ElementRef<'a>> {
    let result = if let Some(elt) = elts.next() {
        elt
    } else {
        return Err(anyhow!("Selector returned no results"));
    };
    if elts.next().is_some() {
        return Err(anyhow!("Selector returned too many results"));
    }

    Ok(result)
}

/// Get the single text from this element.  The result will be the trimmed string result.
fn text1<'a>(elt: ElementRef<'a>) -> Result<&'a str> {
    let mut iter = elt.text();
    let result = if let Some(text) = iter.next() {
        text.trim()
    } else {
        return Err(anyhow!("Selector returned node with no text"));
    };
    if let Some(_) = iter.next() {
        return Err(anyhow!("Selector returned multiple text results"));
    }

    Ok(result)
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

/// Some extensions that make Easy even easier.
trait EasyExt {
    /// Retrieve the given URL (leaving everything else unchanged), fetching the results, and
    /// returning them in a string.
    fn fetch(&mut self, url: &str) -> Result<String>;
}

impl EasyExt for Easy {
    fn fetch(&mut self, url: &str) -> Result<String> {
        self.url(url)?;
        let mut buf = Vec::new();
        {
            let mut transfer = self.transfer();
            transfer.write_function(|data| {
                buf.extend_from_slice(data);
                Ok(data.len())
            })?;
            transfer.perform()?;
        }
        Ok(String::from_utf8(buf)?)
    }
}
