//! Embeds the `turnkey-tk` skills package with its links rebased for the
//! installed layout `turnkey-tk/{SKILL.md, <workflow>/SKILL.md, references/*.md, docs/*.md}`.

// A build script reports a broken package by failing the build and talks to
// cargo through stdout directives.
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stdout)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fmt::Write,
    fs,
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn rebase_links<'a>(text: &'a str, mut rebase: impl FnMut(&'a str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find("](") {
        let after = &rest[position + 2..];
        let Some(end) = after.find(')') else { break };
        out.push_str(&rest[..position + 2]);
        let link = &after[..end];
        let (target, anchor) = link
            .split_once('#')
            .map_or((link, None), |(target, anchor)| (target, Some(anchor)));
        match rebase(target) {
            Some(rebased) => out.push_str(&rebased),
            None => out.push_str(target),
        }
        if let Some(anchor) = anchor {
            out.push('#');
            out.push_str(anchor);
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn frontmatter<'a>(path: &str, text: &'a str, key: &str) -> &'a str {
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("---"), "{path}: missing frontmatter");
    let value = lines
        .take_while(|line| *line != "---")
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .map(str::trim)
        .unwrap_or_else(|| panic!("{path}: frontmatter lacks {key}"));
    assert!(!value.is_empty(), "{path}: frontmatter {key} is empty");
    assert!(
        !value.starts_with(['>', '|', '"', '\'']),
        "{path}: frontmatter {key} must be a plain one-line value"
    );
    value
}

fn links(text: &str) -> Vec<&str> {
    let mut links = Vec::new();
    rebase_links(text, |target| {
        links.push(target);
        None
    });
    links
}

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let skills = root.join("skills");
    let docs = root.join("docs");
    println!("cargo:rerun-if-changed={}", skills.display());

    let mut bundle: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut needed_docs: BTreeSet<String> = BTreeSet::new();
    let mut sources = Vec::new();
    files_under(&skills, &mut sources);
    for source in sources {
        let relative = source.strip_prefix(&skills).unwrap();
        assert!(
            relative.extension().is_some_and(|e| e == "md"),
            "{}: the skills package holds only Markdown",
            source.display()
        );
        let path = relative.to_str().unwrap().to_owned();
        let (source_docs, installed_docs) = if relative.components().count() == 1 {
            ("../docs/", "docs/")
        } else {
            ("../../docs/", "../docs/")
        };
        let text = rebase_links(
            &fs::read_to_string(&source).unwrap_or_else(|e| panic!("{}: {e}", source.display())),
            |target| {
                let doc = target.strip_prefix(source_docs)?;
                needed_docs.insert(doc.to_owned());
                Some(format!("{installed_docs}{doc}"))
            },
        );
        let components: Vec<&str> = relative.iter().map(|c| c.to_str().unwrap()).collect();
        let kind = match components.as_slice() {
            ["SKILL.md"] | [_, "SKILL.md"] if components.first() != Some(&"references") => {
                let expected = match components.as_slice() {
                    [workflow, _] => *workflow,
                    _ => "turnkey-tk",
                };
                let name = frontmatter(&path, &text, "name");
                assert_eq!(
                    name, expected,
                    "{path}: frontmatter name must be {expected}"
                );
                let description = frontmatter(&path, &text, "description");
                format!("Kind::Skill {{ name: {name:?}, description: {description:?} }}")
            }
            ["references", reference] => {
                let stem = reference.strip_suffix(".md").unwrap();
                format!(r#"Kind::Reference {{ name: "references/{stem}" }}"#)
            }
            _ => panic!(
                "{path}: the skills package holds only SKILL.md, <workflow>/SKILL.md, and references/<name>.md"
            ),
        };
        bundle.insert(path, (kind, text));
    }

    let mut queue: Vec<String> = needed_docs.iter().cloned().collect();
    while let Some(doc) = queue.pop() {
        let source = docs.join(&doc);
        println!("cargo:rerun-if-changed={}", source.display());
        let text = rebase_links(
            &fs::read_to_string(&source).unwrap_or_else(|e| panic!("{}: {e}", source.display())),
            |target| {
                target
                    .strip_prefix("../skills/")
                    .map(|rest| format!("../{rest}"))
            },
        );
        for link in links(&text) {
            if let Some(sibling) = link.strip_prefix("./")
                && needed_docs.insert(sibling.to_owned())
            {
                queue.push(sibling.to_owned());
            }
        }
        bundle.insert(format!("docs/{doc}"), ("Kind::Doc".to_owned(), text));
    }

    for (path, (_, text)) in &bundle {
        let parent = Path::new(path).parent().unwrap();
        for link in links(text) {
            if link.is_empty() || link.starts_with("http://") || link.starts_with("https://") {
                continue;
            }
            let mut resolved = PathBuf::new();
            for component in parent.join(link).components() {
                match component {
                    Component::CurDir => {}
                    Component::ParentDir => {
                        assert!(resolved.pop(), "{path}: link {link} escapes the package");
                    }
                    other => resolved.push(other),
                }
            }
            let resolved = resolved.to_str().unwrap();
            assert!(
                bundle.contains_key(resolved),
                "{path}: link {link} resolves to {resolved}, which is not in the package"
            );
        }
    }

    let mut hasher = Sha256::new();
    for (path, (_, text)) in &bundle {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update((text.len() as u64).to_le_bytes());
        hasher.update(text.as_bytes());
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let staged = out.join("bundle");
    if staged.exists() {
        fs::remove_dir_all(&staged).unwrap();
    }
    let mut manifest = format!(
        r#"pub const DIGEST: &str = "{digest}";
pub static FILES: &[File] = &[
"#
    );
    for (path, (kind, text)) in &bundle {
        let target = staged.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, text).unwrap();
        writeln!(
            manifest,
            "    File {{ path: {path:?}, kind: {kind}, content: include_str!({:?}) }},",
            target.to_str().unwrap()
        )
        .unwrap();
    }
    writeln!(manifest, "];").unwrap();
    fs::write(out.join("bundle_manifest.rs"), manifest).unwrap();
}
