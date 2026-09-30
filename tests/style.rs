//! Source layout rules that rustfmt cannot express.
use std::{fs, path::Path};

fn is_use(line: &str) -> bool {
    let line = line.trim_start();
    let line = line.strip_prefix("pub").map_or(line, |rest| {
        rest.strip_prefix("(")
            .and_then(|rest| rest.split_once(')'))
            .map_or(rest, |(_, rest)| rest)
            .trim_start()
    });
    line.starts_with("use ")
}

#[test]
fn a_blank_line_separates_imports_from_the_code_after_them() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("build.rs")];
    let mut dirs = vec![root.join("src"), root.join("tests")];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }

    let mut violations = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut index = 0;
        while index < lines.len() {
            if !is_use(lines[index]) {
                index += 1;
                continue;
            }
            while !lines[index].trim_end().ends_with(';') {
                index += 1;
            }
            let next = lines[index + 1..]
                .iter()
                .find(|line| !line.trim_start().starts_with("#["));
            if lines
                .get(index + 1)
                .is_some_and(|line| !line.trim().is_empty())
                && !next.is_some_and(|line| is_use(line))
            {
                violations.push(format!(
                    "{}:{}",
                    file.strip_prefix(root).unwrap().display(),
                    index + 1
                ));
            }
            index += 1;
        }
    }
    assert!(
        violations.is_empty(),
        "add a blank line after the last import at: {violations:#?}"
    );
}
