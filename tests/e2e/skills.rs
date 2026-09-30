use std::{
    collections::{BTreeMap, BTreeSet},
    env::current_exe,
    fs,
    path::Path,
    process::Command,
};

#[test]
fn verified_by_tables_name_compiled_e2e_tests() {
    let output = Command::new(current_exe().unwrap())
        .arg("--list")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let compiled: BTreeSet<String> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .map(str::to_owned)
        .collect();
    assert!(
        compiled.len() > 20,
        "test listing looks empty: {compiled:?}"
    );

    let skills = Path::new(env!("CARGO_MANIFEST_DIR")).join("skills");
    let mut claimed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in fs::read_dir(&skills).unwrap() {
        let dir = entry.unwrap().path();
        let path = dir.join("SKILL.md");
        if !dir.is_dir() || !path.exists() {
            continue;
        }
        let name = dir.file_name().unwrap().to_str().unwrap().replace('-', "_");
        let text = fs::read_to_string(&path).unwrap();
        let verified = text
            .split("\n## Verified by\n")
            .nth(1)
            .unwrap_or_else(|| panic!("{}: no verified-by section", path.display()));
        let verified = verified.split("\n## ").next().unwrap();
        for line in verified.lines().filter(|line| line.starts_with("| ")) {
            let test = line.trim_matches('|').split('|').nth(1).unwrap().trim();
            if test == "Test" {
                continue;
            }
            assert!(
                compiled.contains(test),
                "{}: `{test}` is not a compiled e2e test",
                path.display()
            );
            claimed
                .entry(name.clone())
                .or_default()
                .insert(test.to_owned());
        }
    }
    assert!(!claimed.is_empty(), "no skill claims any e2e test");

    for test in &compiled {
        let function = test.rsplit("::").next().unwrap();
        for (skill, tests) in &claimed {
            if function
                .strip_prefix(skill.as_str())
                .is_some_and(|rest| rest.starts_with('_'))
            {
                assert!(
                    tests.contains(test),
                    "{test} is named for skill {skill} but its `## Verified by` does not list it"
                );
            }
        }
    }
}
