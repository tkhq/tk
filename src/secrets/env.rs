//! Exports a set of secrets as dotenv lines for a process's environment.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt::Write,
    mem::take,
    path::PathBuf,
};

use anyhow::Result;
use serde_json::{Map, Value, json};
use turnkey_client::generated::SecretMetadata;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    SecretOutput,
    export::{Binding, Exported, export_value, list_all, remove},
    input::{Selector, UniqueKeyValues, quorum_for},
};
use crate::{
    auth::{ResolvedAuth, state_dir},
    errors::{InvalidInput, Malformed, PendingApprovals},
    operations::OperationOutput,
};

const COMMAND: &str = "secret.env";

#[cfg_attr(test, derive(Debug))]
struct Selected {
    name: String,
    secret_id: Uuid,
}

fn select(secrets: Vec<SecretMetadata>) -> Result<BTreeMap<String, Selected>> {
    let mut selected = BTreeMap::new();
    for secret in secrets {
        let SecretMetadata {
            secret_id,
            name,
            static_properties: _,
            created_at_unix_ms: _,
        } = secret;
        let Some(name) = name else { continue };
        let var = name
            .rsplit_once('/')
            .map_or(name.as_str(), |(_, var)| var)
            .to_owned();
        let valid = var
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(InvalidInput(format!(
                "secret {name} does not end in a valid environment variable name; expected <prefix>/<VAR>"
            ))
            .into());
        }
        let slot = match selected.entry(var) {
            Entry::Occupied(occupied) => {
                let (var, Selected { name: other, .. }) = (occupied.key(), occupied.get());
                return Err(InvalidInput(format!(
                    "secrets {other} and {name} both map to variable {var}; narrow the selection"
                ))
                .into());
            }
            Entry::Vacant(vacant) => vacant,
        };
        let secret_id = Uuid::parse_str(&secret_id).map_err(|error| {
            Malformed::new(
                format!(
                    "list_secrets returned secret {name} with secretId {secret_id} that is not a UUID"
                ),
                error,
            )
        })?;
        slot.insert(Selected { name, secret_id });
    }
    Ok(selected)
}

fn line(out: &mut String, var: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0', '\'']) {
        return Err(InvalidInput(format!(
            "value of {var} contains a newline, NUL, or single quote and cannot be written as a dotenv line"
        ))
        .into());
    }
    let bare = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:+=@,-".contains(c));
    if !out.is_empty() {
        out.push('\n');
    }
    if bare {
        write!(out, "{var}={value}")?;
    } else {
        write!(out, "{var}='{value}'")?;
    }
    Ok(())
}

pub(super) async fn run(auth: ResolvedAuth, selector: Selector) -> Result<SecretOutput> {
    let quorum = quorum_for(auth.api_base_url.as_str())?;
    let state_dir = state_dir()?;
    let secrets = list_all(&auth, None, None, |secret| selector.matches(secret)).await?;
    let selected = select(secrets)?;
    if selected.is_empty() {
        return Err(InvalidInput("no secrets match the selection".into()).into());
    }

    let mut exported = Vec::new();
    let mut pending = Vec::new();
    let mut pending_names: Vec<String> = Vec::new();
    let mut env: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    let mut consumed: Vec<PathBuf> = Vec::new();
    let binding = Binding::of(&auth);
    let pending_dir = binding.pending_dir(&state_dir);
    for (var, Selected { name, secret_id }) in selected {
        let attempt = export_value(
            &pending_dir,
            &quorum,
            binding.clone(),
            &auth,
            secret_id,
            UniqueKeyValues::empty(),
        )
        .await?;
        match attempt {
            Exported::Pending(record) => {
                pending.push(json!({
                    "name": name,
                    "secretId": secret_id,
                    "var": var,
                    "activityId": record.data()["activity"]["id"],
                }));
                pending_names.push(name);
            }
            Exported::Decrypted {
                record: _,
                value,
                consumed: path,
            } => {
                exported.push(json!({"name": name, "secretId": secret_id, "var": var}));
                env.insert(var, value);
                consumed.extend(path);
            }
        }
    }
    if !pending.is_empty() {
        return Err(PendingApprovals {
            message: format!(
                "{} secret export(s) await approval: {}; approve them and run the same command again",
                pending.len(),
                pending_names.join(", ")
            ),
            pending: Value::Array(pending),
        }
        .into());
    }

    let mut plain = Zeroizing::new(String::new());
    let mut values = Map::new();
    for (var, mut value) in env {
        line(&mut plain, &var, &value)?;
        values.insert(var, Value::String(take(&mut *value)));
    }
    for path in consumed {
        remove(&path).await?;
    }
    let data = Map::from_iter([
        ("exported".to_owned(), Value::Array(exported)),
        ("pending".to_owned(), Value::Array(Vec::new())),
        ("env".to_owned(), Value::Object(values)),
    ]);
    Ok(SecretOutput {
        record: OperationOutput::result(COMMAND, Value::Object(data)),
        plain: Some(plain),
    })
}

#[cfg(test)]
mod tests {
    use turnkey_client::generated::immutable::models::v1::KeyValue;

    use super::*;

    fn secret(name: &str, properties: &[(&str, &str)]) -> SecretMetadata {
        SecretMetadata {
            secret_id: Uuid::new_v4().to_string(),
            name: Some(name.into()),
            static_properties: properties
                .iter()
                .map(|(key, value)| KeyValue {
                    key: (*key).into(),
                    value: (*value).into(),
                })
                .collect(),
            created_at_unix_ms: 0,
        }
    }

    #[test]
    fn selects_every_secret_keyed_by_var() {
        let secrets = vec![
            secret("hermes/OTHER", &[("consensus", "approval")]),
            secret("hermes/API_TOKEN", &[("consensus", "unilateral")]),
        ];
        let selected = select(secrets).unwrap();
        let vars: Vec<&str> = selected.keys().map(String::as_str).collect();
        assert_eq!(vars, ["API_TOKEN", "OTHER"]);
        assert_eq!(selected["API_TOKEN"].name, "hermes/API_TOKEN");
    }

    #[test]
    fn rejects_bad_variable_names_and_duplicates() {
        let error = select(vec![secret("hermes/not-a-var", &[])]).unwrap_err();
        let InvalidInput(message) = error
            .downcast_ref::<InvalidInput>()
            .expect("an InvalidInput error");
        assert_eq!(
            message,
            "secret hermes/not-a-var does not end in a valid environment variable name; expected <prefix>/<VAR>"
        );
        let error = select(vec![secret("a/TOKEN", &[]), secret("b/TOKEN", &[])]).unwrap_err();
        let InvalidInput(message) = error
            .downcast_ref::<InvalidInput>()
            .expect("an InvalidInput error");
        assert_eq!(
            message,
            "secrets a/TOKEN and b/TOKEN both map to variable TOKEN; narrow the selection"
        );
    }

    fn rendered(var: &str, value: &str) -> Result<String> {
        let mut out = String::new();
        line(&mut out, var, value)?;
        Ok(out)
    }

    #[test]
    fn quotes_only_when_needed_and_rejects_unwritable_values() {
        assert_eq!(
            rendered("A", "tok-1.x/y:z+=@,").unwrap(),
            "A=tok-1.x/y:z+=@,"
        );
        assert_eq!(rendered("A", "has space").unwrap(), "A='has space'");
        assert_eq!(rendered("A", "").unwrap(), "A=''");
        assert_eq!(
            rendered("A", "postgres://u:p@h/db?x=1").unwrap(),
            "A='postgres://u:p@h/db?x=1'"
        );
        let mut joined = String::new();
        line(&mut joined, "A", "1").unwrap();
        line(&mut joined, "B", "2").unwrap();
        assert_eq!(
            joined,
            r#"A=1
B=2"#
        );
        for bad in ["a\nb", "a\rb", "a'b", "a\0b"] {
            let error = rendered("A", bad).unwrap_err();
            let InvalidInput(message) = error
                .downcast_ref::<InvalidInput>()
                .expect("an InvalidInput error");
            assert_eq!(
                message,
                "value of A contains a newline, NUL, or single quote and cannot be written as a dotenv line",
                "{bad:?}"
            );
        }
    }
}
