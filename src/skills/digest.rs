use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

pub(super) fn of<P: AsRef<str>, C: AsRef<[u8]>>(files: &BTreeMap<P, C>) -> String {
    let mut hasher = Sha256::new();
    for (path, content) in files {
        let content = content.as_ref();
        hasher.update(path.as_ref().as_bytes());
        hasher.update([0]);
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(content);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
