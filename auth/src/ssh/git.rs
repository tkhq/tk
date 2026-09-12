use anyhow::{Result, anyhow};
use std::path::PathBuf;

/// Parsed `ssh-keygen -Y sign` style invocation data for Git signing.
#[derive(Debug)]
pub struct GitSignInvocation {
    /// Requested SSH signing namespace.
    pub namespace: String,
    /// Path to the OpenSSH public key file passed by Git.
    pub public_key_path: PathBuf,
    /// Path to the payload file Git wants signed.
    pub payload_path: PathBuf,
}

impl GitSignInvocation {
    /// Parses the `ssh-keygen -Y sign` style arguments Git passes to an SSH signer.
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut namespace = None;
        let mut public_key_path = None;
        let mut payload_path = None;
        let mut iter = args.iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-Y" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| anyhow!("missing value after -Y"))?;
                    if value != "sign" {
                        return Err(anyhow!("unsupported ssh signer operation: {value}"));
                    }
                }
                "-n" => {
                    namespace = Some(
                        iter.next()
                            .ok_or_else(|| anyhow!("missing value after -n"))?
                            .to_string(),
                    );
                }
                "-f" => {
                    public_key_path = Some(PathBuf::from(
                        iter.next()
                            .ok_or_else(|| anyhow!("missing value after -f"))?,
                    ));
                }
                // Git passes -U when `user.signingkey` is a literal `key::` public key:
                // it tells ssh-keygen to sign with the agent. Turnkey holds the key, so
                // the flag changes nothing here and is accepted.
                "-U" => {}
                value if value.starts_with('-') => {
                    return Err(anyhow!("unsupported ssh signer argument: {value}"));
                }
                value => {
                    payload_path = Some(PathBuf::from(value));
                }
            }
        }

        let namespace = namespace.ok_or_else(|| anyhow!("missing required -n <namespace>"))?;
        if namespace != "git" {
            return Err(anyhow!("unsupported ssh signing namespace: {namespace}"));
        }

        Ok(Self {
            namespace,
            public_key_path: public_key_path
                .ok_or_else(|| anyhow!("missing required -f <public-key-file>"))?,
            payload_path: payload_path.ok_or_else(|| anyhow!("missing payload file path"))?,
        })
    }

    /// Returns the output path where the detached signature should be written.
    pub fn signature_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.sig", self.payload_path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::GitSignInvocation;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_the_arguments_git_passes_for_a_key_file() {
        let parsed = GitSignInvocation::parse(&args(&[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            "/tmp/k.pub",
            "/tmp/payload",
        ]))
        .unwrap();
        assert_eq!(parsed.namespace, "git");
        assert_eq!(parsed.public_key_path.to_str(), Some("/tmp/k.pub"));
        assert_eq!(parsed.payload_path.to_str(), Some("/tmp/payload"));
        assert_eq!(parsed.signature_path().to_str(), Some("/tmp/payload.sig"));
    }

    #[test]
    fn accepts_the_agent_flag_git_passes_for_a_literal_key() {
        // `user.signingkey = key::ssh-ed25519 ...` makes git write the key to a
        // temp file and add -U (git 2.34 and later).
        let parsed = GitSignInvocation::parse(&args(&[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            "/tmp/.git_signing_key_tmp",
            "-U",
            "/tmp/payload",
        ]))
        .unwrap();
        assert_eq!(parsed.payload_path.to_str(), Some("/tmp/payload"));
    }

    #[test]
    fn rejects_an_unknown_flag() {
        let err =
            GitSignInvocation::parse(&args(&["-Y", "sign", "-n", "git", "-f", "k", "-Z", "p"]))
                .unwrap_err();
        assert!(err.to_string().contains("-Z"));
    }
}
