//! Typed errors for recoverable auth failures.

/// An expected resource absent from an otherwise successful lookup response.
#[derive(Debug, thiserror::Error)]
#[error("{resource} not found: {id}")]
pub struct MissingResource {
    resource: &'static str,
    id: String,
}

impl MissingResource {
    /// Creates an error for a resource absent from a successful lookup.
    pub fn new(resource: &'static str, id: impl Into<String>) -> Self {
        Self {
            resource,
            id: id.into(),
        }
    }
}
