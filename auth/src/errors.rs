//! Typed errors shared with the CLI's error classification.

/// A resource lookup that returned successfully but found nothing, such as an
/// API `Ok` response whose optional payload is `None`. The CLI classifies this
/// as `not_found`, alongside HTTP 404s.
#[derive(Debug, thiserror::Error)]
#[error("{resource} not found: {id}")]
pub struct MissingResource {
    resource: &'static str,
    id: String,
}

impl MissingResource {
    /// Builds the typed error for a `resource` that resolved to nothing.
    pub fn new(resource: &'static str, id: impl Into<String>) -> Self {
        Self {
            resource,
            id: id.into(),
        }
    }
}
