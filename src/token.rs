//! Gets access tokens for other services with the OAuth client credentials grant, authenticating as the profile's user with its key.

use anyhow::{Context, Result};
use clap::Args;
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    auth::{ApiBaseUrl, ResolvedAuth, build_turnkey_client, http_client, whoami},
    errors::{Malformed, UnexpectedHttpStatus},
    jwt::{client_assertion, dpop_proof, signing_key},
    operations::OperationOutput,
};

const DEFAULT_IDENTITY_ORIGIN: &str = "https://id.turnkey.com";
const GRANT_CLIENT_CREDENTIALS: &str = "client_credentials";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const DPOP_NONCE_HEADER: &str = "DPoP-Nonce";

#[derive(Debug, Args)]
pub struct TokenArgs {
    /// Service the token is for, such as an MCP server's URL.
    #[arg(long, value_name = "URL")]
    resource: Url,
    /// Scopes to ask for, space separated.
    #[arg(long)]
    scope: Option<String>,
    /// Parent organization whose issuer mints the token.
    ///
    /// The profile's user must be in one of its sub-organizations and registered with the identity service as a client.
    #[arg(long, value_name = "ORG_UUID")]
    parent_organization_id: Uuid,
    /// Identity service origin.
    #[arg(long, env = "TK_IDENTITY_ORIGIN", default_value = DEFAULT_IDENTITY_ORIGIN, value_parser = parse_origin)]
    identity_origin: ApiBaseUrl,
    /// Ask for a bearer token instead of one bound to the profile's key.
    ///
    /// Anyone holding a bearer token can use it until it expires.
    #[arg(long)]
    bearer: bool,
}

fn parse_origin(raw: &str) -> Result<ApiBaseUrl> {
    ApiBaseUrl::try_from(raw.to_owned())
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

impl TokenArgs {
    pub(crate) async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let Self {
            resource,
            scope,
            parent_organization_id,
            identity_origin,
            bearer,
        } = self;
        let ResolvedAuth {
            org_id,
            api_base_url,
            stamper,
            source: _,
            http: _,
        } = auth;
        let key = signing_key(&stamper)?;
        let user_id = whoami(&build_turnkey_client(stamper, &api_base_url)?, org_id)
            .await
            .context("look up the profile's user")?
            .user_id;
        let client_id = format!("urn:turnkey:user:{user_id}");
        let issuer = format!(
            "{}/t/{parent_organization_id}",
            identity_origin.as_str().trim_end_matches('/')
        );
        let token_url = format!("{issuer}/token");
        let assertion = client_assertion(&key, &client_id, &issuer)?;

        let mut form = vec![
            ("grant_type", GRANT_CLIENT_CREDENTIALS),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.as_str()),
            ("resource", resource.as_str()),
        ];
        if let Some(scope) = &scope {
            form.push(("scope", scope));
        }

        let http = http_client()?;
        let mut nonce: Option<String> = None;
        let response = loop {
            let mut request = http.post(&token_url).form(&form);
            if !bearer {
                request = request.header("DPoP", dpop_proof(&key, &token_url, nonce.as_deref())?);
            }
            let response = request
                .send()
                .await
                .context("ask the identity service for a token")?;
            let status = response.status();
            let offered = response
                .headers()
                .get(DPOP_NONCE_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = response.text().await.context("read the token response")?;
            // RFC 9449 Section 8: retry once with the nonce the server names.
            // The identity service consumes the client assertion only after
            // the proof passes, so the retry may reuse it.
            if status == StatusCode::BAD_REQUEST
                && !bearer
                && nonce.is_none()
                && let Some(offered) = offered
                && serde_json::from_str::<OAuthError>(&body)
                    .is_ok_and(|OAuthError { error }| error == "use_dpop_nonce")
            {
                nonce = Some(offered);
                continue;
            }
            if !status.is_success() {
                return Err(UnexpectedHttpStatus {
                    status: status.as_u16(),
                    body,
                }
                .into());
            }
            break body;
        };
        let TokenResponse {
            access_token,
            token_type,
            expires_in,
            scope,
        } = serde_json::from_str(&response)
            .map_err(|error| Malformed::new("malformed token response", error))?;

        let record = json!({
            "resource": resource.as_str(),
            "clientId": client_id,
            "tokenType": token_type,
            "accessToken": access_token,
            "expiresIn": expires_in,
            "scope": scope,
        });
        Ok(OperationOutput::result("token", record).with_human(access_token))
    }
}
