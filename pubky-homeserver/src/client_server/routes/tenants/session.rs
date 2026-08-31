use axum::{
    extract::{Path, State},
    http::{header, HeaderValue},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::Host;
use bytes::Bytes;
use pkarr::PublicKey;
use pubky_common::{
    auth::{AuthToken, AUTH_TOKEN_MIN_LEN},
    capabilities::Capability,
    session::SessionDescriptor,
};
use tower_cookies::{Cookie, Cookies};

use crate::{
    client_server::{
        err_if_user_is_invalid::get_user_or_http_error, extractors::PubkyHost,
        layers::authz::session_secret_from_cookies, routes::auth::configure_session_cookie,
        AppState,
    },
    persistence::sql::{session::SessionRepository, user::UserEntity},
    shared::{HttpError, HttpResult},
};

pub async fn session(
    State(state): State<AppState>,
    cookies: Cookies,
    pubky: PubkyHost,
) -> HttpResult<impl IntoResponse> {
    get_user_or_http_error(pubky.public_key(), &mut state.sql_db.pool().into(), false).await?;

    if let Some(secret) = session_secret_from_cookies(&cookies, pubky.public_key()) {
        if let Ok(session) =
            SessionRepository::get_by_secret(&secret, &mut state.sql_db.pool().into()).await
        {
            if &session.user_pubkey != pubky.public_key() {
                return Err(HttpError::not_found());
            }
            let info = session.to_session_info();
            let mut resp = info.serialize().into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            resp.headers_mut()
                .insert(header::VARY, HeaderValue::from_static("cookie, pubky-host"));
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, must-revalidate"),
            );
            return Ok(resp);
        };
    }

    Err(HttpError::not_found())
}

pub async fn signout(
    State(state): State<AppState>,
    cookies: Cookies,
    Host(host): Host,
    pubky: PubkyHost,
) -> HttpResult<impl IntoResponse> {
    if let Some(secret) = session_secret_from_cookies(&cookies, pubky.public_key()) {
        SessionRepository::delete(&secret, &mut state.sql_db.pool().into()).await?;
    }

    // Always instruct the client to drop the session cookie, even if the
    // database record was already gone. This keeps repeated signout calls
    // idempotent and lets browsers wipe stale cookies immediately.
    let mut removal = Cookie::new(pubky.public_key().to_string(), String::new());
    removal.make_removal();
    configure_session_cookie(&mut removal, &host);
    cookies.add(removal);

    // Idempotent Success Response (200 OK)
    Ok(())
}

/// List the caller's active sessions.
///
/// Authorization is a fresh root-capability AuthToken, not a session cookie.
/// A stolen cookie cannot satisfy this.
pub async fn list_sessions(
    State(state): State<AppState>,
    pubky: PubkyHost,
    body: Bytes,
) -> HttpResult<Json<Vec<SessionDescriptor>>> {
    let user = require_owner_proof(&state, pubky.public_key(), &body).await?;
    let sessions =
        SessionRepository::list_active_by_user(user.id, &mut state.sql_db.pool().into()).await?;
    Ok(Json(sessions.iter().map(|s| s.to_descriptor()).collect()))
}

/// Revoke every session for the owner, including any session the caller may be using.
///
/// Safer than "except current": after this call the owner signs in again with their key.
/// A stolen cookie cannot invoke this.
pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    pubky: PubkyHost,
    body: Bytes,
) -> HttpResult<impl IntoResponse> {
    let user = require_owner_proof(&state, pubky.public_key(), &body).await?;
    SessionRepository::delete_all_for_user(user.id, &mut state.sql_db.pool().into()).await?;
    Ok(())
}

/// Revoke one session by id. The id must belong to the proven owner.
pub async fn revoke_session(
    State(state): State<AppState>,
    pubky: PubkyHost,
    Path(session_id): Path<i32>,
    body: Bytes,
) -> HttpResult<impl IntoResponse> {
    let user = require_owner_proof(&state, pubky.public_key(), &body).await?;
    let deleted = SessionRepository::delete_by_id_for_user(
        session_id,
        user.id,
        &mut state.sql_db.pool().into(),
    )
    .await?;
    if deleted {
        Ok(())
    } else {
        Err(HttpError::not_found())
    }
}

/// Verify a fresh AuthToken that proves control of the tenant key.
///
/// This cannot be satisfied by a bearer session cookie: cookies are random
/// secrets, while AuthToken verification requires an Ed25519 signature from
/// the owner key, a timestamp inside the replay window, and a one-time id.
async fn require_owner_proof(
    state: &AppState,
    tenant: &PublicKey,
    body: &[u8],
) -> HttpResult<UserEntity> {
    let token = verify_owner_token(state, body)?;
    if token.public_key() != tenant {
        return Err(HttpError::unauthorized_with_message("Invalid owner proof"));
    }
    if !token.capabilities().contains(&Capability::root()) {
        return Err(HttpError::forbidden_with_message(
            "Owner proof must include root capability",
        ));
    }
    get_user_or_http_error(token.public_key(), &mut state.sql_db.pool().into(), false).await
}

fn verify_owner_token(state: &AppState, body: &[u8]) -> HttpResult<AuthToken> {
    if body.len() < AUTH_TOKEN_MIN_LEN {
        return Err(HttpError::unauthorized_with_message("Invalid owner proof"));
    }
    match state.verifier.verify(body) {
        Ok(token) => Ok(token),
        Err(_) => Err(HttpError::unauthorized_with_message("Invalid owner proof")),
    }
}
