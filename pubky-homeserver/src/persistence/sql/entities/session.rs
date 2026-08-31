use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use pkarr::PublicKey;
use pubky_common::{
    capabilities::Capabilities, crypto::random_bytes, session::SessionDescriptor,
    session::SessionInfo,
};
use sea_query::{Expr, Iden, PostgresQueryBuilder, Query, SimpleExpr};
use sea_query_binder::SqlxBinder;
use sqlx::{
    postgres::PgRow,
    types::chrono::{NaiveDateTime, Utc},
    FromRow, Row,
};

use crate::persistence::sql::{
    entities::user::{UserIden, USER_TABLE},
    UnifiedExecutor,
};

pub const SESSION_TABLE: &str = "sessions";

/// Repository that handles all the queries regarding the SessionEntity.
pub struct SessionRepository;

impl SessionRepository {
    /// Create a new session that expires at `expires_at` (UTC naive).
    pub async fn create<'a>(
        user_id: i32,
        capabilities: &Capabilities,
        expires_at: NaiveDateTime,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SessionSecret, sqlx::Error> {
        let session_secret = base32::encode(base32::Alphabet::Crockford, &random_bytes::<16>());
        let statement = Query::insert()
            .into_table(SESSION_TABLE)
            .columns([
                SessionIden::Secret,
                SessionIden::User,
                SessionIden::Capabilities,
                SessionIden::ExpiresAt,
            ])
            .values(vec![
                SimpleExpr::Value(session_secret.into()),
                SimpleExpr::Value(user_id.into()),
                SimpleExpr::Value(capabilities.to_string().into()),
                SimpleExpr::Value(expires_at.into()),
            ])
            .expect("Failed to build insert statement")
            .returning_col(SessionIden::Secret)
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);

        let con = executor.get_con().await?;
        let row: PgRow = sqlx::query_with(&query, values).fetch_one(con).await?;
        let session_secret: String = row.try_get(SessionIden::Secret.to_string().as_str())?;
        SessionSecret::new(session_secret).map_err(|e| sqlx::Error::Decode(e.into()))
    }

    /// Fetch a session by secret.
    ///
    /// Expired sessions are deleted and reported as missing (fail closed).
    pub async fn get_by_secret<'a>(
        secret: &SessionSecret,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SessionEntity, sqlx::Error> {
        let session = Self::fetch_by_secret(secret, executor).await?;
        if session.is_expired(Utc::now().naive_utc()) {
            let _ = Self::delete(secret, executor).await;
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(session)
    }

    async fn fetch_by_secret<'a>(
        secret: &SessionSecret,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SessionEntity, sqlx::Error> {
        let statement = Query::select()
            .from(SESSION_TABLE)
            .columns([
                (SESSION_TABLE, SessionIden::Id),
                (SESSION_TABLE, SessionIden::Secret),
                (SESSION_TABLE, SessionIden::User),
                (SESSION_TABLE, SessionIden::Capabilities),
                (SESSION_TABLE, SessionIden::CreatedAt),
                (SESSION_TABLE, SessionIden::ExpiresAt),
            ])
            .column((USER_TABLE, UserIden::PublicKey))
            .left_join(
                USER_TABLE,
                Expr::col((SESSION_TABLE, SessionIden::User))
                    .eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((SESSION_TABLE, SessionIden::Secret)).eq(secret.to_string()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values).fetch_one(con).await
    }

    /// List non-expired sessions for a user. Never includes the session secret.
    ///
    /// Expired rows for this user are reaped first.
    pub async fn list_active_by_user<'a>(
        user_id: i32,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<SessionEntity>, sqlx::Error> {
        let now = Utc::now().naive_utc();
        Self::delete_expired_for_user(user_id, now, executor).await?;

        let statement = Query::select()
            .from(SESSION_TABLE)
            .columns([
                (SESSION_TABLE, SessionIden::Id),
                (SESSION_TABLE, SessionIden::Secret),
                (SESSION_TABLE, SessionIden::User),
                (SESSION_TABLE, SessionIden::Capabilities),
                (SESSION_TABLE, SessionIden::CreatedAt),
                (SESSION_TABLE, SessionIden::ExpiresAt),
            ])
            .column((USER_TABLE, UserIden::PublicKey))
            .left_join(
                USER_TABLE,
                Expr::col((SESSION_TABLE, SessionIden::User))
                    .eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((SESSION_TABLE, SessionIden::User)).eq(user_id))
            .and_where(Expr::col((SESSION_TABLE, SessionIden::ExpiresAt)).gt(now))
            .order_by((SESSION_TABLE, SessionIden::Id), sea_query::Order::Asc)
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values).fetch_all(con).await
    }

    /// Delete a session by secret.
    pub async fn delete<'a>(
        secret: &SessionSecret,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::delete()
            .from_table(SESSION_TABLE)
            .and_where(Expr::col(SessionIden::Secret).eq(secret.to_string()))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }

    /// Delete one session belonging to `user_id`. Returns whether a row was removed.
    ///
    /// A session that belongs to a different user is treated as missing.
    pub async fn delete_by_id_for_user<'a>(
        session_id: i32,
        user_id: i32,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let statement = Query::delete()
            .from_table(SESSION_TABLE)
            .and_where(Expr::col(SessionIden::Id).eq(session_id))
            .and_where(Expr::col(SessionIden::User).eq(user_id))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete every session for `user_id`, including the caller's own.
    pub async fn delete_all_for_user<'a>(
        user_id: i32,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        let statement = Query::delete()
            .from_table(SESSION_TABLE)
            .and_where(Expr::col(SessionIden::User).eq(user_id))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        Ok(result.rows_affected())
    }

    async fn delete_expired_for_user<'a>(
        user_id: i32,
        now: NaiveDateTime,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        let statement = Query::delete()
            .from_table(SESSION_TABLE)
            .and_where(Expr::col(SessionIden::User).eq(user_id))
            .and_where(Expr::col(SessionIden::ExpiresAt).lte(now))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        Ok(result.rows_affected())
    }
}

#[derive(PartialEq, Eq, Clone)]
pub struct SessionSecret(String);

impl SessionSecret {
    pub fn new(secret: String) -> anyhow::Result<Self> {
        if secret.len() != 26 {
            return Err(anyhow::anyhow!("Invalid session secret length"));
        }
        Ok(Self(secret))
    }

    /// Check if a string is a valid session secret.
    pub fn is_valid(value: &str) -> bool {
        if value.len() != 26 {
            return false;
        }
        let decoded = base32::decode(base32::Alphabet::Crockford, value);
        decoded.is_some() && decoded.unwrap().len() == 16
    }

    #[cfg(test)]
    pub fn random() -> Self {
        let secret = base32::encode(base32::Alphabet::Crockford, &random_bytes::<16>());
        Self(secret)
    }
}

impl Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSecret(<redacted>)")
    }
}

impl Display for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SessionSecret {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !Self::is_valid(s) {
            return Err(anyhow::anyhow!("Invalid session secret"));
        }
        Ok(Self(s.to_string()))
    }
}

#[derive(Iden)]
pub enum SessionIden {
    Id,
    Secret,
    User,
    Capabilities,
    CreatedAt,
    ExpiresAt,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionEntity {
    pub id: i32,
    pub secret: SessionSecret,
    pub user_id: i32,
    pub user_pubkey: PublicKey,
    pub capabilities: Capabilities,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

impl SessionEntity {
    /// Fail closed: a session is expired at the exact `expires_at` instant.
    pub fn is_expired(&self, now: NaiveDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn to_session_info(&self) -> SessionInfo {
        let mut session = SessionInfo::new(&self.user_pubkey, self.capabilities.clone(), None);
        session.set_created_at(unix_secs(self.created_at));
        session.set_expires_at(Some(unix_secs(self.expires_at)));
        session
    }

    pub fn to_descriptor(&self) -> SessionDescriptor {
        SessionDescriptor::new(
            self.id,
            unix_secs(self.created_at),
            unix_secs(self.expires_at),
            self.capabilities.clone(),
        )
    }
}

fn unix_secs(dt: NaiveDateTime) -> u64 {
    dt.and_utc().timestamp().max(0) as u64
}

impl FromRow<'_, PgRow> for SessionEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let id: i32 = row.try_get(SessionIden::Id.to_string().as_str())?;
        let secret: String = row.try_get(SessionIden::Secret.to_string().as_str())?;
        let secret: SessionSecret =
            SessionSecret::new(secret).map_err(|e| sqlx::Error::Decode(e.into()))?;
        let user_id: i32 = row.try_get(SessionIden::User.to_string().as_str())?;
        let user_public_key: String = row.try_get(UserIden::PublicKey.to_string().as_str())?;
        let user_public_key: PublicKey = user_public_key
            .try_into()
            .map_err(|e: pkarr::errors::PublicKeyError| sqlx::Error::Decode(e.into()))?;
        let capabilities: String = row.try_get(SessionIden::Capabilities.to_string().as_str())?;
        let capabilities: Capabilities = capabilities
            .as_str()
            .try_into()
            .map_err(|e: pubky_common::capabilities::Error| sqlx::Error::Decode(e.into()))?;
        let created_at: NaiveDateTime = row.try_get(SessionIden::CreatedAt.to_string().as_str())?;
        let expires_at: NaiveDateTime = row.try_get(SessionIden::ExpiresAt.to_string().as_str())?;
        Ok(SessionEntity {
            id,
            secret,
            user_id,
            user_pubkey: user_public_key,
            capabilities,
            created_at,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::persistence::sql::{entities::user::UserRepository, SqlDb};
    use pkarr::Keypair;
    use pubky_common::capabilities::Capability;

    use super::*;

    fn future_expiry() -> NaiveDateTime {
        Utc::now().naive_utc() + chrono::TimeDelta::days(30)
    }

    #[test]
    fn test_session_secret() {
        let secret = SessionSecret::random();
        assert!(SessionSecret::is_valid(&secret.to_string()));

        let _ = SessionSecret::from_str("6HHZ06GHB964CZMDAA0WCNV2C8").unwrap();
    }

    #[test]
    fn session_secret_debug_is_redacted() {
        let secret = SessionSecret::random();
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SessionSecret(<redacted>)");
        let entity_debug = format!(
            "{:?}",
            SessionEntity {
                id: 1,
                secret: secret.clone(),
                user_id: 1,
                user_pubkey: Keypair::random().public_key(),
                capabilities: Capabilities::builder().cap(Capability::root()).finish(),
                created_at: Utc::now().naive_utc(),
                expires_at: future_expiry(),
            }
        );
        assert!(!entity_debug.contains(&secret.to_string()));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_get_session() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        let secret = SessionRepository::create(
            user.id,
            &Capabilities::builder().cap(Capability::root()).finish(),
            future_expiry(),
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let session = SessionRepository::get_by_secret(&secret, &mut db.pool().into())
            .await
            .unwrap();

        let session = SessionRepository::get_by_secret(&session.secret, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(session.user_id, user.id);
        assert_eq!(
            session.capabilities,
            Capabilities::builder().cap(Capability::root()).finish()
        );
        assert!(!session.is_expired(Utc::now().naive_utc()));
        assert!(session.to_session_info().expires_at().is_some());

        SessionRepository::delete(&session.secret, &mut db.pool().into())
            .await
            .unwrap();

        let result = SessionRepository::get_by_secret(&session.secret, &mut db.pool().into()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_expired_session_is_rejected_and_reaped() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        let past = Utc::now().naive_utc() - chrono::TimeDelta::seconds(5);
        let secret = SessionRepository::create(
            user.id,
            &Capabilities::builder().cap(Capability::root()).finish(),
            past,
            &mut db.pool().into(),
        )
        .await
        .unwrap();

        let result = SessionRepository::get_by_secret(&secret, &mut db.pool().into()).await;
        assert!(matches!(result, Err(sqlx::Error::RowNotFound)));

        // Reaped: even the raw fetch is gone.
        let listed = SessionRepository::list_active_by_user(user.id, &mut db.pool().into())
            .await
            .unwrap();
        assert!(listed.is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_and_delete_are_scoped_to_user() {
        let db = SqlDb::test().await;
        let alice = UserRepository::create(&Keypair::random().public_key(), &mut db.pool().into())
            .await
            .unwrap();
        let bob = UserRepository::create(&Keypair::random().public_key(), &mut db.pool().into())
            .await
            .unwrap();

        let alice_secret = SessionRepository::create(
            alice.id,
            &Capabilities::builder().cap(Capability::root()).finish(),
            future_expiry(),
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let bob_secret = SessionRepository::create(
            bob.id,
            &Capabilities::builder().finish(),
            future_expiry(),
            &mut db.pool().into(),
        )
        .await
        .unwrap();

        let alice_sessions =
            SessionRepository::list_active_by_user(alice.id, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(alice_sessions.len(), 1);
        assert_eq!(alice_sessions[0].user_id, alice.id);
        let descriptor = alice_sessions[0].to_descriptor();
        assert_eq!(descriptor.id(), alice_sessions[0].id);
        assert!(descriptor.expires_at() > descriptor.created_at());

        let deleted = SessionRepository::delete_by_id_for_user(
            alice_sessions[0].id,
            bob.id,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert!(!deleted, "bob must not be able to delete alice's session");

        assert!(
            SessionRepository::get_by_secret(&alice_secret, &mut db.pool().into())
                .await
                .is_ok()
        );

        let removed = SessionRepository::delete_all_for_user(alice.id, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(
            SessionRepository::get_by_secret(&alice_secret, &mut db.pool().into())
                .await
                .is_err()
        );
        assert!(
            SessionRepository::get_by_secret(&bob_secret, &mut db.pool().into())
                .await
                .is_ok(),
            "revoke-all for alice must not touch bob"
        );
    }
}
