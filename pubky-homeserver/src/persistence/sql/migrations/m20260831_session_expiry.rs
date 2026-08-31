use async_trait::async_trait;
use sea_query::{ColumnDef, PostgresQueryBuilder, Table};
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

const TABLE: &str = "sessions";
const INDEX_EXPIRES_AT: &str = "idx_session_expires_at";
const INDEX_USER: &str = "idx_session_user";

pub struct M20260831SessionExpiryMigration;

#[async_trait]
impl MigrationTrait for M20260831SessionExpiryMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        // Nullable first so existing rows can be backfilled before NOT NULL is applied.
        let statement = Table::alter()
            .table(TABLE)
            .add_column(ColumnDef::new(SessionIden::ExpiresAt).timestamp().null())
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Existing sessions were issued a 365-day cookie. Preserve that lifetime
        // so upgrading does not silently invalidate active sessions.
        let result = sqlx::query(
            r#"UPDATE sessions
               SET expires_at = created_at + INTERVAL '365 days'
               WHERE expires_at IS NULL"#,
        )
        .execute(&mut **tx)
        .await?;
        tracing::info!(
            "Backfilled expires_at on {} existing sessions (created_at + 365 days)",
            result.rows_affected()
        );

        sqlx::query("ALTER TABLE sessions ALTER COLUMN expires_at SET NOT NULL")
            .execute(&mut **tx)
            .await?;

        let expires_index = sea_query::Index::create()
            .name(INDEX_EXPIRES_AT)
            .table(TABLE)
            .col(SessionIden::ExpiresAt)
            .index_type(sea_query::IndexType::BTree)
            .to_owned();
        let query = expires_index.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        let user_index = sea_query::Index::create()
            .name(INDEX_USER)
            .table(TABLE)
            .col(SessionIden::User)
            .index_type(sea_query::IndexType::BTree)
            .to_owned();
        let query = user_index.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        Ok(())
    }

    fn name(&self) -> &str {
        "m20260831_session_expiry"
    }
}

#[derive(sea_query::Iden)]
enum SessionIden {
    ExpiresAt,
    User,
}

#[cfg(test)]
mod tests {
    use pkarr::Keypair;
    use pubky_common::capabilities::{Capabilities, Capability, CapsBuilder};
    use sea_query::{Iden, PostgresQueryBuilder, Query, SimpleExpr};
    use sea_query_binder::SqlxBinder;
    use sqlx::{postgres::PgRow, FromRow, Row};

    use crate::{
        data_directory::LEGACY_SESSION_TTL_SECS,
        persistence::{
            lmdb::tables::users::USERS_TABLE,
            sql::{
                entities::user::UserIden,
                migrations::{M20250806CreateUserMigration, M20250813CreateSessionMigration},
                migrator::Migrator,
                SqlDb,
            },
        },
    };

    use super::*;

    #[derive(Iden)]
    enum SessionCols {
        Id,
        Secret,
        User,
        Capabilities,
        CreatedAt,
        ExpiresAt,
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct SessionRow {
        pub secret: String,
        pub user: i32,
        pub created_at: sqlx::types::chrono::NaiveDateTime,
        pub expires_at: sqlx::types::chrono::NaiveDateTime,
    }

    impl FromRow<'_, PgRow> for SessionRow {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(SessionRow {
                secret: row.try_get(SessionCols::Secret.to_string().as_str())?,
                user: row.try_get(SessionCols::User.to_string().as_str())?,
                created_at: row.try_get(SessionCols::CreatedAt.to_string().as_str())?,
                expires_at: row.try_get(SessionCols::ExpiresAt.to_string().as_str())?,
            })
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_backfills_legacy_ttl_and_sets_not_null() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250813CreateSessionMigration),
            ])
            .await
            .expect("Should run successfully");

        let pubkey = Keypair::random().public_key();
        let secret = "6HHZ06GHB964CZMDAA0WCNV2C8";
        let statement = Query::insert()
            .into_table(USERS_TABLE)
            .columns([UserIden::PublicKey])
            .values(vec![SimpleExpr::Value(pubkey.to_string().into())])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        let caps = CapsBuilder::new().cap(Capability::root()).finish();
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([
                SessionCols::Secret,
                SessionCols::User,
                SessionCols::Capabilities,
            ])
            .values(vec![
                SimpleExpr::Value(secret.into()),
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value(caps.to_string().into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        migrator
            .run_migrations(vec![Box::new(M20260831SessionExpiryMigration)])
            .await
            .expect("expiry migration should apply");

        let statement = Query::select()
            .from(TABLE)
            .columns([
                SessionCols::Id,
                SessionCols::Secret,
                SessionCols::User,
                SessionCols::Capabilities,
                SessionCols::CreatedAt,
                SessionCols::ExpiresAt,
            ])
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);
        let session: SessionRow = sqlx::query_as(query.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();

        assert_eq!(session.secret, secret);
        assert_eq!(session.user, 1);
        let delta = session.expires_at - session.created_at;
        assert_eq!(
            delta.num_seconds(),
            LEGACY_SESSION_TTL_SECS as i64,
            "existing sessions keep the 365-day lifetime they were issued"
        );

        let expires_index = sqlx::query(
            "SELECT indexname FROM pg_indexes WHERE tablename = 'sessions' AND indexname = $1",
        )
        .bind(INDEX_EXPIRES_AT)
        .fetch_optional(db.pool())
        .await
        .unwrap();
        assert!(expires_index.is_some());

        let user_index = sqlx::query(
            "SELECT indexname FROM pg_indexes WHERE tablename = 'sessions' AND indexname = $1",
        )
        .bind(INDEX_USER)
        .fetch_optional(db.pool())
        .await
        .unwrap();
        assert!(user_index.is_some());

        // Column is NOT NULL: inserting without expires_at must fail.
        let insert_without = sqlx::query(
            "INSERT INTO sessions (secret, \"user\", capabilities) VALUES ($1, $2, $3)",
        )
        .bind("AAAAAAAAAAAAAAAAAAAAAAAAAA")
        .bind(1)
        .bind(Capabilities::builder().finish().to_string())
        .execute(db.pool())
        .await;
        assert!(insert_without.is_err());
    }
}
