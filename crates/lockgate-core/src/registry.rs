//! The global project registry.
//!
//! Small, and the only database that is not per-project: it exists so the UI can
//! answer "what projects do I have?" without walking the filesystem. It holds no
//! engagement data — deleting it loses only the list, not any project.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::db::{ProjectPaths, io_err, migrate};

const SCHEMA_VERSION: i64 = 1;

const MIGRATIONS: &[&str] = &[
    // v1
    r#"
    CREATE TABLE project (
      id          INTEGER PRIMARY KEY,
      name        TEXT NOT NULL,
      -- Absolute path to the project directory (see db::ProjectPaths).
      path        TEXT NOT NULL UNIQUE,
      created_at  INTEGER NOT NULL,
      last_opened INTEGER
    );
    "#,
];

#[derive(Clone, Debug)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub path: PathBuf,
    pub created_at: i64,
    pub last_opened: Option<i64>,
}

impl Project {
    pub fn paths(&self) -> ProjectPaths {
        ProjectPaths::new(self.path.clone())
    }
}

pub struct Registry {
    conn: Connection,
}

impl Registry {
    /// Open (creating if needed) the registry at `path`.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&conn, MIGRATIONS, SCHEMA_VERSION)?;
        Ok(Self { conn })
    }

    /// Register a project directory, creating it on disk if absent.
    ///
    /// The directory is the source of truth; the registry row is an index onto
    /// it. Re-registering an existing path updates the name rather than failing,
    /// so a project copied in by hand can simply be re-added.
    pub fn create(&self, name: &str, root: &Path, now: i64) -> rusqlite::Result<Project> {
        let paths = ProjectPaths::new(root);
        // Creating the schema here means a registered project is always openable.
        crate::db::open_project(&paths)?;

        let path = root.to_string_lossy().to_string();
        self.conn.execute(
            "INSERT INTO project (name, path, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(path) DO UPDATE SET name = excluded.name",
            rusqlite::params![name, path, now],
        )?;

        self.by_path(root)?
            .ok_or_else(|| rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn list(&self) -> rusqlite::Result<Vec<Project>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, path, created_at, last_opened FROM project
             ORDER BY COALESCE(last_opened, created_at) DESC",
        )?;
        let rows = stmt.query_map([], row_to_project)?;
        rows.collect()
    }

    pub fn by_path(&self, root: &Path) -> rusqlite::Result<Option<Project>> {
        let path = root.to_string_lossy().to_string();
        let mut stmt = self.conn.prepare(
            "SELECT id, name, path, created_at, last_opened FROM project WHERE path = ?1",
        )?;
        let mut rows = stmt.query_map([path], row_to_project)?;
        rows.next().transpose()
    }

    /// Record that a project was opened, which is what orders `list`.
    pub fn touch(&self, id: i64, now: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE project SET last_opened = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        )?;
        Ok(())
    }

    /// Forget a project. Deliberately does **not** delete its directory: losing
    /// an engagement's traffic to a misclick is not recoverable, and the caller
    /// can always `rm -r` deliberately.
    pub fn forget(&self, id: i64) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM project WHERE id = ?1", [id])?;
        Ok(())
    }
}

fn row_to_project(row: &rusqlite::Row) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        path: PathBuf::from(row.get::<_, String>(2)?),
        created_at: row.get(3)?,
        last_opened: row.get(4)?,
    })
}
