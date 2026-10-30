//! The global project registry.
//!
//! Small, and the only database that is not per-project: it exists so the UI can
//! answer "what projects do I have?" without walking the filesystem. It holds no
//! engagement data — deleting it loses only the list, not any project.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use crate::db::{ProjectPaths, io_err, migrate};

const SCHEMA_VERSION: i64 = 2;

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
    // v2 — programs: a bug-bounty vendor (or engagement) that spans several
    // targets, where each target is a project. The program carries what the
    // vendor publishes as policy; the projects carry the traffic. An
    // orchestrator enumerates its targets from here; a lone project needs
    // none of it.
    r#"
    CREATE TABLE program (
      id         INTEGER PRIMARY KEY,
      name       TEXT NOT NULL UNIQUE,
      -- The program's published policy as markdown: scope notes, forbidden
      -- techniques, rate expectations, the out-of-bounds list. Rendered into
      -- agent prompts; the enforced floor lives per project in `policy`.
      policy_md  TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE program_target (
      program_id INTEGER NOT NULL REFERENCES program(id) ON DELETE CASCADE,
      project_id INTEGER NOT NULL REFERENCES project(id),
      PRIMARY KEY (program_id, project_id)
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

    // --- programs ---
    //
    // A program is a bug-bounty vendor spanning several targets: one row here,
    // targets as projects underneath. The registry is the one database that is
    // not per-project, so this is the only place a multi-target view can live.

    /// Create a program. Names are unique — the orchestrator addresses
    /// programs by name.
    pub fn create_program(
        &self,
        name: &str,
        policy_md: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO program (name, policy_md, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![name, policy_md, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn programs(&self) -> rusqlite::Result<Vec<Program>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, policy_md, created_at FROM program ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(Program {
                id: r.get(0)?,
                name: r.get(1)?,
                policy_md: r.get(2)?,
                created_at: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn program(&self, id: i64) -> rusqlite::Result<Option<Program>> {
        self.conn
            .query_row(
                "SELECT id, name, policy_md, created_at FROM program WHERE id = ?1",
                [id],
                |r| {
                    Ok(Program {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        policy_md: r.get(2)?,
                        created_at: r.get(3)?,
                    })
                },
            )
            .optional()
    }

    /// The projects filed under a program, oldest first.
    pub fn program_targets(&self, program_id: i64) -> rusqlite::Result<Vec<Project>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.name, p.path, p.created_at, p.last_opened
               FROM project p
               JOIN program_target t ON t.project_id = p.id
              WHERE t.program_id = ?1
              ORDER BY p.id",
        )?;
        let rows = stmt.query_map([program_id], row_to_project)?;
        rows.collect()
    }

    pub fn add_program_target(&self, program_id: i64, project_id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO program_target (program_id, project_id) VALUES (?1, ?2)",
            rusqlite::params![program_id, project_id],
        )?;
        Ok(())
    }

    pub fn remove_program_target(&self, program_id: i64, project_id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM program_target WHERE program_id = ?1 AND project_id = ?2",
            rusqlite::params![program_id, project_id],
        )?;
        Ok(())
    }

    /// Replace the program's policy markdown. `None` clears it.
    pub fn set_program_policy(
        &self,
        program_id: i64,
        policy_md: Option<&str>,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE program SET policy_md = ?2 WHERE id = ?1",
            rusqlite::params![program_id, policy_md],
        )
    }

    /// Delete a program. The projects and their traffic stay.
    pub fn delete_program(&self, id: i64) -> rusqlite::Result<usize> {
        self.conn.execute("DELETE FROM program WHERE id = ?1", [id])
    }
}

/// A bug-bounty program spanning several target projects.
#[derive(Clone, Debug)]
pub struct Program {
    pub id: i64,
    pub name: String,
    /// The vendor's published policy, as markdown. Context for prompts; the
    /// enforced floor is each project's own `policy` tables.
    pub policy_md: Option<String>,
    pub created_at: i64,
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
