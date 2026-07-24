//! Notes: the project-level markdown documents an engagement accumulates.
//!
//! A note is a document, not an annotation. Scribbles that belong to one row go
//! in the `comment` columns on `flow` / `sitemap_node`; a note is the page you
//! keep open beside the capture — how the auth flow works, what to try next,
//! the half-written write-up a finding will eventually become.
//!
//! Like `finding.rs` this is authored rather than captured, so the row shape and
//! the SQL live here and the write still runs inside the one writer task's
//! transaction (see `writer.rs`).

use rusqlite::{Connection, OptionalExtension, params};

/// What a caller supplies to start a note. `id` and the timestamps are stamped
/// on insert, so this is only what the author actually knows.
#[derive(Clone, Debug, Default)]
pub struct NewNote {
    pub title: String,
    pub body_md: String,
}

/// A stored note, read back for the list and the detail pane.
#[derive(Clone, Debug)]
pub struct Note {
    pub id: i64,
    pub title: String,
    pub body_md: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Insert a note, returning its new id.
///
/// Runs inside the writer's transaction (`conn` is really a `&Transaction`).
pub fn insert(conn: &Connection, n: &NewNote, now: i64) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO note (title, body_md, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?3)",
        params![n.title, n.body_md, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Every note, newest first. Notes number in the tens like findings, so this is
/// unpaginated on purpose — the body comes back with the row because a list of
/// note titles with no text is not much of a list.
pub fn list(conn: &Connection) -> rusqlite::Result<Vec<Note>> {
    let mut stmt = conn
        .prepare("SELECT id, title, body_md, created_at, updated_at FROM note ORDER BY id DESC")?;
    stmt.query_map([], row_to_note)?.collect()
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<Note>> {
    conn.query_row(
        "SELECT id, title, body_md, created_at, updated_at FROM note WHERE id = ?1",
        [id],
        row_to_note,
    )
    .optional()
}

/// Edit a note in place. `None` leaves that column alone, so retitling does not
/// blank the body and saving the body does not touch the title.
///
/// Returns rows changed, which is 0 for an unknown id.
pub fn update(
    conn: &Connection,
    id: i64,
    title: Option<&str>,
    body_md: Option<&str>,
    now: i64,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE note
            SET title = COALESCE(?2, title),
                body_md = COALESCE(?3, body_md),
                updated_at = ?4
          WHERE id = ?1",
        params![id, title, body_md, now],
    )
}

pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM note WHERE id = ?1", [id])
}

fn row_to_note(r: &rusqlite::Row) -> rusqlite::Result<Note> {
    Ok(Note {
        id: r.get(0)?,
        title: r.get(1)?,
        body_md: r.get(2)?,
        created_at: r.get(3)?,
        updated_at: r.get(4)?,
    })
}
