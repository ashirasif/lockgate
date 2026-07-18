# Data model & feature inventory

Status: **decided.** §15 records the locked answers. Schema v1 implements
projects, capture runs, flows, bodies with spill, sitemap, scope, notes,
findings, and saved filters; the remaining rows in §14 are not built yet.

Every feature below is scored:

- **have** — shipped today
- **v1** — needed for the tool to be coherent; blocks other work
- **v2** — clearly wanted, not blocking
- **later** — real feature, no near-term claim on the schema

---

## 1. One database per project

> **Decided, with one revision.** A project is a *directory*, not a single file.
> The 5MB body spill (§3.1) needs somewhere to put blobs, so the unit on disk is:
>
> ```text
> my-engagement/
>   project.db
>   blobs/ab/cdef…
> ```
>
> Export is still a copy (`cp -r`), delete is still `rm -r`. Everything below
> holds; read "file" as "directory".


Two ways to introduce projects:

**(a) Single database, `project_id` on every table.** One file, cross-project
queries possible, one connection.

**(b) A small registry database, plus one database file per project.** What
Caido and Burp both do.

**Recommendation: (b).**

The traffic tables are the problem. `flow` and `body` will reach millions of rows
and gigabytes on a single engagement; everything else in this document is
thousands of rows at most. Under (a), every index on the hot tables carries a
`project_id` prefix forever, and a project you no longer care about still costs
you page cache and `VACUUM` time.

Under (b):

- **Export/import/backup is `cp`.** A project is a file. This is worth a lot —
  under (a), exporting one project means a filtered dump and a careful
  re-import that renumbers ids.
- **Deleting a project is `rm`,** not a cascading delete across the biggest
  tables you own.
- **No `project_id` column anywhere,** so the schema in §3 survives mostly as-is.
- **Corruption is contained** to one engagement.

The cost is real but small: no cross-project queries (rarely wanted — engagements
are the isolation boundary), and open-project lifecycle to manage (switching
projects means closing one connection and opening another, which also means the
writer task is per-project and must be shut down on switch).

```sql
-- registry.db — small, global, ~/.proxy/registry.db
CREATE TABLE project (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL,
  path        TEXT NOT NULL UNIQUE,  -- absolute path to the project db
  created_at  INTEGER NOT NULL,
  last_opened INTEGER
);
```

Everything from §2 onward lives in the **project** database.

> **Consequence for what is already shipped:** the current schema is v1 with no
> real users. It is cheaper to *rewrite* that migration than to stack a v2 on it.
> I would fold these changes into the v1 string and reset, rather than preserving
> compatibility with a file format nobody has yet.

---

## 2. Naming: "session" is overloaded

Right now `session` means *one proxy run*. But in Caido/Burp, "session" more
often means a Replay session (a saved tab of requests you are iterating on), and
"session handling" means auth/cookie macros. Three different things.

Proposed vocabulary, used consistently below:

| Term | Meaning |
|---|---|
| **project** | An engagement. One database file. |
| **capture run** | One execution of the proxy. What `session` is today — suggest renaming to `capture_run`. |
| **replay collection** | A saved group of requests being iterated on (Caido's "Replay session"). |
| **auth profile** | Credentials/macros for re-authenticating. Distinct again. |

You asked for "projects that own many sessions" — that is `project → capture_run`,
which under the one-file-per-project design is just the existing `session` table
renamed, with no `project_id` needed.

---

## 3. Traffic capture — **have**

Shipped and tested. See `db.rs` / `writer.rs`.

`flow`, `body` (content-addressed, deduped), `ws_message` (table exists, unpopulated).

Known gaps carried forward: `client_addr` unpopulated, no WebSocket frame
recording, HTTP/2 compiled out.

### 3.1 Body spill — **have** / retention — **v2**

Unbounded growth is the failure mode that eventually makes the tool unusable.
Two levers, both additive:

- **Done:** bodies over `INLINE_BODY_LIMIT` (5MB) spill to
  `blobs/<sha[0..2]>/<sha>` with `body.data = NULL` and `storage = 'file'`.
  Written via temp-file-and-rename so a crash cannot leave a truncated body that
  its digest claims is complete.
- **Not done:** a retention policy — drop bodies (not flows) older than N days,
  for out-of-scope hosts, or over a total size budget. This is what `evicted`
  is reserved for.

`evicted` matters: it distinguishes "we deleted the body to save space" from
"there was no body", which are very different when reading old history.

---

## 4. Scope — **v1**

Assets like `*.linear.app`, `google.com`. Scope is a **view filter**: selecting a
scope in the proxy history shows only that asset's resources. It also gates
passive scanning and what Automate may touch.

```sql
CREATE TABLE scope (
  id      INTEGER PRIMARY KEY,
  name    TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE scope_rule (
  id         INTEGER PRIMARY KEY,
  scope_id   INTEGER NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,  -- host_glob | host_regex | cidr | path_prefix | port
  pattern    TEXT NOT NULL,
  action     TEXT NOT NULL,  -- include | exclude
  enabled    INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL
);
```

**Named scopes rather than one global list**, because you routinely want "all of
the client's assets" and "just the one app I'm testing right now" and to switch
between them. `is_active` selects; the rest stay.

**Semantics (decided): inclusion is the lever.**

- No include rules → everything is in scope.
- Any include rule → only matching assets are in scope.
- Excludes carve holes and **always** beat includes, so the result never depends
  on rule order.

**`flow` carries no `in_scope` column, by decision.** Scope is mutable; storing
it would mean rewriting millions of rows on every rule edit. It is evaluated at
query time against `flow.host`.

Storage is not the hard part — evaluation is. Rules compile to an in-memory
matcher at load and on edit. **Not yet implemented:** nothing reads `scope_rule`
today.

---

## 5. Sitemap — **v1**

A tree of hosts and paths, as in Burp's Target tab and Caido's Sitemap.

The important call: **materialise it, do not derive it.** A `SELECT DISTINCT
host, path` over millions of flows on every render is not viable, and more
importantly the tree needs to own attributes that flows cannot express:

- nodes discovered by crawling or import that have **no** flow behind them yet
- per-node notes, comments, and "add to scope" — which is exactly the operation
  you named
- aggregate counts you want without a scan

```sql
CREATE TABLE sitemap_node (
  id         INTEGER PRIMARY KEY,
  parent_id  INTEGER REFERENCES sitemap_node(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,   -- host | dir | leaf
  host       TEXT NOT NULL,
  path       TEXT NOT NULL,   -- full path from root, '' for host nodes
  name       TEXT NOT NULL,   -- this segment only, for display
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  flow_count INTEGER NOT NULL DEFAULT 0,
  origin     TEXT NOT NULL,   -- observed | manual | imported
  comment    TEXT,
  UNIQUE (host, path)
);
CREATE INDEX sitemap_parent ON sitemap_node(parent_id);
```

Maintained by the **writer task**, which already holds an open transaction per
batch — upsert the node chain and bump `last_seen`/`flow_count` alongside the
flow insert. That keeps it off the capture path and consistent with the flow it
came from.

**"Add/remove sitemap node to scope"** then becomes: generate a `scope_rule` from
the node (`host_glob` for a host node, `path_prefix` for a directory). Worth
deciding whether that link is remembered — i.e. does the rule know it came from a
node, so unchecking the node removes it? Recommend yes, via a nullable
`scope_rule.from_node_id`; otherwise the UI cannot show a checkbox state
honestly.

Open question: **does the sitemap span capture runs?** I have assumed yes — it is
project-level knowledge, accumulated. Say if you want it per-run.

---

## 6. Notes — **v1**

Markdown, per project.

```sql
CREATE TABLE note (
  id         INTEGER PRIMARY KEY,
  title      TEXT NOT NULL,
  body_md    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
```

You asked for project-level notes, which is the above and nothing more. But there
is a near-certain follow-on: notes *attached* to a flow, a sitemap node, or a
finding. Two ways:

- **(a) Polymorphic link table** — `note_link(note_id, target_kind, target_id)`.
  Flexible, supports one note referencing several things, but the FK is not
  enforceable by SQLite.
- **(b) Plain `comment` columns** on `flow` and `sitemap_node`, with `note` left
  as standalone project-level documents. **Recommended for v1** — it matches how
  these are actually used (a note is a document; a comment is a scribble on a
  row) and avoids untyped references.

Separately worth having on `flow`, and cheap: `comment TEXT` and `highlight TEXT`
(Burp's colour-tagging). These drive real triage workflow.

---

## 7. Findings — **v1**

You were unsure about fields. Proposal, aimed at "this becomes a report":

```sql
CREATE TABLE finding (
  id          INTEGER PRIMARY KEY,
  title       TEXT NOT NULL,
  severity    TEXT NOT NULL,    -- info|low|medium|high|critical
  status      TEXT NOT NULL,    -- draft|confirmed|false_positive|reported|fixed|wont_fix
  cvss_vector TEXT,             -- e.g. CVSS:3.1/AV:N/AC:L/...
  cvss_score  REAL,             -- derived from the vector; stored for sorting
  cvss_version TEXT,            -- 3.1 | 4.0
  cwe         TEXT,             -- e.g. CWE-89
  description_md TEXT NOT NULL,
  repro_md       TEXT,          -- steps to reproduce
  impact_md      TEXT,
  remediation_md TEXT,
  host        TEXT,             -- primary affected asset
  path        TEXT,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  origin      TEXT NOT NULL     -- manual | workflow  (see §11)
);

-- Evidence: the requests that demonstrate it. Many-to-many on purpose —
-- a good finding usually needs a baseline flow and an exploited flow.
CREATE TABLE finding_evidence (
  finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  flow_id    INTEGER NOT NULL REFERENCES flow(id),
  label      TEXT,              -- 'baseline' | 'payload' | free text
  PRIMARY KEY (finding_id, flow_id)
);
```

Notes on the choices:

- **`severity` stored separately from `cvss_score`,** not derived from it. In
  practice you override CVSS with judgement, and plenty of findings never get a
  vector at all. Deriving would force you to invent vectors to express "this is
  high".
- **`cvss_score` stored, not computed on read.** It is a pure function of the
  vector, but you sort and filter by it constantly, and recomputing in SQL is not
  possible.
- **Markdown for the prose fields,** consistent with notes, so a report exporter
  has one format to handle.
- **`origin`** matters once passive rules can create findings — you need to
  distinguish "the tool thinks" from "I verified".

Deferred but likely: per-finding attachments (screenshots), and a
`finding_template` table so recurring vulns get pre-written description and
remediation text. Both additive.

---

## 8. Filtering & search — **v2**

Two distinct things people conflate:

**Structured filtering** (Caido's HTTPQL, Burp's filter bar) — `host`, `status`,
`method`, `mime`, `in_scope`, `has_comment`. This is a query compiler over the
scalar columns already on `flow`, plus saved filters:

```sql
CREATE TABLE saved_filter (
  id    INTEGER PRIMARY KEY,
  name  TEXT NOT NULL,
  query TEXT NOT NULL,
  sort_order INTEGER NOT NULL
);
```

Designing the query language is a meaningful build in its own right and should be
scoped separately.

**Full-text search over bodies** — SQLite FTS5 over `body.data` and headers.
Flag this early: an FTS index over gigabytes of response bodies can **exceed the
size of the data**, and it indexes minified JS and binary blobs you will never
search. Recommend, when it lands: index only text-ish MIME types, in-scope hosts
only, and make it an opt-in per project rather than default-on.

---

## 9. Replay / Repeater — partially **have**

Sends are already recorded with `source='repeater'` and `parent_id` lineage. What
is missing is the *organisational* layer: named collections and, crucially, an
editable draft that is not yet a flow.

```sql
CREATE TABLE replay_collection (
  id   INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  sort_order INTEGER NOT NULL
);

-- The in-progress request being edited. Distinct from `flow`, which is only
-- ever a record of something actually sent.
CREATE TABLE replay_entry (
  id            INTEGER PRIMARY KEY,
  collection_id INTEGER NOT NULL REFERENCES replay_collection(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  draft_method  TEXT NOT NULL,
  draft_uri     TEXT NOT NULL,
  draft_headers BLOB NOT NULL,
  draft_body_id INTEGER REFERENCES body(id),
  last_flow_id  INTEGER REFERENCES flow(id),  -- most recent send
  sort_order    INTEGER NOT NULL
);
```

Keeping drafts out of `flow` preserves an invariant worth protecting: **every row
in `flow` really happened.** History you can trust is the whole point.

---

## 10. Automate / Intruder — **later**

Payload-driven attack runs. The schema is not hard, but the row counts are: a
cluster-bomb run is trivially 100k requests, which is comparable to everything
else in the project put together.

```sql
CREATE TABLE attack (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  strategy   TEXT NOT NULL,   -- sniper | pitchfork | clusterbomb
  base_flow_id INTEGER REFERENCES flow(id),
  template   BLOB NOT NULL,   -- request with §markers§
  status     TEXT NOT NULL,   -- pending|running|paused|done|failed
  created_at INTEGER NOT NULL
);

CREATE TABLE attack_result (
  id        INTEGER PRIMARY KEY,
  attack_id INTEGER NOT NULL REFERENCES attack(id) ON DELETE CASCADE,
  flow_id   INTEGER REFERENCES flow(id),
  payloads  TEXT NOT NULL,    -- JSON array, one per marker
  status    INTEGER,
  resp_len  INTEGER,
  elapsed_us INTEGER
);
```

Decision to make when it lands: **do attack requests land in `flow` at all?**
Putting 100k intruder requests into the main history drowns the proxy history you
actually want to read. Options: a `source='automate'` filtered out by default, or
keep bodies only for results you flag. Lean toward the former plus aggressive
body eviction.

Wordlists are a supporting table (`wordlist(id, name, path, line_count)`); keep
the lines on disk, not in SQLite.

---

## 11. Passive rules / workflows — **later**

The mechanism by which findings get created automatically. Caido's Workflows,
Burp's Scanner. Data model is small (`rule(id, name, kind, definition, enabled)`)
— the engine is the work. Relevant now only because `finding.origin` and
`finding_template` anticipate it.

---

## 12. Match & replace, interception — **v2**

```sql
CREATE TABLE rewrite_rule (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL,
  phase       TEXT NOT NULL,   -- request | response
  part        TEXT NOT NULL,   -- header | body | uri | method | status
  match_kind  TEXT NOT NULL,   -- literal | regex
  pattern     TEXT NOT NULL,
  replacement TEXT NOT NULL,
  scope_id    INTEGER REFERENCES scope(id),  -- NULL = everywhere
  enabled     INTEGER NOT NULL DEFAULT 1,
  sort_order  INTEGER NOT NULL
);
```

**Interception** (pause a request, edit it, forward it) needs *no* persistence —
the pending queue is inherently in-memory and meaningless after a restart. Only
the rules governing what gets intercepted persist, and those fit the table above.

---

## 13. Environments & auth — **later**

Variables reused across requests (`{{token}}`), plus stored credentials.

```sql
CREATE TABLE environment (id INTEGER PRIMARY KEY, name TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 0);
CREATE TABLE env_var (
  env_id INTEGER NOT NULL REFERENCES environment(id) ON DELETE CASCADE,
  key    TEXT NOT NULL,
  value  TEXT NOT NULL,
  secret INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (env_id, key)
);
```

`secret` is a **display** flag (mask in the UI), not encryption. Worth being
explicit: a project file will contain live session tokens in `flow` bodies
regardless, so treating the file itself as sensitive is the honest posture rather
than pretending selective encryption helps.

---

## 14. Feature summary

| Area | Feature | Status |
|---|---|---|
| Capture | HTTP flows, bodies, dedup | have |
| Capture | WebSocket frames | v2 |
| Capture | HTTP/2 | later (feature-gated off) |
| Capture | Body spill (5MB cap) | have |
| Organise | Projects (one dir each) + registry | have |
| Organise | Capture runs | have |
| Organise | Notes (markdown) | schema only |
| Organise | Flow comments + highlights | schema only |
| Organise | Findings + evidence | schema only |
| Navigate | Scope (named, include/exclude) | schema only |
| Navigate | Sitemap (materialised tree) | have |
| Navigate | Sitemap ↔ scope linkage | schema only |
| Navigate | Structured filter language | schema only |
| Navigate | Full-text body search | dropped for now |
| Act | Replay collections + drafts | v2 |
| Act | Match & replace | v2 |
| Act | Interception | v2 (no schema) |
| Act | Automate / Intruder | later |
| Analyse | Passive rules → findings | later |
| Ops | Environments & variables | later |
| Ops | Export / import | free under §1(b) |

---

## 15. Decisions

| # | Question | Decision |
|---|---|---|
| 1 | Storage layout | Per-project database, plus a registry. Project is a **directory** (§1). |
| 2 | Migration | Rewrite v1 rather than stacking a v2; no users to preserve. |
| 3 | Body cap | 5MB inline; larger spill to `blobs/`. |
| 4 | Scope on `flow` | **Never stored.** Evaluated at query time as a view filter. |
| 5 | Scope semantics | **Inclusion is the lever**: no includes = everything; adding one narrows to matching assets. Excludes carve holes and always win, so order never matters. |
| 6 | Sitemap lifetime | Project-wide, spanning capture runs. |
| 7 | Notes vs comments | `note` = project-level markdown documents. `comment` + `highlight` columns on `flow` and `sitemap_node` for row annotation. |
| 8 | Findings | §7 fields as proposed. |
| 9 | Filtering | Structured filtering only for now; no full-text search. |
| 10 | Automate results | Land in `flow`, filtered out of the default view via `source`. |

### Still open

- **CVSS version**: the column exists but nothing enforces 3.1 vs 4.0 yet.
- **Scope rule matching** is specified but not implemented — no matcher compiles
  `scope_rule` rows into a predicate yet.
- **Ctrl-C** does not flush; only a clean exit from the TUI does.
