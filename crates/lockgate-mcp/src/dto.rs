//! Wire shapes for the MCP tools.
//!
//! `lockgate-core` returns plain data with no serde; these are the JSON-facing
//! mirrors, with `schemars::JsonSchema` so the tool macros can publish an input
//! schema and structured-output schema for each tool. Kept separate from the
//! core types so the wire format can evolve without touching the engine.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use lockgate_core::{Finding, FlowDetail, FlowRow, Identity, Lead, Note, SitemapNode};
use rmcp::schemars;
use serde::Serialize;

/// A header line. Names are already lowercased (see the core writer); original
/// casing is gone before capture stores it.
#[derive(Serialize, schemars::JsonSchema)]
pub struct HeaderDto {
    pub name: String,
    pub value: String,
}

impl From<(String, String)> for HeaderDto {
    fn from((name, value): (String, String)) -> Self {
        Self { name, value }
    }
}

/// A flow as it appears in a listing: metadata only, no body.
#[derive(Serialize, schemars::JsonSchema)]
pub struct FlowDto {
    pub id: i64,
    pub method: String,
    pub uri: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub response_len: Option<i64>,
    /// proxy | repeater | automate | import.
    pub source: String,
    /// Unix microseconds.
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub comment: Option<String>,
    pub highlight: Option<String>,
    pub error: Option<String>,
    /// What put this flow on the wire (`lead:idor-3`), for agent sends. Proxy
    /// traffic has none.
    pub tag: Option<String>,
}

impl From<FlowRow> for FlowDto {
    fn from(r: FlowRow) -> Self {
        Self {
            id: r.id,
            method: r.method,
            uri: r.uri,
            host: r.host,
            path: r.path,
            status: r.status,
            mime: r.mime,
            response_len: r.resp_len,
            source: r.source,
            started_at: r.started_at,
            ended_at: r.ended_at,
            comment: r.comment,
            highlight: r.highlight,
            error: r.error,
            tag: r.tag,
        }
    }
}

/// A bounded look at one side's body. The full bytes are always available as the
/// resource named by `resource_uri` (`flow://{id}/request|response`); this
/// carries only the requested window so a metadata read never drags a 10MB body
/// inline.
#[derive(Serialize, schemars::JsonSchema)]
pub struct BodyPreview {
    /// Total body size in bytes, independent of how much is included here.
    pub total_len: i64,
    /// inline | file | evicted | none. `evicted` means the bytes were reclaimed;
    /// `none` means there is no body on this side.
    pub storage: String,
    /// Byte offset this window starts at.
    pub offset: i64,
    /// True when bytes remain past this window.
    pub truncated: bool,
    /// The window decoded as UTF-8, when it is valid UTF-8. Mutually exclusive
    /// with `base64`.
    pub text: Option<String>,
    /// The window base64-encoded, when it is not valid UTF-8 (binary bodies).
    pub base64: Option<String>,
    /// The `Content-Encoding` the body arrived with, if any. Present whether or
    /// not it was decoded, so a base64 blob is never a mystery.
    pub content_encoding: Option<String>,
    /// Set when the bytes here were decompressed for you. A compressed body can
    /// only be decoded whole, so a windowed read of one is returned raw with
    /// this false — fetch `resource_uri` to get it decoded.
    pub decoded: bool,
    pub resource_uri: String,
}

/// One flow in full: metadata, headers, and a bounded window of each body.
#[derive(Serialize, schemars::JsonSchema)]
pub struct FlowDetailDto {
    #[serde(flatten)]
    pub flow: FlowDto,
    pub http_version: String,
    pub parent_id: Option<i64>,
    pub request_headers: Vec<HeaderDto>,
    pub response_headers: Vec<HeaderDto>,
    pub request_body: BodyPreview,
    pub response_body: BodyPreview,
}

/// The header/length parts of a detail; bodies are attached by the caller, which
/// is what actually reads the (potentially large) bytes.
pub fn detail_headers(d: &FlowDetail) -> (Vec<HeaderDto>, Vec<HeaderDto>) {
    (
        d.req_headers.iter().cloned().map(HeaderDto::from).collect(),
        d.resp_headers
            .iter()
            .cloned()
            .map(HeaderDto::from)
            .collect(),
    )
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct SitemapNodeDto {
    pub id: i64,
    pub parent_id: Option<i64>,
    /// host | dir | leaf.
    pub kind: String,
    pub host: String,
    pub path: String,
    pub name: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub flow_count: i64,
    /// observed | manual | imported.
    pub origin: String,
    pub comment: Option<String>,
    pub highlight: Option<String>,
}

impl From<SitemapNode> for SitemapNodeDto {
    fn from(n: SitemapNode) -> Self {
        Self {
            id: n.id,
            parent_id: n.parent_id,
            kind: n.kind,
            host: n.host,
            path: n.path,
            name: n.name,
            first_seen: n.first_seen,
            last_seen: n.last_seen,
            flow_count: n.flow_count,
            origin: n.origin,
            comment: n.comment,
            highlight: n.highlight,
        }
    }
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct EvidenceDto {
    pub flow_id: i64,
    pub label: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct FindingDto {
    pub id: i64,
    pub title: String,
    /// info | low | medium | high | critical.
    pub severity: String,
    /// draft | confirmed | false_positive | reported | fixed | wont_fix.
    pub status: String,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cwe: Option<String>,
    pub description_md: String,
    pub repro_md: Option<String>,
    pub impact_md: Option<String>,
    pub remediation_md: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// manual | workflow.
    pub origin: String,
    pub evidence: Vec<EvidenceDto>,
}

impl From<Finding> for FindingDto {
    fn from(f: Finding) -> Self {
        Self {
            id: f.id,
            title: f.title,
            severity: f.severity,
            status: f.status,
            cvss_vector: f.cvss_vector,
            cvss_score: f.cvss_score,
            cvss_version: f.cvss_version,
            cwe: f.cwe,
            description_md: f.description_md,
            repro_md: f.repro_md,
            impact_md: f.impact_md,
            remediation_md: f.remediation_md,
            host: f.host,
            path: f.path,
            created_at: f.created_at,
            updated_at: f.updated_at,
            origin: f.origin,
            evidence: f
                .evidence
                .into_iter()
                .map(|(flow_id, label)| EvidenceDto { flow_id, label })
                .collect(),
        }
    }
}

/// A project note: free markdown, no schema beyond a title. Distinct from a
/// flow's `comment`, which annotates one row.
#[derive(Serialize, schemars::JsonSchema)]
pub struct NoteDto {
    pub id: i64,
    pub title: String,
    pub body_md: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<Note> for NoteDto {
    fn from(n: Note) -> Self {
        Self {
            id: n.id,
            title: n.title,
            body_md: n.body_md,
            created_at: n.created_at,
            updated_at: n.updated_at,
        }
    }
}

/// A cookie as reported outward. The value is deliberately absent — a
/// transcript carrying a live session is the one leak this feature must never
/// cause — so the caller sees the name, where it applies, and how big it is.
#[derive(Serialize, schemars::JsonSchema)]
pub struct CookieDto {
    pub name: String,
    pub domain: String,
    pub path: String,
    pub value_len: i64,
}

/// A named session identity: whose cookies a replay carries when sent
/// `as_identity`, plus an optional TOTP secret (reported only as a flag).
#[derive(Serialize, schemars::JsonSchema)]
pub struct IdentityDto {
    pub id: i64,
    pub name: String,
    /// The host the session belongs to, when it belongs to one.
    pub host: Option<String>,
    pub has_totp: bool,
    /// `operator` — adopted or hand-built by the operator — or
    /// `self_registered` — the agent created the account in a run. The
    /// report's black-box claim hangs off this value.
    pub provenance: String,
    /// The mailbox address that seeded a self-registered identity
    /// (`probe+t1@gmail.com`): the cleanup registry for a run's accounts.
    pub seed_account: Option<String>,
    /// Byte-length of the custody password, when the engine holds one for
    /// re-login. The length, never the value — same rule as cookie jars.
    pub password_len: Option<i64>,
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub cookies: Vec<CookieDto>,
}

impl From<Identity> for IdentityDto {
    fn from(i: Identity) -> Self {
        Self {
            id: i.id,
            name: i.name,
            host: i.host,
            has_totp: i.totp_secret.is_some(),
            provenance: i.provenance.as_str().to_string(),
            seed_account: i.seed_account,
            password_len: i.password_len,
            note: i.note,
            created_at: i.created_at,
            updated_at: i.updated_at,
            cookies: i
                .cookies
                .into_iter()
                .map(|c| CookieDto {
                    name: c.name,
                    domain: c.domain,
                    path: c.path,
                    value_len: c.value.len() as i64,
                })
                .collect(),
        }
    }
}

/// A registered mailbox: where verification mail is read from. The type has
/// no credential field — an app password cannot leak through a read that has
/// nowhere to put it.
#[derive(Serialize, schemars::JsonSchema)]
pub struct MailboxAccountDto {
    pub id: i64,
    pub address: String,
    pub imap_host: String,
    pub imap_port: i64,
    pub imap_username: String,
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<lockgate_core::MailboxAccount> for MailboxAccountDto {
    fn from(m: lockgate_core::MailboxAccount) -> Self {
        Self {
            id: m.id,
            address: m.address,
            imap_host: m.imap_host,
            imap_port: m.imap_port as i64,
            imap_username: m.imap_username,
            note: m.note,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// One verification mail, reduced to what registration needs.
#[derive(Serialize, schemars::JsonSchema)]
pub struct VerificationMailDto {
    pub from: String,
    pub subject: String,
    pub link: Option<String>,
    pub code: Option<String>,
}

impl From<lockgate_core::VerificationMail> for VerificationMailDto {
    fn from(v: lockgate_core::VerificationMail) -> Self {
        Self {
            from: v.from,
            subject: v.subject,
            link: v.link,
            code: v.code,
        }
    }
}

/// A lead: what recon proposed, how verification left it, and the ruling.
#[derive(Serialize, schemars::JsonSchema)]
pub struct LeadDto {
    pub id: i64,
    pub kind: String,
    pub title: String,
    pub rationale_md: String,
    pub endpoint: Option<String>,
    /// The flow that inspired the lead, when there was one.
    pub flow_id: Option<i64>,
    /// proposed | verifying | verified | refuted | reported
    pub status: String,
    pub verdict: Option<String>,
    pub control: Option<String>,
    /// admissible | refuted, set by the adjudicator.
    pub ruling: Option<String>,
    pub ruling_reason: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<Lead> for LeadDto {
    fn from(l: Lead) -> Self {
        Self {
            id: l.id,
            kind: l.kind,
            title: l.title,
            rationale_md: l.rationale_md,
            endpoint: l.endpoint,
            flow_id: l.flow_id,
            status: l.status,
            verdict: l.verdict,
            control: l.control,
            ruling: l.ruling,
            ruling_reason: l.ruling_reason,
            created_at: l.created_at,
            updated_at: l.updated_at,
        }
    }
}

/// One file the materialise step wrote.
#[derive(Serialize, schemars::JsonSchema)]
pub struct MaterialisedFileDto {
    pub name: String,
    pub lines: i64,
    pub bytes: i64,
}

/// Decode a body window for JSON: UTF-8 text when it is valid UTF-8 (the common,
/// agent-friendly case), base64 otherwise. Returns `(text, base64)` with exactly
/// one side populated (both `None` only for an empty window).
pub fn encode_bytes(bytes: &[u8]) -> (Option<String>, Option<String>) {
    if bytes.is_empty() {
        return (None, None);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => (Some(text.to_string()), None),
        Err(_) => (None, Some(BASE64.encode(bytes))),
    }
}
