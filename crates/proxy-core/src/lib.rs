//! Core proxy engine: capture, history, and replay.
//!
//! This crate deliberately knows nothing about how it is presented. Frontends
//! (TUI, MCP) depend on it, never the other way around.

pub mod ca;
pub mod db;
pub mod encoding;
pub mod engine;
pub mod finding;
pub mod http_text;
pub mod intercept;
pub mod model;
pub mod note;
pub mod pretty;
pub mod proxy;
pub mod read;
pub mod registry;
pub mod scope;
pub mod server;
pub mod writer;

pub use db::ProjectPaths;
pub use engine::{Engine, ResendError, Resent};
pub use finding::{Finding, FindingEdit, NewFinding, WriteUp};
pub use intercept::{Held, Intercept, Pending, TicketId, Verdict};
pub use model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary};
pub use note::{NewNote, Note};
pub use proxy::ProxyHandler;
pub use read::{BodySlice, FlowDetail, FlowKind, FlowQuery, FlowRow, Side, SitemapNode};
pub use registry::{Project, Registry};
pub use scope::{Action, HostKind, Matcher, RuleSpec, Scope, ScopeRule, Target};
pub use server::serve;
