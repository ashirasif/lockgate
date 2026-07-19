//! Core proxy engine: capture, history, and replay.
//!
//! This crate deliberately knows nothing about how it is presented. Frontends
//! (TUI, MCP) depend on it, never the other way around.

pub mod ca;
pub mod db;
pub mod engine;
pub mod finding;
pub mod model;
pub mod proxy;
pub mod read;
pub mod registry;
pub mod scope;
pub mod server;
pub mod store;
pub mod writer;

pub use db::ProjectPaths;
pub use engine::{Engine, ResendError};
pub use finding::{Finding, NewFinding};
pub use read::{BodySlice, FlowDetail, FlowQuery, FlowRow, Side, SitemapNode};
pub use registry::{Project, Registry};
pub use scope::{Action, HostKind, Matcher, RuleSpec, Scope, ScopeRule, Target};
pub use model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary};
pub use proxy::ProxyHandler;
pub use server::serve;
