//! Core proxy engine: capture, history, and replay.
//!
//! This crate deliberately knows nothing about how it is presented. Frontends
//! (TUI, MCP) depend on it, never the other way around.

pub mod browser;
pub mod ca;
pub mod chain;
pub mod db;
pub mod encoding;
pub mod engine;
pub mod finding;
pub mod http_text;
pub mod identity;
pub mod intercept;
pub mod lead;
pub mod materialise;
pub mod model;
pub mod note;
pub mod notify;
pub mod policy;
pub mod pretty;
pub mod proxy;
pub mod read;
pub mod registry;
pub mod report;
pub mod scanner;
pub mod scope;
pub mod server;
pub mod writer;

pub use chain::{
    ChainError, ChainQuestion, FiledChain, Member, NewChain, Review, ReviewChain, ReviewFinding,
};
pub use db::ProjectPaths;
pub use engine::{Engine, ResendError, Resent, Revision};
pub use finding::{Finding, FindingEdit, NewFinding, WriteUp};
pub use identity::{AdoptError, Cookie, Identity, IdentityEdit, NewIdentity};
pub use intercept::{Held, Intercept, Pending, TicketId, Verdict};
pub use lead::{Lead, LeadError, NewLead};
pub use materialise::{Materialised, MaterialisedFile};
pub use model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary};
pub use note::{NewNote, Note};
pub use notify::{Event, Notifier};
pub use policy::{Policy, PolicyError, PolicyRule, RULE_KINDS};
pub use proxy::ProxyHandler;
pub use read::{BodySlice, FlowDetail, FlowKind, FlowQuery, FlowRow, Side, SitemapNode};
pub use registry::{Project, Registry};
pub use scope::{Action, HostKind, Matcher, RuleSpec, Scope, ScopeRule, Target};
pub use server::serve;
