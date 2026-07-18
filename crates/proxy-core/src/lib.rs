//! Core proxy engine: capture, history, and replay.
//!
//! This crate deliberately knows nothing about how it is presented. Frontends
//! (TUI, MCP) depend on it, never the other way around.

pub mod ca;
pub mod engine;
pub mod model;
pub mod proxy;
pub mod server;
pub mod store;

pub use engine::{Engine, ResendError};
pub use model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary};
pub use proxy::ProxyHandler;
pub use server::serve;
