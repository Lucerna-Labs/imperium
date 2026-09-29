//! The Imperium node binary, as a library.
//!
//! The binary is the process owner, so the pieces that *are* the process —
//! the supervision composition, the cognition policy that decides whether the
//! spider carries an engine, and the control surface — live here rather than in
//! `main.rs`. That is also what lets `tests/spider_cognition.rs` drive the same
//! composition a deployment runs, instead of a copy of it.

pub mod control;
pub mod keyfile;
pub mod mesh_identity;
pub mod operator_key;
pub mod supervision;
