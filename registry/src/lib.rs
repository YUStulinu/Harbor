//! harbor-registry: container images for the Harbor runtime.
//!
//! - [`client`]: pulls images from public registries (Docker Hub's token flow included) and
//!   pushes them to others, verifying every blob's SHA-256 digest;
//! - [`store`]: a content-addressed local store, with layers unpacked for overlayfs;
//! - [`server`]: a small registry (Docker Registry HTTP API v2) serving that store.

pub mod client;
pub mod manifest;
pub mod reference;
pub mod server;
pub mod store;
pub mod unpack;
