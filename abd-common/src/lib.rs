//! Common types and constants for the ABD (Attiya, Bar-Noy, Dolev) protocol implementation.
//!
//! This crate provides shared definitions for both kernel and user-space components,
//! including message types, serialization, and network node/client information.

#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
extern crate std;

pub mod constants;
pub mod map_types;
pub mod msg;
pub mod value;
