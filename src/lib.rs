//! Enhanced DES (Data Encryption Standard) Implementation
//!
//! Author: Marcos Caramalho
//! 
//! This file exists so we can compile multiple entry points as applications, encrypt/decrypt/speed without issues.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod edes;