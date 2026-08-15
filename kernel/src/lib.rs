//! Deepwyrm kernel crate boundary.
//!
//! This bootstrap library is intentionally inert. It establishes no boot,
//! architecture, ABI, syscall, memory, object, task, IPC, synchronization, or
//! time behavior.

#![no_std]
#![forbid(unsafe_code)]
