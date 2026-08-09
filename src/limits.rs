//! Central safety limits. These are format/resource guards, not target-specific values.

/// Default maximum accepted input size.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
/// Default maximum uncompressed ZIP member size.
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
/// JVM constant pools use a `u16` entry count.
pub const MAX_CONSTANT_POOL_ENTRIES: usize = u16::MAX as usize;
/// Defensive cap for PE directory iteration.
pub const MAX_PE_TABLE_ENTRIES: usize = 1_000_000;
/// Defensive cap for NUL-terminated PE strings.
pub const MAX_PE_STRING_BYTES: usize = 4096;
