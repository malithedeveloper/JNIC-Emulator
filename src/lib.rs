//! Safe, research-oriented analysis primitives for JNIC-protected archives.
//!
//! The crate parses input as data. Target native code is never loaded into the
//! host process and is never invoked.

pub mod analyzer;
pub mod archive;
pub mod classfile;
pub mod descriptor;
pub mod emulator;
pub mod jni;
pub mod limits;
pub mod pe;
pub mod report;

pub use analyzer::{AnalysisConfig, AnalysisModel, analyze_path};
pub use report::render_report;
