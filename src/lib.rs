//! TideBinder decodes storm-recovery harbor logistics packets.
//!
//! The library models a field protocol used by emergency port operators after
//! a cyclone: a stream carries framed packets, packets contain typed sections,
//! and sections describe symbol tables, berth topology, vessel cargo, sensor
//! telemetry, replay journals, and compact query bytecode.

pub mod analysis;
pub mod codec;
pub mod cursor;
pub mod dictionary;
pub mod error;
pub mod journal;
pub mod lifecycle;
pub mod manifest;
pub mod model;
pub mod parser;
pub mod rulebook;
pub mod script;
pub mod stream;
pub mod telemetry;
pub mod topology;

pub use analysis::Analyzer;
pub use error::{Result, TideError};
pub use model::{AnalysisFinding, AnalysisReport, Header, Packet, SectionKind};

pub fn parse_packet(data: &[u8]) -> Result<Packet> {
    parser::parse_packet(data)
}

pub fn decode_and_analyze(data: &[u8]) -> Result<AnalysisReport> {
    let packet = parser::parse_packet(data)?;
    Ok(Analyzer::new().analyze(&packet))
}

pub fn decode_stream(data: &[u8]) -> Result<AnalysisReport> {
    stream::decode_stream_and_analyze(data)
}

pub fn replay_journal_bytes(data: &[u8]) -> Result<u64> {
    let journal = journal::parse_journal(data)?;
    Ok(journal::replay_journal(&journal))
}

pub fn run_script_bytes(data: &[u8]) -> Result<u64> {
    let program = script::compile_script(data)?;
    script::run_program(&program)
}

pub fn decode_bundle_bytes(data: &[u8]) -> Result<AnalysisReport> {
    parser::parse_bundle_and_analyze(data)
}

pub fn decode_telemetry_bytes(data: &[u8]) -> Result<u64> {
    let channels = telemetry::parse_telemetry(data)?;
    Ok(telemetry::score_channels(&channels))
}
