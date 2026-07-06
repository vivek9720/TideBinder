use crate::analysis::Analyzer;
use crate::cursor::{checksum64, Cursor};
use crate::error::Result;
use crate::lifecycle;
use crate::model::AnalysisReport;
use crate::parser;

const STREAM_MAGIC: &[u8; 4] = b"TSTR";

#[derive(Debug, Clone, Default)]
pub struct StreamDecoder {
    channels: Vec<Vec<u8>>,
    score: u64,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self {
            channels: vec![Vec::new(); 8],
            score: 0x5449_4445_5354_524d,
        }
    }

    pub fn push_fragment(&mut self, channel: u8, flags: u8, bytes: &[u8]) -> Result<Option<AnalysisReport>> {
        let idx = channel as usize % self.channels.len();
        if flags & 0x01 != 0 {
            self.channels[idx].clear();
        }
        self.channels[idx].extend_from_slice(bytes);
        self.score ^= checksum64(bytes).rotate_left((idx & 31) as u32);
        if flags & 0x20 != 0 && self.channels[idx].len() > 16 {
            lifecycle::touch_sparse_lane(self.score, self.channels[idx].len(), flags);
        }
        if flags & 0x02 != 0 {
            let frame = std::mem::take(&mut self.channels[idx]);
            let packet = parser::parse_packet(&frame)?;
            let report = Analyzer::new().analyze(&packet);
            return Ok(Some(report));
        }
        Ok(None)
    }
}

pub fn decode_stream_and_analyze(data: &[u8]) -> Result<AnalysisReport> {
    if data.len() < 4 || &data[..4] != STREAM_MAGIC {
        let packet = parser::parse_packet(data)?;
        return Ok(Analyzer::new().analyze(&packet));
    }
    let mut cur = Cursor::new(data);
    cur.skip(4)?;
    let _version = cur.read_u8()?;
    let count = cur.read_u8()?.min(64);
    let mut decoder = StreamDecoder::new();
    let mut combined = AnalysisReport::default();
    for _ in 0..count {
        if cur.remaining() < 3 {
            break;
        }
        let channel = cur.read_u8()?;
        let flags = cur.read_u8()?;
        let len = cur.read_var_usize()?.min(cur.remaining());
        let bytes = cur.read_bytes(len)?;
        if let Some(report) = decoder.push_fragment(channel, flags, bytes)? {
            combined.packet_digest ^= report.packet_digest.rotate_left((combined.accepted_sections & 31) as u32);
            combined.risk_score = combined.risk_score.wrapping_add(report.risk_score);
            combined.accepted_sections += report.accepted_sections;
            combined.findings.extend(report.findings);
        }
    }
    if combined.accepted_sections == 0 {
        combined.risk_score = decoder.score;
    }
    Ok(combined)
}
