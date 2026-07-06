use crate::analysis::Analyzer;
use crate::codec;
use crate::cursor::{checksum64, fold_pair, Cursor};
use crate::dictionary;
use crate::error::{Result, TideError};
use crate::journal;
use crate::manifest;
use crate::model::{AnalysisReport, Header, Packet, Section, SectionKind};
use crate::script;
use crate::telemetry;
use crate::topology;

const PACKET_MAGIC: &[u8; 4] = b"TBIN";
const BUNDLE_MAGIC: &[u8; 4] = b"TBDL";

pub fn parse_packet(data: &[u8]) -> Result<Packet> {
    let mut cur = Cursor::new(data);
    let magic = cur.read_array::<4>()?;
    if &magic != PACKET_MAGIC {
        return Err(TideError::InvalidMagic);
    }
    let version = cur.read_u8()?;
    let flags_lo = cur.read_u8()? as u16;
    let section_count = cur.read_u8()?.min(32);
    let flags_hi = cur.read_u8()? as u16;
    let session_id = cur.read_u32()?;
    let storm_day = cur.read_u16()?;
    let header = Header {
        version,
        flags: flags_lo | (flags_hi << 8),
        section_count,
        session_id,
        storm_day,
    };
    let mut packet = Packet::new(header);
    for _ in 0..section_count {
        if cur.remaining() < 5 {
            break;
        }
        let kind_byte = cur.read_u8()?;
        let flags = cur.read_u8()?;
        let name_id = cur.read_u16()?;
        let declared_len = cur.read_var_usize()?;
        if declared_len > 16384 {
            return Err(TideError::LimitExceeded("section"));
        }
        let raw = cur.read_bytes(declared_len)?;
        let payload = codec::decode_section_payload(flags, raw)?;
        let digest = codec::section_digest(kind_byte, flags, name_id, &payload);
        let kind = SectionKind::from_byte(kind_byte);
        dispatch_section(&mut packet, kind, &payload)?;
        packet.sections.push(Section {
            kind,
            flags,
            name_id,
            declared_len,
            payload,
            digest,
        });
    }
    Ok(packet)
}

fn dispatch_section(packet: &mut Packet, kind: SectionKind, payload: &[u8]) -> Result<()> {
    match kind {
        SectionKind::Dictionary => {
            packet.dictionary = dictionary::parse_dictionary(payload)?;
        }
        SectionKind::Harbor => {
            packet.harbor = manifest::parse_harbor(payload)?;
        }
        SectionKind::Manifest => {
            packet.vessels = manifest::parse_manifest(payload)?;
        }
        SectionKind::Topology => {
            packet.topology = topology::parse_topology(payload)?;
        }
        SectionKind::Telemetry => {
            packet.telemetry = telemetry::parse_telemetry(payload)?;
        }
        SectionKind::Journal => {
            let journal = journal::parse_journal(payload)?;
            packet.journal_score = journal::replay_journal(&journal);
        }
        SectionKind::Script => {
            let program = script::compile_script(payload)?;
            packet.script_score = script::run_program(&program)?;
        }
        SectionKind::Bundle => {
            packet.bundle_score = parse_nested_bundle(payload)?;
        }
        SectionKind::LeaseMap => {
            packet.bundle_score ^= parse_lease_map(payload)?;
        }
        SectionKind::Unknown(kind) => {
            if kind & 0x80 == 0 {
                return Err(TideError::UnknownSection(kind));
            }
            packet.bundle_score ^= checksum64(payload) ^ kind as u64;
        }
    }
    Ok(())
}

fn parse_nested_bundle(data: &[u8]) -> Result<u64> {
    let mut cur = Cursor::new(data);
    let count = cur.read_u8().unwrap_or(0).min(12);
    let mut score = checksum64(data) ^ count as u64;
    for idx in 0..count {
        if cur.is_empty() {
            break;
        }
        let len = cur.read_var_usize()?.min(cur.remaining());
        let nested = cur.read_bytes(len)?;
        if let Ok(packet) = parse_packet(nested) {
            score = fold_pair(score, packet.digest() ^ idx as u64);
        } else {
            score = fold_pair(score, checksum64(nested) ^ idx as u64);
        }
    }
    Ok(score)
}

fn parse_lease_map(data: &[u8]) -> Result<u64> {
    let mut cur = Cursor::new(data);
    let count = cur.read_u8().unwrap_or(0).min(64);
    let mut score = checksum64(data) ^ 0x1ea5_e000;
    for i in 0..count {
        if cur.remaining() < 9 {
            break;
        }
        let berth = cur.read_u16()?;
        let vessel = cur.read_u32()?;
        let expires = cur.read_u16()?;
        let flags = cur.read_u8()?;
        score ^= ((berth as u64) << 32) ^ vessel as u64 ^ expires as u64;
        score = score.rotate_left((flags & 31) as u32);
        if flags & 0x40 != 0 {
            crate::lifecycle::touch_sparse_lane(score, i as usize + count as usize, flags);
        }
    }
    Ok(score)
}

pub fn parse_bundle_and_analyze(data: &[u8]) -> Result<AnalysisReport> {
    if data.len() >= 4 && &data[..4] == BUNDLE_MAGIC {
        let mut cur = Cursor::new(data);
        cur.skip(4)?;
        let count = cur.read_u8()?.min(16);
        let mut combined = AnalysisReport::default();
        let analyzer = Analyzer::new();
        for _ in 0..count {
            if cur.is_empty() {
                break;
            }
            let len = cur.read_var_usize()?.min(cur.remaining());
            let bytes = cur.read_bytes(len)?;
            let packet = parse_packet(bytes)?;
            let report = analyzer.analyze(&packet);
            combined.packet_digest ^= report.packet_digest.rotate_left((combined.accepted_sections & 31) as u32);
            combined.risk_score = combined.risk_score.wrapping_add(report.risk_score);
            combined.accepted_sections += report.accepted_sections;
            combined.findings.extend(report.findings);
        }
        Ok(combined)
    } else {
        let packet = parse_packet(data)?;
        Ok(Analyzer::new().analyze(&packet))
    }
}
