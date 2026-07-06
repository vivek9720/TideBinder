use crate::cursor::{checksum64, fold_pair};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Dictionary,
    Harbor,
    Manifest,
    Topology,
    Telemetry,
    Journal,
    Script,
    Bundle,
    LeaseMap,
    Unknown(u8),
}

impl SectionKind {
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => SectionKind::Dictionary,
            2 => SectionKind::Harbor,
            3 => SectionKind::Manifest,
            4 => SectionKind::Topology,
            5 => SectionKind::Telemetry,
            6 => SectionKind::Journal,
            7 => SectionKind::Script,
            8 => SectionKind::Bundle,
            9 => SectionKind::LeaseMap,
            other => SectionKind::Unknown(other),
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            SectionKind::Dictionary => 1,
            SectionKind::Harbor => 2,
            SectionKind::Manifest => 3,
            SectionKind::Topology => 4,
            SectionKind::Telemetry => 5,
            SectionKind::Journal => 6,
            SectionKind::Script => 7,
            SectionKind::Bundle => 8,
            SectionKind::LeaseMap => 9,
            SectionKind::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub flags: u16,
    pub section_count: u8,
    pub session_id: u32,
    pub storm_day: u16,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub kind: SectionKind,
    pub flags: u8,
    pub name_id: u16,
    pub declared_len: usize,
    pub payload: Vec<u8>,
    pub digest: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DictionaryEntry {
    pub id: u16,
    pub flags: u8,
    pub text: String,
    pub digest: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    pub entries: Vec<DictionaryEntry>,
    pub alias_score: u64,
}

impl Dictionary {
    pub fn lookup(&self, id: u16) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.text.as_str())
    }

    pub fn score(&self) -> u64 {
        self.entries.iter().fold(self.alias_score, |acc, entry| {
            fold_pair(acc ^ entry.id as u64, entry.digest ^ entry.flags as u64)
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Berth {
    pub id: u16,
    pub name_id: u16,
    pub depth_dm: u16,
    pub flags: u16,
    pub crane_slots: u8,
    pub tide_window: u16,
}

#[derive(Debug, Clone, Default)]
pub struct HarborState {
    pub port_id: u16,
    pub tide_cm: i16,
    pub surge_cm: i16,
    pub visibility_m: u16,
    pub berths: Vec<Berth>,
}

#[derive(Debug, Clone, Default)]
pub struct CargoItem {
    pub code: u16,
    pub risk: u8,
    pub mass_kg: u32,
    pub label_id: u16,
}

#[derive(Debug, Clone, Default)]
pub struct Vessel {
    pub id: u32,
    pub class_code: u8,
    pub draft_dm: u16,
    pub eta_min: u16,
    pub flags: u16,
    pub cargo: Vec<CargoItem>,
}

#[derive(Debug, Clone, Default)]
pub struct RouteNode {
    pub id: u16,
    pub kind: u8,
    pub name_id: u16,
    pub capacity: u16,
}

#[derive(Debug, Clone, Default)]
pub struct RouteEdge {
    pub from: u16,
    pub to: u16,
    pub minutes: u16,
    pub flags: u16,
    pub clearance_dm: u16,
}

#[derive(Debug, Clone, Default)]
pub struct Topology {
    pub nodes: Vec<RouteNode>,
    pub edges: Vec<RouteEdge>,
    pub risk_hash: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryChannel {
    pub id: u16,
    pub sensor_kind: u8,
    pub unit: u8,
    pub base: i32,
    pub samples: Vec<i32>,
    pub digest: u64,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisFinding {
    pub rule_id: u16,
    pub severity: u8,
    pub subject: u32,
    pub message_id: u16,
    pub evidence: u64,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisReport {
    pub packet_digest: u64,
    pub risk_score: u64,
    pub accepted_sections: usize,
    pub findings: Vec<AnalysisFinding>,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub header: Header,
    pub sections: Vec<Section>,
    pub dictionary: Dictionary,
    pub harbor: HarborState,
    pub vessels: Vec<Vessel>,
    pub topology: Topology,
    pub telemetry: Vec<TelemetryChannel>,
    pub journal_score: u64,
    pub script_score: u64,
    pub bundle_score: u64,
}

impl Packet {
    pub fn new(header: Header) -> Self {
        Self {
            header,
            sections: Vec::new(),
            dictionary: Dictionary::default(),
            harbor: HarborState::default(),
            vessels: Vec::new(),
            topology: Topology::default(),
            telemetry: Vec::new(),
            journal_score: 0,
            script_score: 0,
            bundle_score: 0,
        }
    }

    pub fn digest(&self) -> u64 {
        let mut acc = self.header.session_id as u64;
        acc = fold_pair(acc, self.header.flags as u64);
        acc = fold_pair(acc, self.dictionary.score());
        acc = fold_pair(acc, self.topology.risk_hash);
        acc = fold_pair(acc, self.journal_score);
        acc = fold_pair(acc, self.script_score);
        acc = fold_pair(acc, self.bundle_score);
        for section in &self.sections {
            acc = fold_pair(acc, section.digest ^ section.kind.as_byte() as u64);
        }
        for channel in &self.telemetry {
            acc = fold_pair(acc, channel.digest ^ channel.id as u64);
        }
        for vessel in &self.vessels {
            acc = fold_pair(acc, vessel.id as u64 ^ vessel.flags as u64);
            for cargo in &vessel.cargo {
                acc = fold_pair(acc, cargo.code as u64 ^ cargo.mass_kg as u64 ^ cargo.risk as u64);
            }
        }
        acc
    }

    pub fn symbol_count(&self) -> usize {
        self.dictionary.entries.len()
    }

    pub fn sample_count(&self) -> usize {
        self.telemetry.iter().map(|ch| ch.samples.len()).sum()
    }

    pub fn route_count(&self) -> usize {
        self.topology.nodes.len() + self.topology.edges.len()
    }

    pub fn section_mix(&self) -> u64 {
        let mut bytes = Vec::with_capacity(self.sections.len() * 4 + 8);
        for section in &self.sections {
            bytes.push(section.kind.as_byte());
            bytes.push(section.flags);
            bytes.extend_from_slice(&section.name_id.to_le_bytes());
        }
        checksum64(&bytes)
    }
}
