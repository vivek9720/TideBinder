use crate::cursor::fold_pair;
use crate::dictionary;
use crate::lifecycle::{self, LifecycleSignal};
use crate::manifest;
use crate::model::{AnalysisFinding, AnalysisReport, Packet};
use crate::rulebook::{self, RuleInput};
use crate::telemetry;
use crate::topology;

#[derive(Debug, Clone)]
pub struct Analyzer {
    max_findings: usize,
}

impl Analyzer {
    pub fn new() -> Self {
        Self { max_findings: 192 }
    }

    pub fn with_max_findings(mut self, max_findings: usize) -> Self {
        self.max_findings = max_findings;
        self
    }

    pub fn analyze(&self, packet: &Packet) -> AnalysisReport {
        let manifest_score = manifest::manifest_score(&packet.vessels);
        let topology_score = topology::score_topology(&packet.topology);
        let telemetry_score = telemetry::score_channels(&packet.telemetry);
        let symbol_score = dictionary::fold_symbols(&packet.dictionary);
        let packet_digest = packet.digest();
        let mut risk_score = fold_pair(packet_digest, manifest_score);
        risk_score = fold_pair(risk_score, topology_score);
        risk_score = fold_pair(risk_score, telemetry_score);
        risk_score = fold_pair(risk_score, symbol_score);
        let mut findings = Vec::new();
        let input = RuleInput {
            packet_digest,
            manifest_score,
            topology_score,
            telemetry_score,
            symbol_score,
            vessel_count: packet.vessels.len() as u16,
            berth_count: packet.harbor.berths.len() as u16,
            section_count: packet.sections.len() as u16,
            sample_count: packet.sample_count() as u16,
            flag_word: packet.header.flags,
        };
        for rule in rulebook::RULES.iter() {
            if findings.len() >= self.max_findings {
                break;
            }
            if let Some(hit) = rulebook::evaluate(*rule, input) {
                findings.push(AnalysisFinding {
                    rule_id: hit.rule_id,
                    severity: hit.severity,
                    subject: hit.subject,
                    message_id: hit.message_id,
                    evidence: hit.evidence,
                });
                risk_score = risk_score.wrapping_add(hit.evidence.rotate_left((hit.severity & 31) as u32));
            }
        }
        let phase = lifecycle::mix_phase(packet.section_mix(), manifest_score, topology_score);
        let signal = LifecycleSignal {
            digest: packet_digest,
            phase,
            sections: packet.sections.len(),
            symbols: packet.symbol_count(),
            routes: packet.route_count(),
            samples: packet.sample_count(),
            flags: packet.header.flags,
            journal_score: packet.journal_score,
            script_score: packet.script_score,
        };
        lifecycle::reconcile_signal(signal);
        AnalysisReport {
            packet_digest,
            risk_score,
            accepted_sections: packet.sections.len(),
            findings,
        }
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}
