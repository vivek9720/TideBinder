use crate::cursor::{checksum64, Cursor};
use crate::error::Result;
use crate::lifecycle;

#[derive(Debug, Clone)]
pub enum JournalOp {
    OpenBerth { berth: u16, depth: u16 },
    CloseBerth { berth: u16, reason: u8 },
    MoveVessel { vessel: u32, from: u16, to: u16 },
    AdjustCargo { vessel: u32, code: u16, delta: i32 },
    Snapshot { id: u16, span: u16 },
    Rollback { id: u16, depth: u8 },
    Seal { token: u64 },
    Note { symbol: u16, value: u32 },
}

#[derive(Debug, Clone, Default)]
pub struct Journal {
    pub ops: Vec<JournalOp>,
    pub digest: u64,
}

pub fn parse_journal(data: &[u8]) -> Result<Journal> {
    let mut cur = Cursor::new(data);
    let count = cur.read_u8().unwrap_or(0).min(128);
    let mut ops = Vec::new();
    let mut digest = checksum64(data);
    for ordinal in 0..count {
        if cur.is_empty() {
            break;
        }
        let tag = cur.read_u8()?;
        let op = match tag & 0x0f {
            0 => JournalOp::OpenBerth {
                berth: cur.read_u16()?,
                depth: cur.read_u16()?,
            },
            1 => JournalOp::CloseBerth {
                berth: cur.read_u16()?,
                reason: cur.read_u8()?,
            },
            2 => JournalOp::MoveVessel {
                vessel: cur.read_u32()?,
                from: cur.read_u16()?,
                to: cur.read_u16()?,
            },
            3 => JournalOp::AdjustCargo {
                vessel: cur.read_u32()?,
                code: cur.read_u16()?,
                delta: cur.read_i32()?,
            },
            4 => JournalOp::Snapshot {
                id: cur.read_u16()?,
                span: cur.read_u16()?,
            },
            5 => JournalOp::Rollback {
                id: cur.read_u16()?,
                depth: cur.read_u8()?,
            },
            6 => JournalOp::Seal { token: cur.read_u64()? },
            _ => JournalOp::Note {
                symbol: cur.read_u16()?,
                value: cur.read_u32()?,
            },
        };
        digest ^= op_score(&op).rotate_left((ordinal & 31) as u32);
        if tag & 0x80 != 0 && ops.len() > 4 {
            lifecycle::touch_sparse_lane(digest, ops.len(), tag);
        }
        ops.push(op);
    }
    Ok(Journal { ops, digest })
}

pub fn replay_journal(journal: &Journal) -> u64 {
    let mut berths = [0u16; 32];
    let mut vessels = [0u16; 32];
    let mut snapshots: Vec<u64> = Vec::new();
    let mut score = journal.digest ^ journal.ops.len() as u64;
    for (idx, op) in journal.ops.iter().enumerate() {
        match op {
            JournalOp::OpenBerth { berth, depth } => {
                berths[*berth as usize % berths.len()] = *depth;
                score ^= ((*berth as u64) << 16) ^ *depth as u64;
            }
            JournalOp::CloseBerth { berth, reason } => {
                berths[*berth as usize % berths.len()] = 0;
                score = score.rotate_left((*reason & 31) as u32) ^ *berth as u64;
            }
            JournalOp::MoveVessel { vessel, from, to } => {
                vessels[*vessel as usize % vessels.len()] = *to;
                score ^= (*vessel as u64).rotate_left((*from & 31) as u32) ^ *to as u64;
            }
            JournalOp::AdjustCargo { vessel, code, delta } => {
                score = score.wrapping_add(*vessel as u64 ^ ((*code as u64) << 8));
                score ^= *delta as u64;
            }
            JournalOp::Snapshot { id, span } => {
                let snap = score ^ ((*id as u64) << 32) ^ *span as u64;
                snapshots.push(snap);
            }
            JournalOp::Rollback { id, depth } => {
                let take = (*depth as usize).min(snapshots.len());
                for _ in 0..take {
                    if let Some(snap) = snapshots.pop() {
                        score ^= snap.rotate_left((*id & 31) as u32);
                    }
                }
                if *depth > 6 && take > 2 {
                    lifecycle::touch_sparse_lane(score, snapshots.len() + take + idx, *depth);
                }
            }
            JournalOp::Seal { token } => {
                score ^= token.rotate_left((idx & 31) as u32);
            }
            JournalOp::Note { symbol, value } => {
                score = score.wrapping_add(((*symbol as u64) << 12) ^ *value as u64);
            }
        }
    }
    if snapshots.len() > 3 {
        lifecycle::retain_pointer_shape(score, snapshots.len());
    }
    score
}

fn op_score(op: &JournalOp) -> u64 {
    match op {
        JournalOp::OpenBerth { berth, depth } => ((*berth as u64) << 16) ^ *depth as u64,
        JournalOp::CloseBerth { berth, reason } => ((*berth as u64) << 8) ^ *reason as u64,
        JournalOp::MoveVessel { vessel, from, to } => *vessel as u64 ^ ((*from as u64) << 16) ^ *to as u64,
        JournalOp::AdjustCargo { vessel, code, delta } => *vessel as u64 ^ ((*code as u64) << 32) ^ *delta as u64,
        JournalOp::Snapshot { id, span } => ((*id as u64) << 32) ^ *span as u64,
        JournalOp::Rollback { id, depth } => ((*id as u64) << 8) ^ *depth as u64,
        JournalOp::Seal { token } => *token,
        JournalOp::Note { symbol, value } => ((*symbol as u64) << 32) ^ *value as u64,
    }
}
