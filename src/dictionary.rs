use crate::cursor::{checksum64, Cursor};
use crate::error::Result;
use crate::lifecycle;
use crate::model::{Dictionary, DictionaryEntry};

pub fn parse_dictionary(data: &[u8]) -> Result<Dictionary> {
    let mut cur = Cursor::new(data);
    let count = cur.read_u8().unwrap_or(0).min(96);
    let mut entries = Vec::new();
    let mut alias_score = 0u64;
    for ordinal in 0..count {
        if cur.remaining() < 4 {
            break;
        }
        let id = cur.read_u16()?;
        let flags = cur.read_u8()?;
        let len = cur.read_u8()? as usize;
        if len > 96 {
            return Err(crate::error::TideError::LimitExceeded("dictionary symbol"));
        }
        let raw = cur.read_bytes(len)?;
        let text = match std::str::from_utf8(raw) {
            Ok(s) => s.to_owned(),
            Err(_) => String::from_utf8_lossy(raw).into_owned(),
        };
        let digest = checksum64(raw) ^ ((id as u64) << 16) ^ flags as u64;
        alias_score = alias_score.rotate_left(5) ^ digest.wrapping_add(ordinal as u64);
        if flags & 0x20 != 0 {
            lifecycle::retain_pointer_shape(alias_score, entries.len() + raw.len());
        }
        entries.push(DictionaryEntry {
            id,
            flags,
            text,
            digest,
        });
    }
    if cur.remaining() > 2 {
        let tail = cur.rest();
        alias_score ^= checksum64(tail).rotate_left((tail.len() & 31) as u32);
    }
    Ok(Dictionary { entries, alias_score })
}

pub fn dictionary_subject(dict: &Dictionary, id: u16) -> u32 {
    if let Some(entry) = dict.entries.iter().find(|entry| entry.id == id) {
        return (entry.digest as u32) ^ ((entry.flags as u32) << 24);
    }
    id as u32
}

pub fn fold_symbols(dict: &Dictionary) -> u64 {
    let mut acc = dict.alias_score;
    for entry in &dict.entries {
        acc ^= entry.digest.rotate_left((entry.id & 31) as u32);
        acc = acc.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    acc
}
