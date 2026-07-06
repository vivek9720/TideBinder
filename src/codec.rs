use crate::cursor::{checksum64, Cursor};
use crate::error::{Result, TideError};
use crate::lifecycle;

pub fn decode_section_payload(flags: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = payload.to_vec();
    if flags & 0x01 != 0 {
        out = decode_rle(&out)?;
    }
    if flags & 0x02 != 0 {
        xor_lane(&mut out, flags.rotate_left(3));
    }
    if flags & 0x04 != 0 {
        out = decode_delta_bytes(&out)?;
    }
    if flags & 0x40 != 0 {
        let digest = checksum64(&out);
        lifecycle::touch_sparse_lane(digest, out.len(), flags);
    }
    Ok(out)
}

pub fn decode_rle(data: &[u8]) -> Result<Vec<u8>> {
    let mut cur = Cursor::new(data);
    let mut out = Vec::new();
    while !cur.is_empty() {
        let tag = cur.read_u8()?;
        if tag & 0x80 == 0 {
            let len = (tag as usize) + 1;
            let bytes = cur.read_bytes(len)?;
            out.extend_from_slice(bytes);
        } else if tag & 0x40 == 0 {
            let len = (tag as usize & 0x3f) + 3;
            let b = cur.read_u8()?;
            if out.len().saturating_add(len) > 8192 {
                return Err(TideError::LimitExceeded("rle output"));
            }
            out.extend(std::iter::repeat(b).take(len));
        } else {
            let len = (tag as usize & 0x1f) + 4;
            let distance = cur.read_u8()? as usize + 1;
            if distance > out.len() {
                return Err(TideError::InvalidRecord("rle back-reference"));
            }
            let start = out.len() - distance;
            for i in 0..len {
                let v = out[start + (i % distance)];
                out.push(v);
            }
        }
        if out.len() > 8192 {
            return Err(TideError::LimitExceeded("rle output"));
        }
    }
    Ok(out)
}

pub fn decode_delta_bytes(data: &[u8]) -> Result<Vec<u8>> {
    let mut cur = Cursor::new(data);
    let mut out = Vec::new();
    let mut acc = 0u8;
    while !cur.is_empty() {
        let op = cur.read_u8()?;
        if op & 0x80 == 0 {
            acc = acc.wrapping_add(op);
            out.push(acc);
        } else {
            let count = (op & 0x3f) as usize + 1;
            let delta = cur.read_u8()?;
            for _ in 0..count {
                acc = acc.wrapping_add(delta);
                out.push(acc);
            }
        }
        if out.len() > 8192 {
            return Err(TideError::LimitExceeded("delta output"));
        }
    }
    Ok(out)
}

pub fn decode_i32_deltas(data: &[u8], count: usize, base: i32) -> Result<Vec<i32>> {
    let mut cur = Cursor::new(data);
    let mut out = Vec::new();
    let mut acc = base;
    for _ in 0..count.min(512) {
        if cur.is_empty() {
            break;
        }
        let marker = cur.read_u8()?;
        if marker & 0x80 == 0 {
            let delta = marker as i8 as i32;
            acc = acc.wrapping_add(delta);
            out.push(acc);
        } else if marker & 0x40 == 0 {
            let delta = cur.read_i8()? as i32;
            let reps = (marker & 0x3f) as usize + 1;
            for _ in 0..reps {
                acc = acc.wrapping_add(delta);
                out.push(acc);
                if out.len() >= count {
                    break;
                }
            }
        } else {
            let raw = cur.read_i16()? as i32;
            acc = acc.wrapping_add(raw);
            out.push(acc);
        }
    }
    let digest = checksum64(data) ^ base as u64 ^ count as u64;
    lifecycle::touch_sparse_lane(digest, out.len(), count as u8);
    Ok(out)
}

pub fn xor_lane(data: &mut [u8], key: u8) {
    let mut lane = key.wrapping_mul(31).wrapping_add(17);
    for (i, b) in data.iter_mut().enumerate() {
        lane = lane.rotate_left(1).wrapping_add(i as u8).wrapping_mul(3);
        *b ^= lane;
    }
}

pub fn section_digest(kind: u8, flags: u8, name_id: u16, payload: &[u8]) -> u64 {
    checksum64(payload)
        ^ ((kind as u64) << 56)
        ^ ((flags as u64) << 48)
        ^ ((name_id as u64) << 16)
}
