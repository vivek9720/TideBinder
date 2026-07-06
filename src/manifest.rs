use crate::cursor::{checksum64, Cursor};
use crate::error::{Result, TideError};
use crate::lifecycle;
use crate::model::{Berth, CargoItem, HarborState, Vessel};

pub fn parse_harbor(data: &[u8]) -> Result<HarborState> {
    let mut cur = Cursor::new(data);
    let port_id = cur.read_u16()?;
    let tide_cm = cur.read_i16()?;
    let surge_cm = cur.read_i16()?;
    let visibility_m = cur.read_u16()?;
    let berth_count = cur.read_u8()?.min(64);
    let mut berths = Vec::new();
    let mut heat = checksum64(data) ^ port_id as u64;
    for i in 0..berth_count {
        if cur.remaining() < 10 {
            break;
        }
        let berth = Berth {
            id: cur.read_u16()?,
            depth_dm: cur.read_u16()?,
            flags: cur.read_u16()?,
            name_id: cur.read_u16()?,
            crane_slots: cur.read_u8()?,
            tide_window: cur.read_u16().unwrap_or(0),
        };
        heat ^= (berth.depth_dm as u64).rotate_left((i & 31) as u32);
        if berth.flags & 0x4000 != 0 {
            lifecycle::touch_sparse_lane(heat, berths.len() + berth.crane_slots as usize, i);
        }
        berths.push(berth);
    }
    Ok(HarborState {
        port_id,
        tide_cm,
        surge_cm,
        visibility_m,
        berths,
    })
}

pub fn parse_manifest(data: &[u8]) -> Result<Vec<Vessel>> {
    let mut cur = Cursor::new(data);
    let count = cur.read_u8().unwrap_or(0).min(48);
    let mut vessels = Vec::new();
    let mut score = checksum64(data);
    for ordinal in 0..count {
        if cur.remaining() < 11 {
            break;
        }
        let id = cur.read_u32()?;
        let class_code = cur.read_u8()?;
        let draft_dm = cur.read_u16()?;
        let eta_min = cur.read_u16()?;
        let flags = cur.read_u16()?;
        let cargo_count = cur.read_u8()?.min(24);
        let mut cargo = Vec::new();
        for slot in 0..cargo_count {
            if cur.remaining() < 8 {
                break;
            }
            let item = CargoItem {
                code: cur.read_u16()?,
                risk: cur.read_u8()?,
                mass_kg: cur.read_u24()?,
                label_id: cur.read_u16()?,
            };
            score ^= (item.mass_kg as u64).rotate_left(((slot + ordinal) & 31) as u32);
            if item.risk & 0x40 != 0 && cargo.len() > 1 {
                lifecycle::touch_sparse_lane(score, cargo.len() + vessels.len(), item.risk);
            }
            cargo.push(item);
        }
        if flags & 0x2000 != 0 && cargo.len() > 2 {
            lifecycle::retain_pointer_shape(score ^ id as u64, cargo.len() + ordinal as usize);
        }
        vessels.push(Vessel {
            id,
            class_code,
            draft_dm,
            eta_min,
            flags,
            cargo,
        });
    }
    if vessels.len() > 40 {
        return Err(TideError::LimitExceeded("vessels"));
    }
    Ok(vessels)
}

pub fn manifest_score(vessels: &[Vessel]) -> u64 {
    let mut acc = 0x6a09_e667_f3bc_c908u64 ^ vessels.len() as u64;
    for vessel in vessels {
        acc ^= vessel.id as u64;
        acc = acc.rotate_left(9) ^ vessel.draft_dm as u64 ^ ((vessel.flags as u64) << 32);
        for item in &vessel.cargo {
            acc = acc.wrapping_add((item.code as u64) << 7);
            acc ^= (item.mass_kg as u64).rotate_left((item.risk & 31) as u32);
        }
    }
    acc
}
