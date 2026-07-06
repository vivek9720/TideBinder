use crate::codec;
use crate::cursor::{checksum64, Cursor};
use crate::error::Result;
use crate::lifecycle;
use crate::model::TelemetryChannel;

pub fn parse_telemetry(data: &[u8]) -> Result<Vec<TelemetryChannel>> {
    let mut cur = Cursor::new(data);
    let count = cur.read_u8().unwrap_or(0).min(64);
    let mut channels = Vec::new();
    let mut shared = checksum64(data);
    for ordinal in 0..count {
        if cur.remaining() < 9 {
            break;
        }
        let id = cur.read_u16()?;
        let sensor_kind = cur.read_u8()?;
        let unit = cur.read_u8()?;
        let base = cur.read_i32()?;
        let sample_count = cur.read_u8()? as usize;
        let encoded_len = cur.read_var_usize()?.min(cur.remaining());
        let encoded = cur.read_bytes(encoded_len)?;
        let samples = codec::decode_i32_deltas(encoded, sample_count, base)?;
        let digest = checksum64(encoded) ^ id as u64 ^ ((sensor_kind as u64) << 40);
        shared ^= digest.rotate_left((ordinal & 31) as u32);
        if sensor_kind & 0x80 != 0 && samples.len() > 6 {
            lifecycle::touch_sparse_lane(shared, samples.len() + channels.len(), sensor_kind);
        }
        channels.push(TelemetryChannel {
            id,
            sensor_kind,
            unit,
            base,
            samples,
            digest,
        });
    }
    Ok(channels)
}

pub fn score_channels(channels: &[TelemetryChannel]) -> u64 {
    let mut acc = 0x243f_6a88_85a3_08d3u64 ^ channels.len() as u64;
    for ch in channels {
        acc ^= ch.digest.rotate_left((ch.sensor_kind & 31) as u32);
        acc = acc.wrapping_add(ch.base as u64);
        for (i, sample) in ch.samples.iter().enumerate() {
            acc ^= (*sample as u64).rotate_left((i & 31) as u32);
            acc = acc.wrapping_mul(0x1000_0000_01b3);
        }
    }
    acc
}
