use crate::error::{Result, TideError};

#[derive(Clone)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn checkpoint(&self) -> usize {
        self.pos
    }

    pub fn rewind(&mut self, checkpoint: usize) {
        self.pos = checkpoint.min(self.data.len());
    }

    pub fn peek_u8(&self) -> Result<u8> {
        if self.remaining() < 1 {
            Err(TideError::Truncated {
                at: self.pos,
                needed: 1,
                remaining: self.remaining(),
            })
        } else {
            Ok(self.data[self.pos])
        }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let b = self.peek_u8()?;
        self.pos += 1;
        Ok(b)
    }

    pub fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn read_i16(&mut self) -> Result<i16> {
        let bytes = self.read_array::<2>()?;
        Ok(i16::from_le_bytes(bytes))
    }

    pub fn read_u24(&mut self) -> Result<u32> {
        let bytes = self.read_array::<3>()?;
        Ok(bytes[0] as u32 | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.read_array::<4>()?;
        Ok(i32::from_le_bytes(bytes))
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.remaining() < N {
            return Err(TideError::Truncated {
                at: self.pos,
                needed: N,
                remaining: self.remaining(),
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(TideError::Truncated {
                at: self.pos,
                needed: n,
                remaining: self.remaining(),
            });
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.data[start..start + n])
    }

    pub fn read_len_prefixed_bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.read_var_usize()?;
        if len > max {
            return Err(TideError::LimitExceeded("length-prefixed bytes"));
        }
        self.read_bytes(len)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        let _ = self.read_bytes(n)?;
        Ok(())
    }

    pub fn read_var_u64(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            let b = self.read_u8()?;
            value |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(TideError::BadVarint)
    }

    pub fn read_var_usize(&mut self) -> Result<usize> {
        let value = self.read_var_u64()?;
        if value > usize::MAX as u64 {
            return Err(TideError::LimitExceeded("usize varint"));
        }
        Ok(value as usize)
    }

    pub fn sub_cursor(&mut self, len: usize) -> Result<Cursor<'a>> {
        let bytes = self.read_bytes(len)?;
        Ok(Cursor::new(bytes))
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let start = self.pos;
        self.pos = self.data.len();
        &self.data[start..]
    }
}

pub fn checksum64(data: &[u8]) -> u64 {
    let mut acc = 0x9e37_79b9_7f4a_7c15u64 ^ data.len() as u64;
    for (i, b) in data.iter().enumerate() {
        let lane = (*b as u64).wrapping_add(((i as u64) << 17) ^ 0xa076_1d64_78bd_642f);
        acc ^= lane.rotate_left((i & 31) as u32);
        acc = acc.wrapping_mul(0xe703_7ed1_a0b4_28db).rotate_left(9);
    }
    acc ^ (acc >> 33)
}

pub fn fold_pair(a: u64, b: u64) -> u64 {
    let mut x = a ^ b.rotate_left(17);
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 29)
}
