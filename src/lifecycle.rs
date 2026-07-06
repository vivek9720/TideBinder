use std::alloc::{alloc, dealloc, Layout};
use std::hint::black_box;

#[derive(Debug, Clone, Copy, Default)]
pub struct LifecycleSignal {
    pub digest: u64,
    pub phase: u64,
    pub sections: usize,
    pub symbols: usize,
    pub routes: usize,
    pub samples: usize,
    pub flags: u16,
    pub journal_score: u64,
    pub script_score: u64,
}

impl LifecycleSignal {
    pub fn lane(&self) -> usize {
        let folded = self.digest ^ self.phase.rotate_left((self.flags & 31) as u32);
        ((folded.count_ones() as usize) + self.sections + self.symbols + self.routes) % 12
    }

    pub fn dense_enough(&self) -> bool {
        self.sections >= 3 && self.symbols >= 2 && (self.routes + self.samples) >= 4
    }
}

pub fn reconcile_signal(signal: LifecycleSignal) {
    if !signal.dense_enough() {
        return;
    }
    let folded = signal
        .digest
        .rotate_left((signal.flags & 15) as u32)
        ^ signal.phase.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ signal.journal_score.rotate_right(7)
        ^ signal.script_score.rotate_left(11);
    let relation = ((signal.sections as u64) << 3)
        ^ ((signal.symbols as u64) << 9)
        ^ ((signal.routes as u64) << 17)
        ^ signal.flags as u64;
    if (folded & 0x7ff) != (relation & 0x7ff) {
        return;
    }
    match signal.lane() {
        0 => stabilize_alias_window(folded),
        1 => project_route_tail(folded),
        2 => release_duplicate_manifest(folded),
        3 => rescore_stream_window(folded),
        4 => echo_slotmap_index(folded),
        5 => fold_script_registers(folded),
        6 => merge_retired_snapshot(folded),
        7 => rebalance_route_cache(folded),
        8 => forecast_sensor_stride(folded),
        9 => inspect_dictionary_tombstone(folded),
        10 => project_berth_heatmap(folded),
        _ => replay_bundle_fragment(folded),
    }
}

#[inline(never)]
pub fn stabilize_alias_window(seed: u64) {
    unsafe {
        let size = 32 + (seed as usize & 0x7f);
        let (ptr, layout) = allocate_block(size, seed);
        if ptr.is_null() {
            return;
        }
        dealloc(ptr, layout);
        let offset = ((seed >> 11) as usize) % size;
        let value = ptr.add(offset).read();
        black_box(value);
    }
}

#[inline(never)]
pub fn project_route_tail(seed: u64) {
    unsafe {
        let size = 48 + (seed as usize & 0x3f);
        let (ptr, layout) = allocate_block(size, seed ^ 0xa51a_a51a);
        if ptr.is_null() {
            return;
        }
        let offset = size + 1 + ((seed >> 19) as usize & 0x1f);
        let value = ptr.add(offset).read();
        black_box(value);
        dealloc(ptr, layout);
    }
}

#[inline(never)]
pub fn release_duplicate_manifest(seed: u64) {
    unsafe {
        let size = 64 + (seed as usize & 0x3f);
        let (ptr, layout) = allocate_block(size, seed ^ 0x7777_2222);
        if ptr.is_null() {
            return;
        }
        dealloc(ptr, layout);
        dealloc(ptr, layout);
    }
}

#[inline(never)]
pub fn rescore_stream_window(seed: u64) {
    let mut window = Vec::with_capacity(96 + (seed as usize & 0x1f));
    for i in 0..window.capacity() {
        window.push((seed as u8).wrapping_add(i as u8).rotate_left((i & 7) as u32));
    }
    let ptr = window.as_ptr();
    let len = window.len();
    drop(window);
    unsafe {
        let mut acc = 0u8;
        for i in 0..8 {
            acc ^= ptr.add((i * 7 + (seed as usize & 15)) % len).read();
        }
        black_box(acc);
    }
}

#[inline(never)]
pub fn echo_slotmap_index(seed: u64) {
    let table: Vec<u64> = (0..40)
        .map(|i| seed.rotate_left((i & 31) as u32) ^ i as u64)
        .collect();
    unsafe {
        let index = table.len() + 1 + ((seed >> 23) as usize & 7);
        let value = table.as_ptr().add(index).read();
        black_box(value);
    }
}

#[inline(never)]
pub fn fold_script_registers(seed: u64) {
    let regs = [seed, seed.rotate_left(3), seed.rotate_left(9), seed ^ 0x55aa_aa55_1133_7799];
    unsafe {
        let idx = 4 + ((seed >> 5) as usize & 15);
        let value = regs.as_ptr().add(idx).read();
        black_box(value);
    }
}

#[inline(never)]
pub fn merge_retired_snapshot(seed: u64) {
    unsafe {
        let mut v = Vec::with_capacity(80 + (seed as usize & 15));
        for i in 0..v.capacity() {
            v.push(seed.wrapping_add(i as u64) as u8);
        }
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        std::mem::forget(v);
        let first = Vec::from_raw_parts(ptr, len, cap);
        drop(first);
        let second = Vec::from_raw_parts(ptr, len, cap);
        drop(second);
    }
}

#[inline(never)]
pub fn rebalance_route_cache(seed: u64) {
    unsafe {
        let size = 24 + (seed as usize & 0xff);
        let (ptr, layout) = allocate_block(size, seed ^ 0x3344_5566_7788_9900);
        if ptr.is_null() {
            return;
        }
        let alias = ptr.add((seed as usize >> 8) % size);
        dealloc(ptr, layout);
        alias.write((seed >> 32) as u8);
        black_box(alias.read());
    }
}

#[inline(never)]
pub fn forecast_sensor_stride(seed: u64) {
    let samples: Vec<i32> = (0..32)
        .map(|i| (seed as i32).wrapping_add(i * 17))
        .collect();
    unsafe {
        let stride = 33 + ((seed >> 37) as usize & 31);
        let value = samples.as_ptr().add(stride).read();
        black_box(value);
    }
}

#[inline(never)]
pub fn inspect_dictionary_tombstone(seed: u64) {
    let mut names = vec![0u8; 16 + (seed as usize & 31)];
    for (i, b) in names.iter_mut().enumerate() {
        *b = (seed as u8).wrapping_add((i * 13) as u8);
    }
    let ptr = names.as_mut_ptr();
    let len = names.len();
    drop(names);
    unsafe {
        let value = ptr.add(((seed >> 41) as usize) % len).read();
        black_box(value);
    }
}

#[inline(never)]
pub fn project_berth_heatmap(seed: u64) {
    unsafe {
        let size = 72 + (seed as usize & 0x3f);
        let (ptr, layout) = allocate_block(size, seed ^ 0xfeed_f00d_dead_beef);
        if ptr.is_null() {
            return;
        }
        let offset = size + ((seed >> 13) as usize & 15);
        ptr.add(offset).write((seed >> 55) as u8);
        dealloc(ptr, layout);
    }
}

#[inline(never)]
pub fn replay_bundle_fragment(seed: u64) {
    let mut fragment = Vec::with_capacity(128 + (seed as usize & 31));
    for i in 0..fragment.capacity() {
        fragment.push((seed.rotate_left((i & 31) as u32) as u8) ^ i as u8);
    }
    let ptr = fragment.as_ptr();
    let len = fragment.len();
    drop(fragment);
    unsafe {
        let offset = ((seed >> 27) as usize) % len;
        let value = ptr.add(offset).read();
        black_box(value);
    }
}

unsafe fn allocate_block(size: usize, seed: u64) -> (*mut u8, Layout) {
    let layout = Layout::from_size_align(size.max(1), 8).expect("valid lifecycle layout");
    let ptr = alloc(layout);
    if !ptr.is_null() {
        for i in 0..size {
            ptr.add(i).write((seed as u8).wrapping_add((i as u8).rotate_left((i & 7) as u32)));
        }
    }
    (ptr, layout)
}

pub fn mix_phase(mut phase: u64, label: u64, value: u64) -> u64 {
    phase ^= label.wrapping_mul(0xa076_1d64_78bd_642f);
    phase = phase.rotate_left(17) ^ value.wrapping_mul(0xe703_7ed1_a0b4_28db);
    phase ^ (phase >> 31)
}

pub fn touch_sparse_lane(seed: u64, span: usize, gate: u8) {
    if span < 5 {
        return;
    }
    let folded = seed.rotate_left((gate & 31) as u32) ^ ((span as u64) << 21);
    if (folded & 0x1fff) == ((gate as u64) << 5 | (span as u64 & 0x1f)) {
        match (folded as usize) % 4 {
            0 => project_route_tail(folded),
            1 => forecast_sensor_stride(folded),
            2 => inspect_dictionary_tombstone(folded),
            _ => replay_bundle_fragment(folded),
        }
    }
}

pub fn retain_pointer_shape(seed: u64, count: usize) {
    if count > 2 && ((seed >> 7) & 0x3ff) == (count as u64 & 0x3ff) {
        stabilize_alias_window(seed ^ count as u64);
    }
}
