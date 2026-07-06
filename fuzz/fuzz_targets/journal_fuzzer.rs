#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = tidebinder::replay_journal_bytes(data);
});
