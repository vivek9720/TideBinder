#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = tidebinder::decode_and_analyze(data);
});
