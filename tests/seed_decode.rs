#[test]
fn packet_seed_decodes() {
    let data = include_bytes!("../fuzz/corpus/packet_fuzzer/valid_port_recovery.tbin");
    let report = tidebinder::decode_and_analyze(data).expect("packet seed should decode");
    assert!(report.accepted_sections >= 6);
}

#[test]
fn stream_seed_reassembles() {
    let data = include_bytes!("../fuzz/corpus/stream_fuzzer/reassembled_packet.tstr");
    let report = tidebinder::decode_stream(data).expect("stream seed should decode");
    assert!(report.accepted_sections >= 6);
}

#[test]
fn bundle_seed_decodes() {
    let data = include_bytes!("../fuzz/corpus/bundle_fuzzer/two_packet_bundle.tbdl");
    let report = tidebinder::decode_bundle_bytes(data).expect("bundle seed should decode");
    assert!(report.accepted_sections >= 12);
}

#[test]
fn journal_seed_replays() {
    let data = include_bytes!("../fuzz/corpus/journal_fuzzer/recovery_journal.bin");
    let score = tidebinder::replay_journal_bytes(data).expect("journal seed should replay");
    assert_ne!(score, 0);
}

#[test]
fn script_seed_runs() {
    let data = include_bytes!("../fuzz/corpus/script_fuzzer/berth_query.tqbc");
    let score = tidebinder::run_script_bytes(data).expect("script seed should run");
    assert_ne!(score, 0);
}
