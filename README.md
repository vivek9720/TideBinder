# TideBinder

TideBinder is a Rust decoder for a simulated storm-recovery harbor logistics protocol. It parses multi-section packets carrying a dictionary, berth state, vessel cargo manifests, route topology, telemetry channels, replay journals, and compact query bytecode.

The repository is intended for Fenrir-style fuzzing submissions: it includes cargo-fuzz targets under `fuzz/`, a seed corpus under `fuzz/corpus/`, and a ClusterFuzzLite build script that compiles all fuzz targets into `$OUT` without network access.

## Local checks

```bash
cargo check --locked --offline
cargo check --manifest-path fuzz/Cargo.toml --locked --offline --bins
```

ClusterFuzzLite should run `.clusterfuzzlite/build.sh` from the repository root with `$SRC` and `$OUT` set by the platform.
