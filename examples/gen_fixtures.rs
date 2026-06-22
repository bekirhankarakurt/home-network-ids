//! Regenerates the pcap fixtures in `tests/fixtures/` from `hnids::synth`.
//!
//! ```text
//! cargo run --example gen_fixtures [OUT_DIR]
//! ```

use std::path::PathBuf;

use home_network_ids::synth;

fn main() -> std::io::Result<()> {
    let dir = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from("tests/fixtures"), PathBuf::from);
    std::fs::create_dir_all(&dir)?;
    for (name, generate) in synth::FIXTURES {
        let trace = generate();
        let bytes = synth::encode(name, &trace)?;
        std::fs::write(dir.join(name), &bytes)?;
        println!("{name}: {} frames, {} bytes", trace.len(), bytes.len());
    }
    Ok(())
}
