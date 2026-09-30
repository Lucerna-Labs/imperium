//! Generate the native operator-key format for an isolated VM test fixture.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: lab_operator_key <new-fixture-path>")?;
    imperium_cli::operator_key::load_or_generate(std::path::Path::new(&path))?;
    Ok(())
}
