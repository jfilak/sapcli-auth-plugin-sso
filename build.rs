use vergen_gitcl::{Emitter, GitclBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure which git metrics you want to extract
    let git = GitclBuilder::default()
        .sha(true)       // Enables VERGEN_GIT_SHA
        .branch(true)    // Enables VERGEN_GIT_BRANCH
        .build()?;

    // Emit the cargo:rustc-env instructions
    Emitter::default()
        .add_instructions(&git)?
        .emit()?;

    Ok(())
}