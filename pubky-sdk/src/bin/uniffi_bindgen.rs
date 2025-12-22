use anyhow::Result;
use std::env;
use std::process::Command;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <language> [output_dir]", args[0]);
        eprintln!("  language: swift or kotlin");
        eprintln!("  output_dir: optional output directory (defaults to generated-<language>/)");
        std::process::exit(1);
    }
    
    let language = &args[1];
    let output_dir = if args.len() > 2 {
        args[2].clone()
    } else {
        format!("generated-{}", language)
    };
    
    let udl_file = "src/pubky_sdk.udl";
    
    println!("Generating {} bindings to {}/", language, output_dir);
    println!("UDL file: {}", udl_file);
    
    let status = Command::new("uniffi-bindgen")
        .args([
            "generate",
            udl_file,
            "--language",
            language,
            "--out-dir",
            &output_dir,
        ])
        .status()?;
    
    if !status.success() {
        eprintln!("uniffi-bindgen failed");
        std::process::exit(1);
    }
    
    println!("✓ Generated {} bindings in {}/", language, output_dir);
    Ok(())
}

