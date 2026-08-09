use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use jnic_emulator::{AnalysisConfig, analyze_path, render_report};

#[derive(Debug, Parser)]
#[command(
    name = "jnic-emulator",
    author = "malidev",
    version,
    about = "Safely inspect JNIC-protected JARs and x86-64 PE payloads"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse a JAR/PE and write a controlled static-emulation report.
    Analyze {
        /// Input JAR, ZIP, DLL, or PE file.
        input: PathBuf,
        /// Destination for the text report.
        #[arg(short, long, default_value = "analysis.txt")]
        output: PathBuf,
        /// Maximum accepted input size in MiB.
        #[arg(long, default_value_t = 1024)]
        max_input_mib: u64,
        /// Maximum uncompressed JAR-member size in MiB.
        #[arg(long, default_value_t = 512)]
        max_entry_mib: u64,
        /// Maximum decoded native-resource size in MiB.
        #[arg(long, default_value_t = 1024)]
        max_decoded_mib: u64,
        /// Maximum x86 instructions decoded for each mapped method.
        #[arg(long, default_value_t = 250_000)]
        max_method_instructions: usize,
        /// Maximum control-flow states explored for each mapped method.
        #[arg(long, default_value_t = 25_000)]
        max_path_states: usize,
    },
    /// Run deterministic parser and ABI checks.
    SelfTest,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[!] Analysis failed safely: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Analyze {
            input,
            output,
            max_input_mib,
            max_entry_mib,
            max_decoded_mib,
            max_method_instructions,
            max_path_states,
        } => {
            ensure!(
                input != output,
                "output path must differ from the input path"
            );
            ensure!(
                max_method_instructions > 0,
                "instruction limit must be nonzero"
            );
            ensure!(max_path_states > 0, "path-state limit must be nonzero");
            let mib = 1024_u64 * 1024;
            let config = AnalysisConfig {
                max_input_bytes: max_input_mib
                    .checked_mul(mib)
                    .context("input limit overflow")?,
                max_entry_bytes: max_entry_mib
                    .checked_mul(mib)
                    .context("entry limit overflow")?,
                max_decoded_resource_bytes: max_decoded_mib
                    .checked_mul(mib)
                    .context("decoded-resource limit overflow")?,
                trace: jnic_emulator::emulator::TraceConfig {
                    max_instructions_per_method: max_method_instructions,
                    max_path_states,
                    ..Default::default()
                },
            };
            println!("[*] Parsing input as inert data: {}", input.display());
            println!("[*] Target machine code will not be loaded or invoked.");
            let model = analyze_path(&input, config)?;
            let report = render_report(&model);
            std::fs::write(&output, report)
                .with_context(|| format!("cannot write report {}", output.display()))?;
            let methods = model
                .mappings
                .iter()
                .map(|mapping| mapping.methods.len())
                .sum::<usize>();
            let mapped = model
                .mappings
                .iter()
                .flat_map(|mapping| &mapping.methods)
                .filter(|method| method.native_rva.is_some())
                .count();
            println!("[+] Report written: {}", output.display());
            println!(
                "[+] Classes: {} | Methods: {methods} | Mapped: {mapped} | Warnings: {}",
                model.mappings.len(),
                model.warnings.len()
            );
        }
        Command::SelfTest => {
            let descriptor = jnic_emulator::descriptor::parse_method_descriptor(
                "(ILjava/lang/String;[[B)Ljava/util/List;",
            )?;
            ensure!(
                descriptor.parameters.len() == 3,
                "descriptor self-test failed"
            );
            ensure!(
                jnic_emulator::jni::function_name(228) == Some("ExceptionCheck"),
                "JNI ABI self-test failed"
            );
            ensure!(
                jnic_emulator::pe::decode_jni_export_class(
                    "Java_example_nativebridge_Entry__00024jnicLoader"
                ) == Some("example/nativebridge/Entry".to_owned()),
                "JNI export decoder self-test failed"
            );
            println!("[OK] jnic-emulator self-test");
        }
    }
    Ok(())
}
