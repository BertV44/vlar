//! Veeam Log Anonymizer CLI
//!
//! Command-line interface for anonymizing Veeam Backup & Replication logs.

use chrono::Local;
use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;
use veeam_log_anonymizer::{Anonymizer, AnonymizerConfig, AnonymizerError};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const BANNER: &str = r#"
╦  ╦┌─┐┌─┐┌─┐┌┬┐  ╦  ┌─┐┌─┐  ╔═╗┌┐┌┌─┐┌┐┌┬ ┬┌┬┐┬┌─┐┌─┐┬─┐
╚╗╔╝├┤ ├┤ ├─┤│││  ║  │ ││ ┬  ╠═╣││││ ││││└┬┘│││││┌─┘├┤ ├┬┘
 ╚╝ └─┘└─┘┴ ┴┴ ┴  ╩═╝└─┘└─┘  ╩ ╩┘└┘└─┘┘└┘ ┴ ┴ ┴┴└└─┘└─┘┴└─
"#;

/// High-performance log anonymization tool for Veeam Backup & Replication
#[derive(Parser, Debug)]
#[command(name = "veeam-log-anonymizer")]
#[command(version = VERSION)]
#[command(about = "Anonymize Veeam Backup & Replication logs", long_about = None)]
#[command(after_help = "EXAMPLES:
    # Anonymize a single log file
    veeam-log-anonymizer -i backup.log -o ./output

    # Anonymize all logs in a directory
    veeam-log-anonymizer -d /var/log/veeam -o ./anonymized -f

    # Export mapping dictionary and show verbose output
    veeam-log-anonymizer -d ./logs -o ./output -f -D -v

    # Use existing mapping for consistent anonymization
    veeam-log-anonymizer -d ./logs -o ./output --import mapping.json
")]
struct Cli {
    /// Input log file
    #[arg(short = 'i', long = "input", group = "input_source", value_name = "FILE")]
    input_file: Option<PathBuf>,

    /// Input directory containing log files (recursive)
    #[arg(short = 'd', long = "directory", group = "input_source", value_name = "DIR")]
    input_directory: Option<PathBuf>,

    /// Output directory for anonymized files
    #[arg(short = 'o', long = "output", required = true, value_name = "DIR")]
    output_directory: PathBuf,

    /// Force overwrite existing files and create directories
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Display the mapping table of anonymized entities
    #[arg(short = 'm', long = "mapping")]
    mapping: bool,

    /// Show verbose output with file-by-file progress
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Export JSON dictionary of all anonymized mappings
    #[arg(short = 'D', long = "dictionary")]
    dictionary: bool,

    /// Import existing mapping file for consistent anonymization
    #[arg(long = "import", value_name = "FILE")]
    import_mapping: Option<PathBuf>,

    /// File extensions to process (default: log)
    #[arg(short = 'e', long = "extension", value_name = "EXT")]
    extensions: Vec<String>,

    /// Disable progress bar
    #[arg(long = "no-progress")]
    no_progress: bool,

    /// Show detailed statistics
    #[arg(short = 's', long = "stats")]
    stats: bool,
}

fn main() {
    // Print banner
    println!("{}", BANNER);
    println!("  Version {}", VERSION);
    println!();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Validate input source
    let input_path = match (&cli.input_file, &cli.input_directory) {
        (Some(file), None) => file.clone(),
        (None, Some(dir)) => dir.clone(),
        (None, None) => {
            eprintln!("Error: You must specify either -i/--input or -d/--directory");
            std::process::exit(1);
        }
        (Some(_), Some(_)) => {
            eprintln!("Error: Cannot specify both -i/--input and -d/--directory");
            std::process::exit(1);
        }
    };

    // Run anonymization
    if let Err(e) = run(cli, input_path) {
        eprintln!("\n✗ Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli, input_path: PathBuf) -> Result<(), AnonymizerError> {
    let start = Instant::now();

    // Build configuration
    let extensions = if cli.extensions.is_empty() {
        vec!["log".to_string()]
    } else {
        cli.extensions
    };

    let config = AnonymizerConfig {
        force_overwrite: cli.force,
        verbose: cli.verbose,
        export_dictionary: cli.dictionary,
        show_mapping: cli.mapping,
        show_progress: !cli.no_progress && !cli.verbose,
        import_mapping: cli.import_mapping,
        extensions,
    };

    // Create anonymizer
    let mut anonymizer = Anonymizer::new(config.clone())?;

    // Phase 1: Collect input files
    println!("┌─ Collecting Files");
    let files = anonymizer.collect_input_files(&input_path)?;
    println!("│  Found {} file(s)", files.len());
    println!("└─ Done\n");

    // Phase 2: Scan and extract entities
    println!("┌─ Scanning for Entities");
    let scan_stats = anonymizer.scan_files(&files)?;
    println!("│  Discovered {} unique entities", scan_stats.entities_found);

    // Show detailed stats if requested
    if cli.stats {
        anonymizer.mapping().print_stats();
    }
    println!("└─ Done\n");

    // Show mapping table if requested
    if cli.mapping {
        println!("┌─ Mapping Table");
        anonymizer.mapping().print_mapping();
        println!("└─ End Mapping\n");
    }

    // Export dictionary if requested
    if cli.dictionary {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let dict_filename = format!("veeam-anonymizer-{}.json", timestamp);
        let dict_path = cli.output_directory.join(&dict_filename);

        // Ensure output directory exists
        if !cli.output_directory.exists() && cli.force {
            std::fs::create_dir_all(&cli.output_directory).map_err(|e| {
                AnonymizerError::DirCreationError {
                    path: cli.output_directory.clone(),
                    source: e,
                }
            })?;
        }

        anonymizer
            .mapping()
            .export_to_json(&dict_path, files.len())
            .map_err(|e| AnonymizerError::WriteError {
                path: dict_path.clone(),
                source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
            })?;

        println!("┌─ Dictionary Exported");
        println!("│  {}", dict_path.display());
        println!("└─ Done\n");
    }

    // Phase 3: Process and anonymize files
    println!("┌─ Anonymizing Files");
    let process_stats = anonymizer.process_files(&files, &input_path, &cli.output_directory)?;

    if process_stats.files_skipped > 0 {
        println!(
            "│  ⚠ Skipped {} file(s) due to errors",
            process_stats.files_skipped
        );
    }
    println!("└─ Done\n");

    // Print summary
    let elapsed = start.elapsed();
    let throughput = if elapsed.as_secs_f64() > 0.0 {
        process_stats.bytes_processed_mb() / elapsed.as_secs_f64()
    } else {
        0.0
    };

    println!("═══════════════════════════════════════");
    println!("  Summary");
    println!("═══════════════════════════════════════");
    println!("  Files processed:  {}", process_stats.files_processed);
    println!("  Data processed:   {:.2} MB", process_stats.bytes_processed_mb());
    println!("  Entities found:   {}", process_stats.entities_found);
    println!("  Time elapsed:     {:.2?}", elapsed);
    println!("  Throughput:       {:.1} MB/s", throughput);
    println!("  Output directory: {}", cli.output_directory.display());
    println!("═══════════════════════════════════════");
    println!("\n✓ Anonymization complete!");

    Ok(())
}
