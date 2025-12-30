# Veeam Log Anonymizer

A high-performance log anonymization tool for Veeam Backup & Replication logs. Protects sensitive information in log files before sharing for support or analysis.

## Features

- **⚡ High Performance**: Parallel file processing and Aho-Corasick multi-pattern matching
- **📦 Single Binary**: No runtime dependencies, just download and run
- **🔒 Comprehensive**: Anonymizes IPs, domains, emails, usernames, paths, and more
- **🎯 Smart Detection**: Automatically identifies sensitive entities in logs
- **📊 Consistent**: Same entities get the same anonymized values within a session
- **🔄 Reproducible**: Import/export mapping dictionaries for consistent re-runs

## Installation

### From Source

```bash
git clone https://github.com/yourusername/veeam-log-anonymizer.git
cd veeam-log-anonymizer
cargo build --release

# Binary location: target/release/veeam-log-anonymizer
```

### Pre-built Binaries

Download from the [Releases](https://github.com/yourusername/veeam-log-anonymizer/releases) page.

## Usage

```bash
# Anonymize a single log file
veeam-log-anonymizer -i /path/to/file.log -o /path/to/output

# Anonymize all log files in a directory (recursive)
veeam-log-anonymizer -d /path/to/logs -o /path/to/output -f

# Export mapping dictionary and show statistics
veeam-log-anonymizer -d /logs -o /output -f -D -s

# Use existing mapping for consistent anonymization
veeam-log-anonymizer -d /logs -o /output --import previous-mapping.json
```

### Command Line Options

| Option | Long | Description |
|--------|------|-------------|
| `-i` | `--input` | Input log file |
| `-d` | `--directory` | Input directory (recursive) |
| `-o` | `--output` | Output directory (required) |
| `-f` | `--force` | Force overwrite / create directories |
| `-m` | `--mapping` | Display mapping table |
| `-v` | `--verbose` | Verbose output (file-by-file) |
| `-D` | `--dictionary` | Export JSON mapping dictionary |
| `-s` | `--stats` | Show detailed statistics |
| `-e` | `--extension` | File extensions to process (default: log) |
| | `--import` | Import existing mapping file |
| | `--no-progress` | Disable progress bar |

## What Gets Anonymized

| Entity Type | Example Original | Example Anonymized |
|-------------|------------------|-------------------|
| IPv4 Address | `192.168.1.100` | `**.**.1.100` |
| Email | `admin@corp.local` | `ab3xk9mn@srv-kx9nm2.local` |
| Domain | `corp.example.com` | `node-pq4wz8.local` |
| User Account | `DOMAIN\admin` | `DOMAIN\user_rp3kx9nm` |
| vCenter | `vcenter.corp.local` | `srv-wz4vb8` |
| ESXi Host | `esxi01.corp.local` | `host-qp2kx9` |
| Hyper-V Host | `hvhost01` | `node-yz7wv4` |
| SMTP Server | `mail.corp.local` | `sys-nm8qp2` |
| VM Name | `production-db` | `vm-kx9nm2pq` |
| Datastore | `SAN-LUN01` | `datastore-pq4wz8` |
| UNC Path | `\\server\share\folder` | `\\server\share\Px9Km2` |

### Preserved Values

The following are **not** anonymized to preserve log readability:

- **Version strings**: `7.0.3.0`, `8.0.1.0` (VMware versions)
- **Loopback addresses**: `127.0.0.1`
- **Link-local addresses**: `169.254.x.x`
- **Broadcast addresses**: `255.255.255.255`

## JSON Dictionary Output

When using `-D`, a timestamped JSON file is created:

```json
{
  "metadata": {
    "version": "1.0.0",
    "created_at": "2024-01-15T10:30:00+00:00",
    "files_processed": 42,
    "total_entities": 156
  },
  "mappings": {
    "user_accounts": [
      {"original": "administrator", "anonymized": "user_kx9nm2pq"}
    ],
    "vcenter_servers": [
      {"original": "vcenter01", "anonymized": "srv-rp3kx9nm"}
    ],
    "domains": [
      {"original": "corp.local", "anonymized": "host-yz7wv4nm.local"}
    ]
  }
}
```

## Library Usage

Use as a library in your own Rust projects:

```rust
use veeam_log_anonymizer::{Anonymizer, AnonymizerConfig};
use std::path::Path;

let config = AnonymizerConfig {
    force_overwrite: true,
    show_progress: false,
    ..Default::default()
};

let mut anonymizer = Anonymizer::new(config)?;
let files = anonymizer.collect_input_files(Path::new("/logs"))?;
anonymizer.scan_files(&files)?;
anonymizer.process_files(&files, Path::new("/logs"), Path::new("/output"))?;

// Access mapping table
for entity in anonymizer.mapping().iter() {
    println!("{}: {} → {}", entity.entity_type, entity.original, entity.anonymized);
}
```

## Cross-Platform Building

```bash
# Linux (default)
cargo build --release

# Windows
cargo build --release --target x86_64-pc-windows-gnu

# macOS
cargo build --release --target x86_64-apple-darwin

# macOS Apple Silicon
cargo build --release --target aarch64-apple-darwin
```

## Performance

The tool is optimized for processing large log directories:

- **Parallel scanning**: Utilizes all CPU cores for file analysis
- **Aho-Corasick algorithm**: O(n) multi-pattern matching regardless of pattern count
- **Single-pass processing**: Each file is read once and written once
- **Memory efficient**: Streaming processing for large files

Typical performance: **50-200 MB/s** depending on hardware and pattern density.

## License

MIT License - See [LICENSE](LICENSE) file.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
