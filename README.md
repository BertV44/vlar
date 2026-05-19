# Veeam Log Anonymizer — Rust Edition

High-performance anonymization tool for Veeam Backup & Replication logs, rewritten in Rust for speed and portability.

**Coverage aligned with [Veeam KB2462](https://www.veeam.com/kb2462)** — *Sensitive data types in Veeam Backup & Replication and Veeam Backup for Microsoft 365 log files*.

---

## ⚠ Disclaimer

**This is a community project. It is NOT an official Veeam product and comes with NO official Veeam support.**

- Use at your own risk.
- Always review anonymized output before sharing it with third parties — no detection system is perfect, and false negatives (sensitive data that slipped through) are possible.
- The `--paranoid` flag re-scans output for known entities as a safety net, but it does not guarantee zero leakage.
- The dictionary file (`-D`) contains the full reverse mapping in cleartext. **Never include it in a support bundle.** Use `--dict-output` to write it to a separate directory.
- The author and Veeam Software accept no responsibility for any data leakage, regulatory issue, or operational impact arising from use of this tool.

---

## Author

Bertrand Castagnet — EMEA TAM at Veeam France

---

## Reference work

This tool's detection scope follows the categories listed in [KB2462](https://www.veeam.com/kb2462). The current coverage map is summarized in the table below.

### KB2462 coverage matrix (VBR)

| KB2462 sensitive data type | v2.4 status |
|---|---|
| User names | ✅ DOMAIN\user, .\user, --aggressive naked-user, --user-list |
| Object names (hosts, datastores, VMs, clusters) | ✅ via `--object-list` |
| VM file names and paths | 🟡 backup files only (.vbk/.vib/.vbm/.vrb); generic paths via lists |
| FQDN / Hostname / NetBIOS names | ✅ FQDN via `--aggressive`, short hostnames via `--hostname-list` |
| IPv4 addresses | ✅ |
| IPv6 addresses | ✅ |
| Customer-specific paths to backup files | 🟡 file names yes, path prefix on roadmap |
| Names of backup files | ✅ |
| SharePoint / Exchange / SQL / Oracle / PostgreSQL / MongoDB / SAP HANA | 🟡 DB names via `--db-list` |
| Query execution results | ❌ out of scope (would corrupt logs) |
| SSH host fingerprints | ✅ SHA256, MD5, ssh-rsa/ed25519/ecdsa public keys |
| SSH connection type | ❌ not sensitive |
| SSH scripts/commands output | ❌ not delimitable reliably |
| PEM certificates / private keys / JWT | ✅ |
| MAC addresses | ✅ (bonus — not in KB2462 but recommended) |

---

## Features

- **Fast**: Aho-Corasick literal replacement engine, parallel file processing with rayon, lock-free entity aggregation
- **Portable**: Single static binary, no runtime dependencies
- **Smart**: Strict validation prevents false positives — only real entities are anonymized
- **Consistent**: Same entity always gets the same replacement across all files
- **Reversible**: Export a dictionary, then reverse anonymization when needed
- **Comprehensive**: Detects all KB2462 categories where automatic detection is reliable; explicit lists for the rest
- **Flexible**: Exclude specific entity types with `--exclude`, opt-in aggressive detection with `--aggressive`
- **Safe**: Paranoid re-scan mode + collision detection on generated values

## What's new in v2.4

Major coverage upgrade aligned with [Veeam KB2462](https://www.veeam.com/kb2462):

- **IPv6 addresses** detected and anonymized (preserves loopback, link-local, multicast)
- **MAC addresses** in both colon (`XX:XX:XX:XX:XX:XX`) and compact (`XXXXXXXXXXXX`) formats
- **SSH host fingerprints**: SHA256, MD5, and full ssh-rsa/ed25519/ecdsa public keys
- **Backup file names** (.vbk/.vib/.vbm/.vrb): stem replaced, extension preserved
- **PEM inline** (JSON-escaped `\n` between BEGIN/END): now properly redacted (was missed in v2.3)
- **`--hostname-list FILE`**: explicit list of short hostnames to anonymize
- **`--object-list FILE`**: explicit list of customer object names (VMs, datastores, hosts, clusters)
- **`--db-list FILE`**: explicit list of database names (SQL/Oracle/PostgreSQL/MongoDB/HANA)
- All new types individually toggleable via `--exclude ipv6,mac,ssh-fp,backup-file,hostname,object,db`
- Banner now references KB2462 as scope reference
- Dictionary JSON format extended (backward-compatible via `#[serde(default)]`)

## Previous releases (recap)

- **v2.3**: Aho-Corasick engine (5-10× faster), `--aggressive` for FQDN/naked-user, PEM/JWT redaction, `.\user` local-machine detection
- **v2.2**: Single-pass replacement engine, lock-free parallel scanning, UTF-16 BOM handling, collision-safe generation, `--dict-output`, `--paranoid`, internal-TLD handling

## Installation

### From source

```bash
# Install Rust if needed (1.80+ required for LazyLock)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cd veeam-log-anonymizer
cargo build --release

# Binary: target/release/veeam-log-anonymizer
```

### Pre-built binaries

Download from the [Releases](https://github.com/BertV44/vlar/releases) page. Builds available for Linux (x86_64, ARM64), macOS (Intel, Apple Silicon), and Windows.

## Usage

### Default mode (safe)

```bash
# Single file
veeam-log-anonymizer -i backup.log -o ./output -f

# Directory (recursive)
veeam-log-anonymizer -d /var/log/veeam -o ./anonymized -f -v

# Recommended workflow with separated dictionary and paranoid check
veeam-log-anonymizer -d ./logs -o ./anonymized -f -v -D \
    --dict-output ./keep-safe -s --paranoid
```

### Maximum KB2462 coverage

```bash
# Prepare explicit lists (one entry per line, # for comments)
cat > ~/.vla/users.txt <<EOF
veeamadmin
backup-svc
EOF

cat > ~/.vla/hosts.txt <<EOF
vsa1
backup-srv01
EOF

cat > ~/.vla/objects.txt <<EOF
vm-prod-crm
vm-prod-db
Datastore-Tier1
EOF

cat > ~/.vla/dbs.txt <<EOF
VeeamBackup
ProductionCRM
EOF

# Full anonymization run
veeam-log-anonymizer \
    -d ./logs -o ./anonymized -f -v -D \
    --dict-output ~/.vla/dicts \
    --aggressive --paranoid -s \
    --user-list ~/.vla/users.txt \
    --hostname-list ~/.vla/hosts.txt \
    --object-list ~/.vla/objects.txt \
    --db-list ~/.vla/dbs.txt
```

### Reverse anonymization

```bash
veeam-log-anonymizer --reverse ~/.vla/dicts/veeam-anonymizer-*.json \
    -d ./anonymized -o ./restored -f
```

### Selective exclusion

```bash
# Keep IPs visible (e.g. local-only deployment)
veeam-log-anonymizer -d ./logs -o ./output -f -e ip,ipv6

# Disable PEM redaction (rare — need to inspect certificate chain)
veeam-log-anonymizer -d ./logs -o ./output -f -e pem
```

## Options

| Flag | Long | Description |
|---|---|---|
| `-i` | `--input FILE` | Input log file |
| `-d` | `--directory DIR` | Input directory (recursive) |
| `-o` | `--output DIR` | Output directory (required) |
| `-f` | `--force` | Force overwrite / create directories |
| `-v` | `--verbose` | Show filenames in progress bar |
| `-m` | `--mapping` | Print mapping table to console |
| `-D` | `--dictionary` | Export mapping to JSON file |
|  | `--dict-output DIR` | Write dictionary to a separate directory (recommended) |
| `-s` | `--stats` | Show detailed statistics |
| `-e` | `--exclude TYPES` | Skip entity types (see below) |
|  | `--dry-run` | Preview without writing files |
|  | `--reverse FILE` | De-anonymize using dictionary JSON |
|  | `--paranoid` | Re-scan output files to detect any leaked entities |
|  | `--aggressive` | Enable detection of standalone FQDNs and naked usernames |
|  | `--user-list FILE` | Explicit list of usernames |
|  | `--hostname-list FILE` | Explicit list of short hostnames |
|  | `--object-list FILE` | Explicit list of customer object names (VMs, datastores, hosts) |
|  | `--db-list FILE` | Explicit list of database names |

### `--exclude` accepted types

`email`, `user`, `domain`, `ip`, `ipv6`, `mac`, `ssh-fp`, `backup-file`, `naked-user`, `fqdn`, `hostname`, `object`, `db`, `pem`, `private-key`, `jwt`

## What gets anonymized

### Default (always on, except via `--exclude`)

| Entity | Example | Replacement |
|---|---|---|
| Email addresses | `admin@company.com` | `k8mN2xpQ@rT4wL9mK3nPq.com` |
| Domain\User | `CORP\john.doe` | `aBcDeFgH\iJkLmNoPqR` |
| Local user | `.\veeamadmin` | (anonymized via naked-user channel) |
| Domains (from emails) | `company.com` | `rT4wL9mK3nPq.com` |
| Internal FQDNs | `mail.corp.local` | `rT4wL9mK3nPq.com` |
| IPv4 | `192.168.1.100` | `**.**.1.100` |
| IPv4-mapped IPv6 | `[::ffff:172.16.5.5]` | `[::ffff:**.**.5.5]` |
| **IPv6** | `2a01:cb05:...:aa77` | `****:****:****:****:****:****:****:aa77` |
| **MAC** (colon) | `00:50:56:96:AA:77` | `**:**:**:**:**:77` |
| **MAC** (compact) | `005056962A77` | `**********77` |
| **SSH SHA256** | `SHA256:abc...xyz=` | `SHA256:[REDACTED]` |
| **SSH MD5** | `MD5:ab:cd:...` | `MD5:[REDACTED]` |
| **SSH pubkey** | `ssh-rsa AAAA...` | `ssh-rsa [REDACTED]` |
| **Backup files** | `Job-CRM-2026-05-17.vbk` | `xR4t9pZmK9Lq.vbk` |
| PEM certificates | full block | `BEGIN/END preserved, body redacted` |
| PEM private keys | full block | `[REDACTED RSA PRIVATE KEY]` |
| JWT tokens | `eyJ...` | `[REDACTED JWT]` |

### Aggressive mode (`--aggressive`)

| Entity | Example | Replacement |
|---|---|---|
| Naked usernames | `User: veeamadmin` | `User: xRyZ8vMqWp` |
| Naked usernames | `Account: jdoe` | `Account: aB3kLm9PqR` |
| Standalone FQDNs | `k10-route.apps.cluster.home` | `xR4t9pZ.anon.home` |

### Explicit lists (no auto-detection — provide your own)

| Source | Replacement format |
|---|---|
| `--hostname-list` | `host-XXXXXX` |
| `--object-list` | `obj-XXXXXXXX` |
| `--db-list` | `db-XXXXXXXX` |
| `--user-list` | naked-user channel |

### Always preserved

- VMware vSphere versions (`7.x.x.x`, `8.x.x.x`)
- VBR/Kasten product versions (e.g. `12.1.0.2131`)
- Loopback (`127.0.0.1`, `::1`)
- Link-local (`169.254.x.x`, `fe80::/10`)
- Broadcast, multicast (IPv4 224-239, IPv6 `ff::/8`)
- All timestamps, log levels, and non-sensitive text
- System accounts (SYSTEM, Administrator, LocalService, etc.)
- Technical terms and Veeam service names

## Recommended support workflow

```bash
# 1. Anonymize with maximum coverage; dictionary in a SEPARATE private dir
veeam-log-anonymizer \
    -d ./logs -o ./anonymized -f -D \
    --dict-output ~/private/veeam-dicts \
    --aggressive --paranoid \
    --user-list ~/.vla/users.txt \
    --hostname-list ~/.vla/hosts.txt \
    --object-list ~/.vla/objects.txt \
    --db-list ~/.vla/dbs.txt

# 2. Verify --paranoid reports zero leaks. If not, review and re-run.
#    Add the leaked entries to the appropriate list and re-run.

# 3. Bundle and send ONLY the ./anonymized directory to support.
#    Do NOT include the dictionary file.

# 4. When support pinpoints an issue, reverse to see real values locally
veeam-log-anonymizer --reverse ~/private/veeam-dicts/veeam-anonymizer-*.json \
    -d ./anonymized -o ./restored -f
```

## Known limitations

- **Auto-detection is regex-based** — sophisticated obfuscation, custom log formats, or unexpected encoding may cause false negatives. Use explicit lists for known-sensitive items + `--paranoid` + manual review for sensitive cases.
- **Query execution results** (KB2462) are not anonymized: they are arbitrary text and any regex would either miss them or corrupt valid log content. Manual review or pre-processing required.
- **PostgreSQL/SQL/Oracle/Mongo/Hana DB content** beyond names: same caveat.
- **Generated replacements** use a non-cryptographic PRNG (`rand::thread_rng`, ChaCha12 in rand 0.8). Adequate for anonymization, **not** for cryptographic privacy guarantees.
- **The dictionary file is unencrypted**. Treat it like a credential.
- Very large files (>1 GB) are read into memory. Consider splitting beforehand.
- FQDN auto-detection requires a recognized TLD whitelist; unknown internal TLDs require `--hostname-list`.

## Development

```bash
make check          # Format + lint + test (CI equivalent)
make release        # Optimized build
make demo           # Quick visual test
make build-all      # Cross-compile for all platforms
make install        # Install to ~/.cargo/bin
```

## License

MIT License. No warranty, express or implied. See `LICENSE`.

This tool is informed by — but not endorsed by — Veeam Software. The list of sensitive data types this tool aims to detect is based on the public Veeam Knowledge Base article [KB2462](https://www.veeam.com/kb2462).
