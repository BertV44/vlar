//! Integration tests — run the compiled binary end-to-end
//! Run with: cargo test --test integration_test

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn bin() -> String {
    env!("CARGO_BIN_EXE_veeam-log-anonymizer").to_string()
}

fn run(args: &[&str]) -> std::process::Output {
    std::process::Command::new(bin())
        .args(args)
        .output()
        .expect("Failed to run binary")
}

/// Run the binary with extra environment variables set.
fn run_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = std::process::Command::new(bin());
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("Failed to run binary")
}

/// Create a `.zip` at `path` from (entry_name, contents) pairs.
fn make_zip(path: &Path, entries: &[(&str, &str)]) {
    use std::io::Write;
    let file = fs::File::create(path).unwrap();
    let mut zw = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in entries {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(content.as_bytes()).unwrap();
    }
    zw.finish().unwrap();
}

/// Read a `.zip` into a sorted list of (entry_name, contents) for files.
fn read_zip(path: &Path) -> Vec<(String, String)> {
    use std::io::Read;
    let file = fs::File::open(path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let mut e = archive.by_index(i).unwrap();
        if e.is_file() {
            let name = e.name().to_string();
            let mut s = String::new();
            let _ = e.read_to_string(&mut s);
            out.push((name, s));
        }
    }
    out.sort();
    out
}

/// Recursively collect every file path under `dir`.
fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.extend(collect_files(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

/// Relative-to-`base` path strings of every file under `base` (slash-normalized).
fn rel_paths(base: &Path) -> Vec<String> {
    collect_files(base)
        .iter()
        .map(|p| {
            p.strip_prefix(base)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn full_pipeline_single_file() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    let log = r#"[2025-01-15 08:30:01] Starting backup job
[2025-01-15 08:30:02] Connecting to vCenter at 192.168.10.50
[2025-01-15 08:30:03] Authenticated as CORP\john.doe
[2025-01-15 08:30:04] Notification sent to john.doe@company.com
[2025-01-15 08:30:05] Backup target: 10.0.0.100
[2025-01-15 08:30:06] VMware vSphere 8.0.3.0 detected
[2025-01-15 08:30:07] Localhost check: 127.0.0.1
[2025-01-15 08:30:08] Job completed successfully
"#;
    let input_path = input_dir.path().join("backup.log");
    fs::write(&input_path, log).unwrap();

    let out = run(&[
        "-i",
        input_path.to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "-D",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let output = fs::read_to_string(output_dir.path().join("backup.log")).unwrap();

    // Sensitive data MUST be removed
    assert!(
        !output.contains("john.doe@company.com"),
        "Email must be anonymized"
    );
    assert!(!output.contains("192.168.10.50"), "IP must be anonymized");
    assert!(!output.contains("10.0.0.100"), "IP must be anonymized");

    // Non-sensitive MUST be preserved
    assert!(
        output.contains("8.0.3.0"),
        "VMware version must be preserved"
    );
    assert!(output.contains("127.0.0.1"), "Loopback must be preserved");
    assert!(
        output.contains("Starting backup job"),
        "Log text must be preserved"
    );
    assert!(
        output.contains("[2025-01-15 08:30:01]"),
        "Timestamps must be preserved"
    );

    // Dictionary file must exist
    let dict_exists = fs::read_dir(output_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with("veeam-anonymizer") && n.ends_with(".json"))
                .unwrap_or(false)
        });
    assert!(dict_exists, "Dictionary JSON must be created with -D");
}

#[test]
fn directory_mode_recursive() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    let sub = input_dir.path().join("sub");
    fs::create_dir_all(&sub).unwrap();

    fs::write(
        input_dir.path().join("root.log"),
        "[2025-01-01] admin@test.org from 192.168.1.1\n",
    )
    .unwrap();
    fs::write(
        sub.join("nested.log"),
        "[2025-01-01] admin@test.org from 10.10.10.10\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(out.status.success());

    assert!(output_dir.path().join("root.log").exists());
    assert!(output_dir.path().join("sub/nested.log").exists());

    let out_a = fs::read_to_string(output_dir.path().join("root.log")).unwrap();
    let out_b = fs::read_to_string(output_dir.path().join("sub/nested.log")).unwrap();

    assert!(!out_a.contains("admin@test.org"));
    assert!(!out_b.contains("admin@test.org"));
}

#[test]
fn no_overwrite_without_force() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(input_dir.path().join("test.log"), "test@example.com\n").unwrap();
    fs::write(output_dir.path().join("test.log"), "existing").unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "Should fail without -f");

    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert_eq!(content, "existing", "Should not overwrite");
}

#[test]
fn dry_run_no_output() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "admin@example.com 10.0.0.1\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--dry-run",
    ]);
    assert!(out.status.success());
    assert!(
        !output_dir.path().join("test.log").exists(),
        "Dry run must not write files"
    );
}

#[test]
fn exclude_ip_preserves_ips() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "admin@company.com from 192.168.1.100\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--exclude",
        "ip",
    ]);
    assert!(out.status.success());

    let output = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        output.contains("192.168.1.100"),
        "IP should be preserved when excluded"
    );
    assert!(
        !output.contains("admin@company.com"),
        "Email should still be anonymized"
    );
}

#[test]
fn exclude_email_preserves_emails() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "admin@company.com from 192.168.1.100\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--exclude",
        "email,domain",
    ]);
    assert!(out.status.success());

    let output = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        output.contains("admin@company.com"),
        "Email should be preserved"
    );
    assert!(
        !output.contains("192.168.1.100"),
        "IP should still be anonymized"
    );
}

// ─── #14: --exclude domain / --exclude email, and their domain overlap ───
//
// `domain` is only ever discovered as the second half of an email address
// (see extract_entities_of_kind / README "Domains (from emails)"), and the
// same domain string is then replaced everywhere it appears — bare or not —
// so the same organization always maps to the same anonymized name. That
// overlap is exactly what #14 tripped over: build_map's email-replacement
// step re-manufactured a domain mapping the exclusion filter had just
// emptied, so `-e domain` got silently undone the moment the domain also
// showed up in an email (the ordinary case).

#[test]
fn exclude_domain_preserves_standalone_domain_seen_only_via_email() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "mail admin@acme-corp.com\nbare acme-corp.com alone\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--exclude",
        "domain",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Skipped 1 domain(s) (excluded)"),
        "the skip line should still fire: {stderr}"
    );
    assert!(
        !stderr.contains("1 domains"),
        "the \"Found:\" summary must not report a domain right after saying \
         it was skipped — that contradiction is the #14 symptom: {stderr}"
    );

    let output = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        output.contains("bare acme-corp.com alone"),
        "the standalone domain --exclude domain was asked to preserve must \
         survive untouched, got: {output}"
    );
    assert!(
        output.ends_with("@acme-corp.com\n") || output.contains("@acme-corp.com\n"),
        "the domain half of the (still-anonymized) email must also be left \
         alone once domain is excluded, got: {output}"
    );
    assert!(
        !output.contains("admin@acme-corp.com"),
        "email is NOT excluded here, so its local part must still be \
         anonymized — only the domain half is protected, got: {output}"
    );
}

#[test]
fn exclude_email_preserves_whole_address_domain_still_anonymized_standalone() {
    // Decision for #14's "related, milder" half: `-e email` preserves the
    // entire address, local part and domain both — a half-rewritten address
    // (local part kept, domain replaced) is neither anonymized nor readable,
    // which is worse than either. A domain that shows up *outside* an
    // excluded email is a separate occurrence and is still anonymized when
    // `domain` itself isn't also excluded — the two flags stay independent.
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "mail admin@acme-corp.com\nbare acme-corp.com alone\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--exclude",
        "email",
    ]);
    assert!(out.status.success());

    let output = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    let mut lines = output.lines();
    let mail_line = lines.next().unwrap();
    let bare_line = lines.next().unwrap();

    assert_eq!(
        mail_line, "mail admin@acme-corp.com",
        "excluded email must survive byte-for-byte, including its domain half"
    );
    assert_ne!(
        bare_line, "bare acme-corp.com alone",
        "the standalone domain is a different occurrence and must still be \
         anonymized since -e email doesn't exclude domain"
    );
    assert!(
        bare_line.ends_with(".com alone"),
        "anonymized domain should keep the .com-style shape, got: {bare_line}"
    );
}

#[test]
fn exclude_domain_and_email_preserves_both() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "mail admin@acme-corp.com\nbare acme-corp.com alone\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--exclude",
        "domain,email",
    ]);
    assert!(out.status.success());

    let output = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert_eq!(
        output, "mail admin@acme-corp.com\nbare acme-corp.com alone\n",
        "combining both exclusions must fully preserve the input"
    );
}

#[test]
fn no_exclusion_still_anonymizes_domain_consistently_bare_and_via_email() {
    // Baseline: with no --exclude in force, the email's domain half and the
    // standalone occurrence of the same domain must still both be replaced,
    // and with the *same* generated value — that consistency (STEP 1's
    // "single source of truth") must survive the #14 fix untouched.
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "mail admin@acme-corp.com\nbare acme-corp.com alone\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(out.status.success());

    let output = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !output.contains("acme-corp.com"),
        "with nothing excluded, every occurrence of the domain must be \
         anonymized, got: {output}"
    );
    let mut lines = output.lines();
    let mail_line = lines.next().unwrap();
    let bare_line = lines.next().unwrap();
    let mail_domain = mail_line.rsplit('@').next().unwrap();
    let bare_domain = bare_line
        .strip_prefix("bare ")
        .unwrap()
        .strip_suffix(" alone")
        .unwrap();
    assert_eq!(
        mail_domain, bare_domain,
        "the email's domain and the standalone domain must get the identical \
         replacement: {mail_line} vs {bare_line}"
    );
}

#[test]
fn exclude_invalid_type_fails() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(input_dir.path().join("test.log"), "test\n").unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "--exclude",
        "foobar",
    ]);
    assert!(!out.status.success(), "Should fail on invalid entity type");
}

#[test]
fn empty_file_handled() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(input_dir.path().join("empty.log"), "").unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("empty.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        out.status.success(),
        "Empty files should be handled gracefully"
    );
}

#[test]
fn stats_flag_works() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "admin@example.com 192.168.1.1\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "-s",
    ]);
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Statistics"),
        "Stats should be printed with -s"
    );
}

// ── v2.2 features ───────────────────────────────────────

#[test]
fn dict_output_separate_directory() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let dict_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "admin@company.com from 192.168.1.100\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "-D",
        "--dict-output",
        dict_dir.path().to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Dictionary should be in dict_dir, NOT in output_dir
    let in_dict_dir = fs::read_dir(dict_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with("veeam-anonymizer") && n.ends_with(".json"))
                .unwrap_or(false)
        });
    let in_output_dir = fs::read_dir(output_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with("veeam-anonymizer") && n.ends_with(".json"))
                .unwrap_or(false)
        });
    assert!(in_dict_dir, "Dict must be in --dict-output directory");
    assert!(!in_output_dir, "Dict must NOT leak into output directory");
}

#[test]
fn dict_in_output_emits_warning() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(input_dir.path().join("test.log"), "admin@company.com\n").unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "-D",
    ]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("WARNING") || stderr.contains("warning"),
        "Should warn when dict is inside output. stderr: {}",
        stderr
    );
}

#[test]
fn paranoid_mode_passes_on_clean_output() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "admin@company.com from 192.168.1.100 user CORP\\jdoe\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--paranoid",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Paranoid check") || stdout.contains("no leaked"),
        "Should report paranoid check result. stdout: {}",
        stdout
    );
}

#[test]
fn community_disclaimer_in_output() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(input_dir.path().join("test.log"), "x\n").unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("COMMUNITY") || stdout.contains("community"),
        "Banner must display community-project disclaimer"
    );
}

// ── v2.3 features ───────────────────────────────────────

#[test]
fn local_user_detected_by_default() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "Created by .\\veeamadmin at 17/03/2026 17:31.\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--paranoid",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let anonymized = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !anonymized.contains("veeamadmin"),
        "'.\\veeamadmin' should be anonymized by default. Got: {}",
        anonymized
    );
}

#[test]
fn aggressive_mode_detects_naked_user() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "[User: veeamadmin][GET] request to /api/v1/serverTime\n",
    )
    .unwrap();

    // Without --aggressive: leaks
    let out_off = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(out_off.status.success());
    let off_content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        off_content.contains("veeamadmin"),
        "Without --aggressive, naked user remains"
    );

    // With --aggressive: anonymized
    let output_dir2 = TempDir::new().unwrap();
    let out_on = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir2.path().to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        out_on.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_on.stderr)
    );
    let on_content = fs::read_to_string(output_dir2.path().join("test.log")).unwrap();
    assert!(
        !on_content.contains("veeamadmin"),
        "With --aggressive: {}",
        on_content
    );
}

#[test]
fn user_list_captures_explicit_names() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let user_list = TempDir::new().unwrap();
    let user_list_file = user_list.path().join("users.txt");

    fs::write(
        &user_list_file,
        "bcastagnet\nveeamadmin\n# comment line\n\n",
    )
    .unwrap();
    fs::write(
        input_dir.path().join("test.log"),
        "Job started by bcastagnet on console at 10:00\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--user-list",
        user_list_file.to_str().unwrap(),
        "--paranoid",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !content.contains("bcastagnet"),
        "User-list entry must be anonymized. Got: {}",
        content
    );
}

#[test]
fn pem_certificate_redacted_by_default() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    let pem = "Cert: -----BEGIN CERTIFICATE-----\n\
               MIIDVzCCAj+gAwIBAgIIaJH88lPDzA0wDQYJKoZIhvcNAQELBQAw\n\
               DTE5MDcwMTAwMDAwMFoXDTI3MDcwMTAwMDAwMFowGzEZMBcGA1UE\n\
               -----END CERTIFICATE-----\nDone.";
    fs::write(input_dir.path().join("test.log"), pem).unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(out.status.success());
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        content.contains("-----BEGIN CERTIFICATE-----"),
        "BEGIN marker preserved"
    );
    assert!(
        content.contains("-----END CERTIFICATE-----"),
        "END marker preserved"
    );
    assert!(
        content.contains("[REDACTED CONTENT]"),
        "Body must be redacted. Got: {}",
        content
    );
    assert!(!content.contains("MIIDVzCC"), "Base64 body must be removed");
}

#[test]
fn pem_private_key_fully_redacted() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    let key = "-----BEGIN RSA PRIVATE KEY-----\n\
               THIS_IS_SECRET_KEY_MATERIAL_DO_NOT_LEAK\n\
               -----END RSA PRIVATE KEY-----";
    fs::write(input_dir.path().join("test.log"), key).unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(out.status.success());
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !content.contains("THIS_IS_SECRET"),
        "Key material must be gone. Got: {}",
        content
    );
    assert!(
        content.contains("[REDACTED"),
        "Should leave a redaction marker"
    );
}

#[test]
fn jwt_redacted_by_default() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    let jwt = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n";
    fs::write(input_dir.path().join("test.log"), jwt).unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(out.status.success());
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        content.contains("[REDACTED JWT]"),
        "JWT must be redacted. Got: {}",
        content
    );
    assert!(
        !content.contains("eyJhbGciOiJIUzI1NiIs"),
        "Token body must be removed"
    );
}

#[test]
fn aggressive_detects_standalone_fqdn() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "Connecting to k10-route.apps.cluster.home over HTTPS\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !content.contains("k10-route.apps.cluster.home"),
        "FQDN must be anonymized. Got: {}",
        content
    );
}

#[test]
fn exclude_pem_keeps_certificate() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    let pem = "-----BEGIN CERTIFICATE-----\nMIIDVzCC\n-----END CERTIFICATE-----";
    fs::write(input_dir.path().join("test.log"), pem).unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--exclude",
        "pem",
    ]);
    assert!(out.status.success());
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(content.contains("MIIDVzCC"), "Excluded PEM stays intact");
}

#[test]
fn round_trip_with_naked_users() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let dict_dir = TempDir::new().unwrap();
    let restored_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "Created by .\\veeamadmin and User: bcastagnet on 2026-05-17\n",
    )
    .unwrap();

    // Anonymize with naked user detection
    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "--dict-output",
        dict_dir.path().to_str().unwrap(),
        "-f",
        "-D",
        "--aggressive",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Find dictionary file
    let dict_file = fs::read_dir(dict_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .expect("Dictionary file should exist");

    // Reverse
    let out_rev = run(&[
        "--reverse",
        dict_file.path().to_str().unwrap(),
        "-i",
        output_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        restored_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        out_rev.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_rev.stderr)
    );

    let original = fs::read_to_string(input_dir.path().join("test.log")).unwrap();
    let restored = fs::read_to_string(restored_dir.path().join("test.log")).unwrap();
    assert_eq!(original, restored, "Round-trip must be lossless");
}

// ── v2.4 features (KB2462 coverage) ───────────────────────

#[test]
fn ipv6_anonymized_by_default() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "Listening on 2a01:cb05:8c57:6800:250:56ff:fe96:aa77 port 9419\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let anonymized = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !anonymized.contains("2a01:cb05"),
        "IPv6 must be anonymized. Got: {}",
        anonymized
    );
    assert!(
        anonymized.contains("aa77"),
        "Last hextet should be preserved"
    );
}

#[test]
fn mac_address_anonymized() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "Interface eth0 MAC=00:50:56:96:AA:77 up\nPhysical Address. : 005056962A77\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let anonymized = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !anonymized.contains("00:50:56:96:AA:77"),
        "Colon MAC must go. Got: {}",
        anonymized
    );
    assert!(!anonymized.contains("005056962A77"), "Compact MAC must go");
}

/// #13: `00:50:56:...` is the VMware OUI, so a colon MAC with a hex letter
/// is the common case in a Veeam bundle, not the exotic one. It used to be
/// claimed by the IPv6 channel (which `--exclude mac` never touches), so it
/// got masked with the IPv6 format and survived `-e mac` intact. Reproduces
/// the exact report from the issue: with `-e mac`, both the hex-letter MAC
/// and the all-digit MAC must survive untouched.
#[test]
fn exclude_mac_preserves_hex_letter_mac() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("a.log"),
        "hexmac 00:50:56:96:AA:77 digitmac 00:11:22:33:44:55\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "-e",
        "mac",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let anonymized = fs::read_to_string(output_dir.path().join("a.log")).unwrap();
    assert!(
        anonymized.contains("00:50:56:96:AA:77"),
        "-e mac must preserve a MAC with hex letters. Got: {}",
        anonymized
    );
    assert!(
        anonymized.contains("00:11:22:33:44:55"),
        "-e mac must still preserve an all-digit MAC. Got: {}",
        anonymized
    );
}

/// Without `--exclude`, a colon MAC containing hex letters must come out
/// wearing the documented MAC mask (`**:**:**:**:**:XX`) rather than the
/// IPv6 mask it used to get when the IPv6 channel claimed it first.
#[test]
fn hex_letter_mac_gets_mac_mask_by_default() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("a.log"),
        "hexmac 00:50:56:96:AA:77 digitmac 00:11:22:33:44:55\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let anonymized = fs::read_to_string(output_dir.path().join("a.log")).unwrap();
    assert!(
        anonymized.contains("**:**:**:**:**:77"),
        "hex-letter MAC must get the MAC mask, not the IPv6 mask. Got: {}",
        anonymized
    );
    assert!(
        anonymized.contains("**:**:**:**:**:55"),
        "all-digit MAC must keep getting the MAC mask. Got: {}",
        anonymized
    );
    assert!(!anonymized.contains("00:50:56:96:AA:77"));
    assert!(!anonymized.contains("00:11:22:33:44:55"));
}

/// `--exclude ipv6` alone must still preserve a genuine IPv6 address, and a
/// colon MAC elsewhere in the same file must still be masked — the two
/// channels stay independent after the #13 fix.
#[test]
fn exclude_ipv6_preserves_ipv6_and_mac_still_masked() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("a.log"),
        "hexmac 00:50:56:96:AA:77 addr 2a01:cb05:8c57:6800:250:56ff:fe96:aa77\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "-e",
        "ipv6",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let anonymized = fs::read_to_string(output_dir.path().join("a.log")).unwrap();
    assert!(
        anonymized.contains("2a01:cb05:8c57:6800:250:56ff:fe96:aa77"),
        "-e ipv6 must preserve the genuine IPv6 address. Got: {}",
        anonymized
    );
    assert!(
        !anonymized.contains("00:50:56:96:AA:77"),
        "MAC must still be masked when only ipv6 is excluded. Got: {}",
        anonymized
    );
}

#[test]
fn ssh_fingerprint_redacted() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "RSA key fingerprint is SHA256:1234567890abcdefghijklmnopqrstuvwxyzABCDEFG.\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(out.status.success());
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        content.contains("[REDACTED]"),
        "SSH fp must be redacted. Got: {}",
        content
    );
    assert!(!content.contains("1234567890abcdefghij"));
}

#[test]
fn backup_file_stem_anonymized() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("test.log"),
        "Restoring from CRM-Production-2026-05-17.vbk into staging area\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(out.status.success());
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !content.contains("CRM-Production"),
        "Backup file stem must be replaced. Got: {}",
        content
    );
    assert!(content.contains(".vbk"), "Extension must be preserved");
}

#[test]
fn hostname_list_anonymized() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let list_file = list_dir.path().join("hosts.txt");

    fs::write(&list_file, "vsa1\nbackup-srv\n# comment\n").unwrap();
    fs::write(
        input_dir.path().join("test.log"),
        "Source: vsa1 / Target: backup-srv configured at 10:00\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--hostname-list",
        list_file.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(
        !content.contains("vsa1"),
        "Hostname must be anonymized. Got: {}",
        content
    );
    assert!(!content.contains("backup-srv"));
}

#[test]
fn object_list_anonymized() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let list_file = list_dir.path().join("objects.txt");

    fs::write(&list_file, "vm-prod-01\nDatastore-SAN-01\n").unwrap();
    fs::write(
        input_dir.path().join("test.log"),
        "Backup of vm-prod-01 on Datastore-SAN-01 started\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--object-list",
        list_file.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(!content.contains("vm-prod-01"));
    assert!(!content.contains("Datastore-SAN-01"));
}

#[test]
fn db_list_anonymized() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let list_file = list_dir.path().join("dbs.txt");

    fs::write(&list_file, "VeeamBackup\nProductionDB\n").unwrap();
    fs::write(
        input_dir.path().join("test.log"),
        "Connected to database VeeamBackup. Cloning to ProductionDB\n",
    )
    .unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--db-list",
        list_file.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let content = fs::read_to_string(output_dir.path().join("test.log")).unwrap();
    assert!(!content.contains("VeeamBackup"));
    assert!(!content.contains("ProductionDB"));
}

#[test]
fn kb2462_reference_in_banner() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(input_dir.path().join("test.log"), "x\n").unwrap();

    let out = run(&[
        "-i",
        input_dir.path().join("test.log").to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("KB2462"),
        "Banner must cite Veeam KB2462. Got: {}",
        stdout
    );
}

#[test]
fn paranoid_no_false_positive_on_backup_extension() {
    // issue #2: "disk.vib\next" / "chain.vbk\n1024" were wrongly detected as
    // DOMAIN\user and then re-flagged by --paranoid as leaks.
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    fs::write(
        input_dir.path().join("restore.log"),
        "Restore disk foo.vib\\next started\nChain chain.vbk\\n1024 verified\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--paranoid",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("Leak detected"),
        "paranoid must not flag backup-extension false positives. Output: {}",
        combined
    );
    // Backup file stems are still anonymized; the ".vib"/".vbk" tails remain.
    let content = fs::read_to_string(output_dir.path().join("restore.log")).unwrap();
    assert!(
        !content.contains("foo.vib"),
        "stem must be replaced: {}",
        content
    );
    assert!(
        !content.contains("chain.vbk"),
        "stem must be replaced: {}",
        content
    );
}

// ── Path-name anonymization (issue #1) ──────────────────────────────

#[test]
fn path_filename_hostname_anonymized() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let list_file = list_dir.path().join("hosts.txt");

    fs::write(&list_file, "vsa1\n").unwrap();
    // Hostname appears in the FILE NAME and in the content.
    fs::write(
        input_dir.path().join("Task.vsa1-backup.log"),
        "Source host vsa1 connected\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--hostname-list",
        list_file.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let names = rel_paths(output_dir.path());
    assert_eq!(names.len(), 1, "expected one output file, got {:?}", names);
    let name = &names[0];
    assert!(
        !name.contains("vsa1"),
        "Hostname must be removed from the file name. Got: {}",
        name
    );
    // Recognizable prefix and extension preserved.
    assert!(name.starts_with("Task."), "prefix preserved. Got: {}", name);
    assert!(name.ends_with(".log"), "extension preserved. Got: {}", name);

    let content = fs::read_to_string(output_dir.path().join(name)).unwrap();
    assert!(
        !content.contains("vsa1"),
        "content anonymized. Got: {}",
        content
    );
}

#[test]
fn path_directory_object_anonymized() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let list_file = list_dir.path().join("objects.txt");

    fs::write(&list_file, "prod-vm01\n").unwrap();
    // Object name appears as a DIRECTORY name.
    let sub = input_dir.path().join("prod-vm01");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join("agent.log"), "job started\n").unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--object-list",
        list_file.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let names = rel_paths(output_dir.path());
    assert_eq!(names.len(), 1, "expected one output file, got {:?}", names);
    assert!(
        !names[0].contains("prod-vm01"),
        "Object name must be removed from the directory path. Got: {}",
        names[0]
    );
    assert!(
        names[0].ends_with("agent.log"),
        "leaf file name preserved (not an entity). Got: {}",
        names[0]
    );
}

#[test]
fn path_fqdn_autodetected_in_name() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    // FQDN present ONLY in the file name, nowhere in content.
    fs::write(
        input_dir.path().join("Agent.host.example.com.log"),
        "nothing sensitive in here\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let names = rel_paths(output_dir.path());
    assert_eq!(names.len(), 1, "expected one output file, got {:?}", names);
    assert!(
        !names[0].contains("host.example.com"),
        "FQDN in file name must be auto-detected and anonymized. Got: {}",
        names[0]
    );
}

#[test]
fn path_keep_path_names_optout() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let list_file = list_dir.path().join("hosts.txt");

    fs::write(&list_file, "vsa1\n").unwrap();
    fs::write(
        input_dir.path().join("Task.vsa1-backup.log"),
        "Source host vsa1 connected\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--hostname-list",
        list_file.to_str().unwrap(),
        "--keep-path-names",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // File name kept verbatim …
    let kept = output_dir.path().join("Task.vsa1-backup.log");
    assert!(
        kept.exists(),
        "--keep-path-names must preserve the file name"
    );
    // … but content is still anonymized.
    let content = fs::read_to_string(&kept).unwrap();
    assert!(
        !content.contains("vsa1"),
        "content still anonymized with --keep-path-names. Got: {}",
        content
    );
}

#[test]
fn path_round_trip_reverse_restores_names() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let restored_dir = TempDir::new().unwrap();
    let dict_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let list_file = list_dir.path().join("hosts.txt");

    fs::write(&list_file, "vsa1\n").unwrap();
    let original_content = "Source host vsa1 connected\n";
    fs::write(
        input_dir.path().join("Task.vsa1-backup.log"),
        original_content,
    )
    .unwrap();

    // Forward: anonymize + export dictionary to a separate directory.
    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "-D",
        "--dict-output",
        dict_dir.path().to_str().unwrap(),
        "--hostname-list",
        list_file.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "forward stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The anonymized name must differ from the original.
    let anon_names = rel_paths(output_dir.path());
    assert_eq!(anon_names.len(), 1);
    assert!(!anon_names[0].contains("vsa1"));

    // Find the exported dictionary file.
    let dict = collect_files(dict_dir.path())
        .into_iter()
        .find(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .expect("dictionary json must exist");

    // Reverse: feed the anonymized output back through --reverse.
    let out = run(&[
        "-d",
        output_dir.path().to_str().unwrap(),
        "-o",
        restored_dir.path().to_str().unwrap(),
        "-f",
        "--reverse",
        dict.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "reverse stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Original file name AND content are restored.
    let restored = restored_dir.path().join("Task.vsa1-backup.log");
    assert!(
        restored.exists(),
        "reverse must restore the original file name. Got: {:?}",
        rel_paths(restored_dir.path())
    );
    assert_eq!(fs::read_to_string(&restored).unwrap(), original_content);
}

#[test]
fn paranoid_flags_leak_in_kept_path_name() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let list_file = list_dir.path().join("hosts.txt");

    fs::write(&list_file, "prod-host-01\n").unwrap();
    fs::write(
        input_dir.path().join("Task.prod-host-01.log"),
        "Source host prod-host-01 connected\n",
    )
    .unwrap();

    // With --keep-path-names the sensitive token stays in the file name;
    // --paranoid must flag it as a path-name leak.
    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--hostname-list",
        list_file.to_str().unwrap(),
        "--keep-path-names",
        "--paranoid",
    ]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("path name") && stderr.contains("prod-host-01"),
        "paranoid must report the leaked hostname in the path name. stderr: {}",
        stderr
    );
}

// ── v2.6: --validate-only ───────────────────────────────────────────

#[test]
fn validate_only_json_report_and_exit_code() {
    let input_dir = TempDir::new().unwrap();
    fs::write(
        input_dir.path().join("test.log"),
        "admin@corp.com from 192.168.1.50\nCORP\\jdoe ran job\n",
    )
    .unwrap();

    let out = run(&["-d", input_dir.path().to_str().unwrap(), "--validate-only"]);

    // Entities present → deterministic exit code 2.
    assert_eq!(
        out.status.code(),
        Some(2),
        "exit code must be 2 when entities found"
    );

    // stdout must be PURE JSON (banner/chatter routed to stderr).
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim_start();
    assert!(
        trimmed.starts_with('{'),
        "stdout must start with JSON. Got: {}",
        stdout
    );
    assert!(stdout.contains("\"mode\": \"validate-only\""));
    assert!(stdout.contains("\"entities_total\""));
    assert!(stdout.contains("\"email\""));
    assert!(stdout.contains("\"ip\""));

    // Report must NOT leak original values.
    assert!(
        !stdout.contains("admin@corp.com") && !stdout.contains("192.168.1.50"),
        "validate-only report must never contain original values. Got: {}",
        stdout
    );

    // No files written (we passed no -o), and the source is unchanged.
    let src = fs::read_to_string(input_dir.path().join("test.log")).unwrap();
    assert!(
        src.contains("admin@corp.com"),
        "source file must be untouched"
    );
}

#[test]
fn validate_only_no_entities_exit_zero() {
    let input_dir = TempDir::new().unwrap();
    fs::write(
        input_dir.path().join("clean.log"),
        "just an ordinary log line with no secrets\n",
    )
    .unwrap();

    let out = run(&["-d", input_dir.path().to_str().unwrap(), "--validate-only"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "exit code must be 0 when nothing detected"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"entities_total\": 0"));
}

#[test]
fn validate_only_report_output_to_file() {
    let input_dir = TempDir::new().unwrap();
    let report = TempDir::new().unwrap();
    let report_path = report.path().join("report.json");
    fs::write(input_dir.path().join("t.log"), "x@y.com 10.0.0.9\n").unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "--validate-only",
        "--report-output",
        report_path.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(report_path.exists(), "report file must be written");
    let report_json = fs::read_to_string(&report_path).unwrap();
    assert!(report_json.contains("\"mode\": \"validate-only\""));
}

// ── issue #11: --validate-only report must not leak names via paths ──

#[test]
fn validate_only_report_anonymizes_hostname_and_object_in_path() {
    let input_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let host_list = list_dir.path().join("hosts.txt");
    let obj_list = list_dir.path().join("objects.txt");
    fs::write(&host_list, "SRV-PROD-CRM01\n").unwrap();
    fs::write(&obj_list, "vm-finance-db\n").unwrap();

    // Same shape as the issue's reproduction: hostname as a directory name, VM
    // name embedded in the file name. Content carries an auto-detected entity
    // (an IP) too — kind_counts() treats hostname/object as list-injected/global
    // rather than per-file, so a file with nothing auto-detected in its content
    // never gets a `by_file` entry at all; the content entity is what makes this
    // file (and therefore its path) show up in `by_file` to begin with.
    let sub = input_dir.path().join("SRV-PROD-CRM01");
    fs::create_dir_all(&sub).unwrap();
    fs::write(
        sub.join("Task.SRV-PROD-CRM01-vm-finance-db.log"),
        "backup job ran, target 192.168.1.50\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "--validate-only",
        "--hostname-list",
        host_list.to_str().unwrap(),
        "--object-list",
        obj_list.to_str().unwrap(),
    ]);

    // Detected via the explicit lists, same deterministic exit code as any other run.
    assert_eq!(out.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("SRV-PROD-CRM01") && !stdout.contains("vm-finance-db"),
        "hostname/VM name must not appear verbatim anywhere in the report. Got: {}",
        stdout
    );

    // stdout is still pure, valid JSON (banner/chatter stays on stderr) — parse it
    // and check the specific field the issue reported, not just a substring.
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must parse as JSON");
    let file = report["by_file"][0]["file"].as_str().unwrap();
    assert!(
        !file.contains("SRV-PROD-CRM01") && !file.contains("vm-finance-db"),
        "by_file[].file must be anonymized. Got: {}",
        file
    );
    assert!(
        file.starts_with("host-") && file.ends_with(".log"),
        "recognizable prefix/extension survive, only the entity is replaced. Got: {}",
        file
    );
}

#[test]
fn validate_only_report_source_path_anonymized() {
    let root = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let host_list = list_dir.path().join("hosts.txt");
    fs::write(&host_list, "SRV-PROD-CRM01\n").unwrap();

    // The scanned directory itself (`-d`), not just an entry under it, is named
    // after the hostname.
    let input_dir = root.path().join("SRV-PROD-CRM01");
    fs::create_dir_all(&input_dir).unwrap();
    fs::write(input_dir.join("t.log"), "ordinary log line\n").unwrap();

    let out = run(&[
        "-d",
        input_dir.to_str().unwrap(),
        "--validate-only",
        "--hostname-list",
        host_list.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must parse as JSON");
    let source = report["source"].as_str().unwrap();
    assert!(
        !source.contains("SRV-PROD-CRM01"),
        "`source` must not leak the scanned directory's own name. Got: {}",
        source
    );
}

#[test]
fn validate_only_report_ip_in_path_rendered_path_safe() {
    let input_dir = TempDir::new().unwrap();
    let ip_dir = input_dir.path().join("Console").join("10.0.0.21");
    fs::create_dir_all(&ip_dir).unwrap();
    fs::write(ip_dir.join("task.log"), "target 10.0.0.21 reached\n").unwrap();

    let out = run(&["-d", input_dir.path().to_str().unwrap(), "--validate-only"]);
    assert_eq!(out.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("10.0.0.21"),
        "raw IP must not appear in the report. Got: {}",
        stdout
    );
    // Same filesystem-safe mask a real output tree's directory name would get
    // (`*` is illegal in a Windows path component), so a reader correlating the
    // report against an anonymized output directory sees matching names.
    assert!(
        stdout.contains("xx.xx.0.21"),
        "IP directory should render path-safe the same way a real output tree would. Got: {}",
        stdout
    );
}

#[test]
fn validate_only_report_ignores_keep_path_names() {
    let input_dir = TempDir::new().unwrap();
    let list_dir = TempDir::new().unwrap();
    let host_list = list_dir.path().join("hosts.txt");
    fs::write(&host_list, "SRV-PROD-CRM01\n").unwrap();
    fs::write(
        input_dir.path().join("Task.SRV-PROD-CRM01.log"),
        "job ran\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "--validate-only",
        "--hostname-list",
        host_list.to_str().unwrap(),
        "--keep-path-names",
    ]);
    assert_eq!(out.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("SRV-PROD-CRM01"),
        "--keep-path-names must not defeat report path anonymization. Got: {}",
        stdout
    );
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must parse as JSON despite the flag combo");

    // The deviation from --keep-path-names' normal effect is explained, not silent.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--keep-path-names has no effect on the --validate-only report"),
        "must explain why the flag is not honored here. stderr: {}",
        stderr
    );
}

// ── v2.6: .zip input ────────────────────────────────────────────────

#[test]
fn zip_repack_round_trip() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("bundle.zip");
    let out_zip = dir.path().join("anon.zip");
    make_zip(
        &in_zip,
        &[
            ("Task.log", "admin@corp.com from 192.168.1.50\n"),
            ("sub/agent.log", "connected 10.20.30.40\n"),
            (
                "sub/notes.txt",
                "binary-ish or non-log content kept verbatim\n",
            ),
        ],
    );

    let out = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let entries = read_zip(&out_zip);
    // Same number of file entries, same tree.
    assert_eq!(entries.len(), 3, "entry count preserved: {:?}", entries);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"Task.log"));
    assert!(names.contains(&"sub/agent.log"));
    assert!(names.contains(&"sub/notes.txt"));

    // .log content anonymized; non-.log copied verbatim.
    for (name, content) in &entries {
        assert!(
            !content.contains("admin@corp.com"),
            "{} not anonymized",
            name
        );
        assert!(!content.contains("192.168.1.50"), "{} not anonymized", name);
        assert!(!content.contains("10.20.30.40"), "{} not anonymized", name);
        if name.ends_with("notes.txt") {
            assert!(content.contains("kept verbatim"), "non-log copied verbatim");
        }
    }

    // The dictionary must never be inside the zip.
    assert!(
        !names.iter().any(|n| n.contains("veeam-anonymizer")),
        "dictionary must not be packed in the zip"
    );
}

#[test]
fn zip_extract_mode() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("bundle.zip");
    let out_dir = TempDir::new().unwrap();
    make_zip(&in_zip, &[("a.log", "user admin@corp.com at 172.16.0.9\n")]);

    let out = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "-o",
        out_dir.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let content = fs::read_to_string(out_dir.path().join("a.log")).unwrap();
    assert!(!content.contains("admin@corp.com") && !content.contains("172.16.0.9"));
}

#[test]
fn zip_entry_name_anonymized_with_hostname_list() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("bundle.zip");
    let out_zip = dir.path().join("anon.zip");
    let list = dir.path().join("hosts.txt");
    fs::write(&list, "vsa1\n").unwrap();
    make_zip(&in_zip, &[("Task.vsa1.log", "host vsa1 ok\n")]);

    let out = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "--hostname-list",
        list.to_str().unwrap(),
        "-f",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let entries = read_zip(&out_zip);
    assert_eq!(entries.len(), 1);
    assert!(
        !entries[0].0.contains("vsa1"),
        "entry name must be anonymized: {}",
        entries[0].0
    );
    assert!(entries[0].0.starts_with("Task.") && entries[0].0.ends_with(".log"));
}

// ── v2.6: optional dictionary encryption ────────────────────────────

#[test]
fn encrypt_dict_round_trip_env_passphrase() {
    let input_dir = TempDir::new().unwrap();
    let anon = TempDir::new().unwrap();
    let restored = TempDir::new().unwrap();
    let dict_dir = TempDir::new().unwrap();
    let original = "admin@corp.com from 192.168.1.50\n";
    fs::write(input_dir.path().join("t.log"), original).unwrap();

    // Forward with encrypted dictionary.
    let out = run_env(
        &[
            "-d",
            input_dir.path().to_str().unwrap(),
            "-o",
            anon.path().to_str().unwrap(),
            "-f",
            "-D",
            "--dict-output",
            dict_dir.path().to_str().unwrap(),
            "--encrypt-dict",
        ],
        &[("VLAR_DICT_PASSPHRASE", "correct horse battery")],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // An encrypted .age dictionary was produced (no cleartext .json).
    let age_dict = fs::read_dir(dict_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "age").unwrap_or(false))
        .expect(".json.age dictionary must exist");

    // Reverse with the correct passphrase restores the original content.
    let out = run_env(
        &[
            "-d",
            anon.path().to_str().unwrap(),
            "-o",
            restored.path().to_str().unwrap(),
            "-f",
            "--reverse",
            age_dict.to_str().unwrap(),
        ],
        &[("VLAR_DICT_PASSPHRASE", "correct horse battery")],
    );
    assert!(
        out.status.success(),
        "reverse stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(restored.path().join("t.log")).unwrap(),
        original
    );

    // Wrong passphrase fails cleanly (non-zero exit, no panic).
    let out = run_env(
        &[
            "-d",
            anon.path().to_str().unwrap(),
            "-o",
            TempDir::new().unwrap().path().to_str().unwrap(),
            "-f",
            "--reverse",
            age_dict.to_str().unwrap(),
        ],
        &[("VLAR_DICT_PASSPHRASE", "wrong passphrase")],
    );
    assert!(!out.status.success(), "wrong passphrase must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("passphrase") || stderr.to_lowercase().contains("decrypt"),
        "must report a decryption error. stderr: {}",
        stderr
    );
}

// ── v2.6.1: IP/IPv6/MAC anonymized in path names (path-safe) ─────────

#[test]
fn path_ip_directory_anonymized() {
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();

    // A directory literally named after an IP (real-world case).
    let ip_dir = input_dir.path().join("Console").join("10.0.0.21");
    fs::create_dir_all(&ip_dir).unwrap();
    fs::write(ip_dir.join("task.log"), "target 10.0.0.21 reached\n").unwrap();
    // A loopback dir must be left alone.
    let lo = input_dir.path().join("Console").join("localhost");
    fs::create_dir_all(&lo).unwrap();
    fs::write(lo.join("x.log"), "noop\n").unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--paranoid",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let names = rel_paths(output_dir.path());
    // The IP directory must be renamed to a filesystem-safe form (no '*').
    assert!(
        !names.iter().any(|n| n.contains("10.0.0.21")),
        "IP directory must be anonymized in the output path. Got: {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n.contains("xx.xx.0.21")),
        "IP directory should be rendered path-safe (xx.xx.0.21). Got: {:?}",
        names
    );
    // Loopback directory preserved.
    assert!(
        names.iter().any(|n| n.contains("localhost")),
        "localhost dir must be preserved. Got: {:?}",
        names
    );
    // No '*' may ever appear in an output path component.
    assert!(
        !names.iter().any(|n| n.contains('*')),
        "no '*' allowed in path names. Got: {:?}",
        names
    );

    // Paranoid must not flag the (now-renamed) IP path.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("10.0.0.21"),
        "paranoid must not report the IP as a leak. stderr: {}",
        stderr
    );
}

#[test]
fn paranoid_no_false_positive_on_windows_path_segments() {
    // v2.6.1: "...\VeeamBackup\Backup_Job_1\..." path segments must not be
    // treated as DOMAIN\user and re-flagged by --paranoid.
    let input_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    fs::write(
        input_dir.path().join("svc.log"),
        "open C:\\Program Files\\Veeam\\VeeamBackup\\Backup_Job_1\\run.log now\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        input_dir.path().to_str().unwrap(),
        "-o",
        output_dir.path().to_str().unwrap(),
        "-f",
        "--paranoid",
    ]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Leak detected"),
        "no path-segment false positives expected. stderr: {}",
        stderr
    );
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Non-.log text files: extension set, --ext, and nested archives
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A `.trace` entry inside a zip used to be copied byte-for-byte into the
/// "anonymized" zip, so real customer data shipped in the file sent to support.
#[test]
fn zip_non_log_text_entry_is_anonymized_not_copied() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("bundle.zip");
    let out_zip = dir.path().join("anon.zip");
    make_zip(
        &in_zip,
        &[
            ("Svc.log", "log user admin@corp.com at 172.16.0.9\n"),
            ("Proxy.trace", "trace user erin@corp.com at 172.16.0.10\n"),
            ("Report.html", "<p>carol@corp.com 172.16.0.11</p>\n"),
        ],
    );

    let out = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for (name, content) in read_zip(&out_zip) {
        assert!(
            !content.contains("erin@corp.com")
                && !content.contains("carol@corp.com")
                && !content.contains("admin@corp.com")
                && !content.contains("172.16.0."),
            "entry {name} still holds original data: {content}"
        );
    }
}

/// Directory input must cover the whole bundle, not only `.log`.
#[test]
fn directory_covers_default_text_extensions() {
    let src = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();
    fs::write(src.path().join("a.log"), "admin@corp.com 172.16.0.9\n").unwrap();
    fs::write(src.path().join("b.trace"), "erin@corp.com 172.16.0.10\n").unwrap();
    fs::write(src.path().join("c.html"), "carol@corp.com 172.16.0.11\n").unwrap();

    let out = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out_dir.path().to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for name in ["a.log", "b.trace", "c.html"] {
        let p = out_dir.path().join(name);
        assert!(p.exists(), "{name} missing from output");
        let content = fs::read_to_string(&p).unwrap();
        assert!(
            !content.contains("@corp.com") && !content.contains("172.16.0."),
            "{name} not anonymized: {content}"
        );
    }
}

/// `--only-ext` narrows the set; everything else is reported as skipped.
#[test]
fn only_ext_restricts_and_reports_skipped() {
    let src = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();
    fs::write(src.path().join("a.log"), "admin@corp.com\n").unwrap();
    fs::write(src.path().join("b.trace"), "erin@corp.com\n").unwrap();

    let out = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out_dir.path().to_str().unwrap(),
        "--only-ext",
        "log",
        "-f",
        "--aggressive",
    ]);
    assert!(out.status.success());
    assert!(out_dir.path().join("a.log").exists());
    assert!(!out_dir.path().join("b.trace").exists());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Skipped 1 file(s)") && stderr.contains(".trace"),
        "skipped files must be reported, not silently dropped. stderr: {stderr}"
    );
}

/// A directory containing a `.zip` warns by default and expands with the flag.
#[test]
fn expand_archives_anonymizes_nested_zip_entries() {
    let src = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();
    fs::write(src.path().join("live.log"), "admin@corp.com 172.16.0.9\n").unwrap();
    make_zip(
        &src.path().join("rotated.zip"),
        &[
            ("Old.log", "dave@corp.com 172.16.0.16\n"),
            ("Old.trace", "erin@corp.com 172.16.0.17\n"),
        ],
    );

    // Default: warns, does not touch the archive.
    let out = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out_dir.path().to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Skipped 1 .zip archive"),
        "nested archive must be reported. stderr: {stderr}"
    );

    // With the flag: entries land under <archive-name>/ and are anonymized.
    let out_dir2 = TempDir::new().unwrap();
    let out = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out_dir2.path().to_str().unwrap(),
        "--expand-archives",
        "-f",
        "--aggressive",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for rel in [
        "live.log",
        "rotated.zip.extracted/Old.log",
        "rotated.zip.extracted/Old.trace",
    ] {
        let p = out_dir2.path().join(rel);
        assert!(p.exists(), "{rel} missing from expanded output");
        let content = fs::read_to_string(&p).unwrap();
        assert!(
            !content.contains("@corp.com") && !content.contains("172.16.0."),
            "{rel} not anonymized: {content}"
        );
    }
}

/// A single-entry archive whose entry has the same name as a live file next to it
/// used to be staged onto that live file. Whichever `WalkDir` reached second won:
/// the archive entry was written first, then the live file's `hard_link` failed with
/// EEXIST and the `fs::copy` fallback truncated the extracted content. The rotated
/// log vanished while the run reported "1 text entr(ies) staged" and exited 0.
#[test]
fn expand_archives_keeps_both_on_name_collision() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(src.path().join("Svc.log"), "LIVE alice@corp.com 10.1.1.1\n").unwrap();
    make_zip(
        &src.path().join("Svc.log.zip"),
        &[("Svc.log", "ROTATED bob@corp.com 10.2.2.2\n")],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "--expand-archives",
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    // Both records must reach the output, in distinct files.
    let mut live = false;
    let mut rotated = false;
    for e in collect_files(out.path()) {
        let c = fs::read_to_string(&e).unwrap_or_default();
        live |= c.contains("LIVE");
        rotated |= c.contains("ROTATED");
    }
    assert!(live, "live Svc.log content missing from output");
    assert!(
        rotated,
        "rotated Svc.log content was silently dropped — the collision overwrote it"
    );
}

/// The same collision with a multi-entry archive used to abort the whole run with a
/// bare `Is a directory (os error 21)`, because the archive's expansion directory and
/// the live file wanted the same path.
#[test]
fn expand_archives_multi_entry_collision_does_not_abort() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(src.path().join("Svc.log"), "LIVE alice@corp.com\n").unwrap();
    make_zip(
        &src.path().join("Svc.log.zip"),
        &[
            ("a.log", "R1 bob@corp.com\n"),
            ("b.log", "R2 carol@corp.com\n"),
        ],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "--expand-archives",
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "run aborted on a name collision. stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let bodies: Vec<String> = collect_files(out.path())
        .iter()
        .map(|p| fs::read_to_string(p).unwrap_or_default())
        .collect();
    for marker in ["LIVE", "R1", "R2"] {
        assert!(
            bodies.iter().any(|c| c.contains(marker)),
            "{marker} missing from output; got {bodies:?}"
        );
    }
}

/// Two archives in the same directory holding an identically named entry must both
/// survive — each archive gets its own expansion directory.
#[test]
fn expand_archives_two_archives_same_entry_name() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    make_zip(
        &src.path().join("r1.zip"),
        &[("App.log", "FIRST bob@corp.com\n")],
    );
    make_zip(
        &src.path().join("r2.zip"),
        &[("App.log", "SECOND carol@corp.com\n")],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "--expand-archives",
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let bodies: Vec<String> = collect_files(out.path())
        .iter()
        .map(|p| fs::read_to_string(p).unwrap_or_default())
        .collect();
    for marker in ["FIRST", "SECOND"] {
        assert!(
            bodies.iter().any(|c| c.contains(marker)),
            "{marker} missing — one archive overwrote the other; got {bodies:?}"
        );
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// #15: --expand-archives must not silence coverage reporting
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Like `make_zip`, but for an entry whose content is not valid UTF-8 text —
/// needed once an entry is itself a `.zip` file (arbitrary binary), which
/// `make_zip`'s `&str` signature cannot carry.
fn make_zip_bytes(path: &Path, entries: &[(&str, &[u8])]) {
    use std::io::Write;
    let file = fs::File::create(path).unwrap();
    let mut zw = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in entries {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(content).unwrap();
    }
    zw.finish().unwrap();
}

/// `stage_with_archives` used to stage only files inside the active extension
/// set and report nothing else, so `collect_input_files` then walked a staging
/// root with nothing left to flag — the coverage warning vanished exactly when
/// `--expand-archives` was turned on, even though the `.reg` was still dropped.
/// This must read the same as a non-expanding run left out-of-set files (see
/// `only_ext_restricts_and_reports_skipped` above for that shape without the
/// flag): the flag changes where entries come from, not whether an out-of-set
/// file gets named.
#[test]
fn expand_archives_still_reports_directory_out_of_set_files() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(src.path().join("a.log"), "alice@corp.com 10.1.1.1\n").unwrap();
    fs::write(src.path().join("export.reg"), "host=vbr01.corp.com\n").unwrap();
    make_zip(
        &src.path().join("rot.zip"),
        &[("Old.log", "bob@corp.com 10.2.2.2\n")],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "--expand-archives",
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("Skipped 1 file(s) with unhandled extensions") && stderr.contains(".reg"),
        "export.reg must still be reported with --expand-archives, exactly as without it. \
         stderr: {stderr}"
    );
    assert!(
        collect_files(out.path())
            .iter()
            .all(|p| p.file_name().and_then(|n| n.to_str()) != Some("export.reg")),
        "export.reg must not appear in the output — only the warning was ever missing"
    );
}

/// The same gap one level down: an out-of-set entry found *inside* an archive
/// being expanded must be reported too, not only an out-of-set file sitting
/// next to the archive in the directory.
#[test]
fn expand_archives_reports_out_of_set_entries_inside_archive() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    make_zip(
        &src.path().join("rot.zip"),
        &[
            ("Old.log", "alice@corp.com 10.1.1.1\n"),
            ("Old.ini", "bob@corp.com 10.2.2.2\n"),
        ],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "--expand-archives",
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("Skipped 1 file(s) with unhandled extensions") && stderr.contains(".ini"),
        "an out-of-set entry inside the archive must be reported. stderr: {stderr}"
    );
    assert!(
        collect_files(out.path())
            .iter()
            .all(|p| p.file_name().and_then(|n| n.to_str()) != Some("Old.ini")),
        "Old.ini must not be staged or expanded — it is outside the active extension set"
    );
}

/// A `.zip` nested inside another `.zip` — VB365 bundles nest rotated logs this
/// way. `--expand-archives` does not recurse into it (see the comment on the
/// nested-`.zip` branch in `stage_with_archives` for why: doing so needs to
/// fully materialize the inner archive to get the random access `zip::ZipArchive`
/// requires, which reopens the same amplification a streaming copy avoids).
/// What matters here is that the gap is reported as *not covered*, not silently
/// dropped, and that the outer archive's own text entry is unaffected.
#[test]
fn expand_archives_reports_zip_nested_inside_zip() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();

    // Build the inner zip for real, then splice its raw bytes into the outer
    // zip as a single entry — an inner zip's bytes are arbitrary binary, not
    // text, so `make_zip`'s `&str` entries cannot carry it directly.
    let inner_scratch = src.path().join("Inner.zip.tmp");
    make_zip(&inner_scratch, &[("Deep.log", "carol@corp.com 10.5.5.5\n")]);
    let inner_bytes = fs::read(&inner_scratch).unwrap();
    fs::remove_file(&inner_scratch).unwrap();

    make_zip_bytes(
        &src.path().join("Outer.zip"),
        &[
            ("Level1.log", "dave@corp.com 10.6.6.6\n".as_bytes()),
            ("Inner.zip", &inner_bytes),
        ],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "--expand-archives",
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stderr = String::from_utf8_lossy(&o.stderr);

    // The outer archive's own text entry is expanded and anonymized as usual.
    let level1 = out.path().join("Outer.zip.extracted").join("Level1.log");
    assert!(level1.exists(), "Level1.log missing from expanded output");
    let content = fs::read_to_string(&level1).unwrap();
    assert!(
        !content.contains("dave@corp.com") && !content.contains("10.6.6.6"),
        "Level1.log not anonymized: {content}"
    );

    // Deep.log, inside the nested zip, must not appear anywhere — covered or
    // not, it must not be silently dropped without a trace, and it must not
    // leak unanonymized either.
    assert!(
        collect_files(out.path())
            .iter()
            .all(|p| p.file_name().and_then(|n| n.to_str()) != Some("Deep.log")),
        "Deep.log must not appear in the output — it was never expanded"
    );
    for f in collect_files(out.path()) {
        let c = fs::read_to_string(&f).unwrap_or_default();
        assert!(
            !c.contains("carol@corp.com"),
            "content from inside the nested zip leaked unanonymized into {f:?}"
        );
    }

    // The gap must be named and stated as uncovered, not phrased as merely
    // "skipped" the way an out-of-set extension is — there is no --ext flag
    // that reaches inside a second archive layer.
    assert!(
        stderr.contains("NOT covered"),
        "a nested archive must be reported as not covered. stderr: {stderr}"
    );
    assert!(
        stderr.contains("Inner.zip"),
        "the nested archive must be named. stderr: {stderr}"
    );
}

/// `stage_with_archives` reports what it left behind itself; the ordinary
/// directory walk that runs afterwards, over the staging root, must come back
/// with nothing to add — the root never holds an out-of-set file or a `.zip` of
/// its own. If both walks reported, the operator would see either a duplicated
/// count or two summaries that disagree, and would have no way to tell which
/// one to trust.
#[test]
fn expand_archives_coverage_report_is_not_duplicated() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(src.path().join("a.log"), "alice@corp.com\n").unwrap();
    fs::write(src.path().join("b.reg"), "host=vbr01.corp.com\n").unwrap();
    make_zip(
        &src.path().join("rot.zip"),
        &[("c.log", "bob@corp.com\n"), ("d.ini", "carol@corp.com\n")],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "--expand-archives",
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stderr = String::from_utf8_lossy(&o.stderr);

    // One combined tally — the directory's own out-of-set file and the
    // archive's out-of-set entry both show up in it — not one report from
    // staging and a second, near-empty one from the walk that runs afterwards.
    assert_eq!(
        stderr.matches("unhandled extensions").count(),
        1,
        "coverage must be reported exactly once per run, not once per internal walk. \
         stderr: {stderr}"
    );
    assert!(
        stderr.contains(".reg") && stderr.contains(".ini"),
        "both the directory file and the archive entry must appear in that one report. \
         stderr: {stderr}"
    );
    // The staging root never contains a `.zip` of its own (archives are expanded,
    // not copied), so the walk that runs the ordinary pipeline afterwards must
    // not also claim to have found one nested inside it — that would be a second,
    // contradictory summary in the same run.
    assert!(
        !stderr.contains("found inside the directory"),
        "the staging root must not be reported as containing its own nested zip. \
         stderr: {stderr}"
    );
}

/// Zip input copies entries outside the extension set through byte-for-byte. That is
/// a deliberate design choice, but it has to be reported: the directory walk warned
/// while the zip path stayed silent, and the zip is what gets sent to support.
#[test]
fn zip_unhandled_entries_are_reported() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("bundle.zip");
    let out_zip = dir.path().join("anon.zip");
    make_zip(
        &in_zip,
        &[
            ("Svc.log", "log admin@corp.com\n"),
            ("export.reg", "host=vbr01.corp.com user=CORP\\svc_v\n"),
            ("README", "plain dave@corp.com\n"),
        ],
    );

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains(".reg") && stderr.contains("(none)"),
        "unhandled zip entries must be listed by extension. stderr: {stderr}"
    );
    assert!(
        stderr.contains("UNCHANGED"),
        "the report must say these entries are not anonymized. stderr: {stderr}"
    );
}

/// The JSON escape false positive is not specific to `'`: `\t`, `\n`, `\f`, `\r`
/// and `\b` made RE_DOMAIN_USER fire the same way ("col1\tsep2" -> domain col1 / user
/// tsep2), producing junk mappings that rewrote ordinary text and turned valid JSON
/// escapes into invalid ones.
#[test]
fn json_single_char_escapes_are_not_domain_users() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let line = "{\"m\":\"col1\\tsep2 line\\nend2 page\\fmore ret\\rx bs\\bx on srv.corp.com\"}\n";
    fs::write(src.path().join("p.trace"), line).unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--aggressive",
        "--paranoid",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let got = fs::read_to_string(out.path().join("p.trace")).unwrap();
    // Every escape must survive byte-for-byte...
    for esc in ["\\t", "\\n", "\\f", "\\r", "\\b"] {
        assert!(
            got.contains(esc),
            "escape {esc} was corrupted into a fake DOMAIN\\user: {got}"
        );
    }
    // ...along with the words around them, while the real FQDN is still anonymized.
    for word in ["col1", "sep2", "line", "end2", "page", "more"] {
        assert!(
            got.contains(word),
            "ordinary word {word} was rewritten: {got}"
        );
    }
    assert!(!got.contains("srv.corp.com"), "FQDN not anonymized: {got}");
}

/// A plain-text `.log` keeps normal DOMAIN\user detection — the JSON rule must not
/// leak into content where a single backslash really is a separator.
#[test]
fn plain_log_domain_user_still_detected() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(src.path().join("a.log"), "logon by CORP\\tanya failed\n").unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let got = fs::read_to_string(out.path().join("a.log")).unwrap();
    assert!(
        !got.contains("CORP\\tanya"),
        "plain-text DOMAIN\\user must still be anonymized: {got}"
    );
}

/// JSON-encoded logs write `'` as `'`, which made `RE_DOMAIN_USER` fire with
/// domain "com" / user "u0027s" and left --paranoid reporting a phantom leak.
#[test]
fn json_escape_is_not_a_domain_user() {
    let src = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();
    fs::write(
        src.path().join("a.trace"),
        "{\"m\":\"box alice@corp.com\\u0027s folder on srv.corp.com\\u0027\"}\n",
    )
    .unwrap();

    let out = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out_dir.path().to_str().unwrap(),
        "-f",
        "--aggressive",
        "--paranoid",
    ]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Leak detected"),
        "escaped apostrophe must not be reported as a leak. stderr: {stderr}"
    );

    let content = fs::read_to_string(out_dir.path().join("a.trace")).unwrap();
    // The domain is anonymized; the escape survives as ordinary text.
    assert!(
        !content.contains("corp.com"),
        "domain not anonymized: {content}"
    );
    assert!(
        content.contains("\\u0027"),
        "escape sequence was corrupted: {content}"
    );
}

/// A genuine account inside a JSON-encoded `.trace` is written `DOMAIN\\user`, which
/// the single-backslash pattern never matched — the service account shipped in clear
/// while `--paranoid` reported the file clean (#8). The replacement must keep the
/// doubled separator, or the anonymized line stops being valid JSON.
#[test]
fn escaped_domain_user_in_trace_is_anonymized_and_reversible() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let back = TempDir::new().unwrap();
    let dict = TempDir::new().unwrap();

    // As stored on disk, all three lines valid JSON:
    //   1. a real account   -> must be anonymized
    //   2. a Windows path    -> must be left alone
    //   3. a \t escape       -> must be left alone
    let input = concat!(
        r#"{"m":"quoted \"ACME\\svc_veeam\" logged on"}"#,
        "\n",
        r#"{"m":"path C:\\Program\\VeeamBackup\\Backup_Job_1\\run.log"}"#,
        "\n",
        r#"{"m":"col1\tsep2 on srv.corp.com"}"#,
        "\n"
    );
    fs::write(src.path().join("p.trace"), input).unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--aggressive",
        "--paranoid",
        "-D",
        "--dict-output",
        dict.path().to_str().unwrap(),
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let got = fs::read_to_string(out.path().join("p.trace")).unwrap();
    assert!(
        !got.contains("svc_veeam"),
        "escaped DOMAIN\\\\user leaked in clear: {got}"
    );
    assert!(
        got.contains(r"\\"),
        "the doubled separator must survive, or the line is no longer valid JSON: {got}"
    );
    // The path and the tab escape are untouched.
    assert!(
        got.contains(r"VeeamBackup\\Backup_Job_1"),
        "JSON-encoded path was rewritten: {got}"
    );
    assert!(
        got.contains(r"col1\tsep2"),
        "tab escape was rewritten: {got}"
    );

    // Reversing with the dictionary restores the original bytes exactly.
    let dict_file = collect_files(dict.path())
        .into_iter()
        .find(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .expect("dictionary not written");
    let o = run(&[
        "--reverse",
        dict_file.to_str().unwrap(),
        "-d",
        out.path().to_str().unwrap(),
        "-o",
        back.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        fs::read_to_string(back.path().join("p.trace")).unwrap(),
        input,
        "round trip through the dictionary must restore the original bytes"
    );
}

/// The same real account reaches the anonymizer in two different byte forms: plain
/// `ACME\svc_veeam` in a `.log`, JSON-escaped `ACME\\svc_veeam` in a `.trace`. Before
/// this fix, `build_map()` keyed replacement generation off the raw matched string, so
/// the two forms got two independent random replacements — a support engineer
/// correlating a job's `.log` with its `.trace` then saw two accounts where there was
/// only one, breaking the README's "same entity always gets the same replacement"
/// promise. This asserts both files anonymize to the *same* domain/user words (only the
/// separator width differs), and that `-D` + `--reverse` still restores both files
/// byte-for-byte.
#[test]
fn same_account_consistent_across_log_and_trace() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let back = TempDir::new().unwrap();
    let dict = TempDir::new().unwrap();

    let log_input = "logon ACME\\svc_veeam here\n";
    // As stored on disk: {"m":"json \"ACME\\svc_veeam\" here"}
    let trace_input = concat!(r#"{"m":"json \"ACME\\svc_veeam\" here"}"#, "\n");
    fs::write(src.path().join("a.log"), log_input).unwrap();
    fs::write(src.path().join("b.trace"), trace_input).unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "-D",
        "--dict-output",
        dict.path().to_str().unwrap(),
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let log_out = fs::read_to_string(out.path().join("a.log")).unwrap();
    let trace_out = fs::read_to_string(out.path().join("b.trace")).unwrap();
    assert!(
        !log_out.contains("ACME") && !log_out.contains("svc_veeam"),
        "account leaked in clear in a.log: {log_out}"
    );
    assert!(
        !trace_out.contains("ACME") && !trace_out.contains("svc_veeam"),
        "account leaked in clear in b.trace: {trace_out}"
    );

    // Pull the replacement principal out of each file. a.log carries a single
    // backslash separator, b.trace a doubled one — everything else around the
    // match is unchanged, so stripping the known prefix/suffix isolates it.
    let log_repl = log_out
        .strip_prefix("logon ")
        .and_then(|s| s.strip_suffix(" here\n"))
        .expect("a.log layout must be unchanged around the match");
    let (log_domain, log_user) = log_repl
        .split_once('\\')
        .expect("a.log replacement must keep a single separator");

    let trace_repl = trace_out
        .strip_prefix("{\"m\":\"json \\\"")
        .and_then(|s| s.strip_suffix("\\\" here\"}\n"))
        .expect("b.trace layout must be unchanged around the match");
    let (trace_domain, trace_user) = trace_repl
        .split_once("\\\\")
        .expect("b.trace replacement must keep a doubled separator");

    assert_eq!(
        log_domain, trace_domain,
        "same account must get the same domain word in both files: a.log={log_repl} \
         b.trace={trace_repl}"
    );
    assert_eq!(
        log_user, trace_user,
        "same account must get the same user word in both files: a.log={log_repl} \
         b.trace={trace_repl}"
    );

    // Reversing with the dictionary restores the original bytes exactly, for both
    // files — the two raw forms must both still be present in the dictionary.
    let dict_file = collect_files(dict.path())
        .into_iter()
        .find(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .expect("dictionary not written");
    let o = run(&[
        "--reverse",
        dict_file.to_str().unwrap(),
        "-d",
        out.path().to_str().unwrap(),
        "-o",
        back.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        fs::read_to_string(back.path().join("a.log")).unwrap(),
        log_input,
        "round trip through the dictionary must restore a.log's original bytes"
    );
    assert_eq!(
        fs::read_to_string(back.path().join("b.trace")).unwrap(),
        trace_input,
        "round trip through the dictionary must restore b.trace's original bytes"
    );
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Zip-slip: hostile entry names in an untrusted bundle
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Write a zip with entry names exactly as given, bypassing any normalisation
/// `make_zip` might apply — the whole point here is to produce names a well-behaved
/// writer would refuse.
fn make_zip_raw(path: &Path, entries: &[(&str, &str)]) {
    use std::io::Write;
    let file = fs::File::create(path).unwrap();
    let mut zw = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in entries {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(content.as_bytes()).unwrap();
    }
    zw.finish().unwrap();
}

/// A `.zip` bundle is untrusted input — it arrives from a customer. An entry named
/// `../../x` used to be joined straight onto the output root, landing outside the
/// directory the operator named, with exit code 0 and no mention in the listing.
#[test]
fn zip_traversal_entry_stays_inside_output_dir() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("evil.zip");
    let out = dir.path().join("a/b/out");
    fs::create_dir_all(&out).unwrap();
    make_zip_raw(
        &in_zip,
        &[
            ("good/Svc.log", "legit admin@corp.com 10.1.1.1\n"),
            ("../../ESCAPED.log", "escaped erin@corp.com 10.2.2.2\n"),
        ],
    );

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    // Nothing may exist above the output directory.
    for stray in ["a/ESCAPED.log", "a/b/ESCAPED.log", "ESCAPED.log"] {
        assert!(
            !dir.path().join(stray).exists(),
            "{stray} was written outside -o"
        );
    }
    // The content is still anonymized and still delivered, just contained.
    let names = rel_paths(&out);
    assert!(
        names.iter().any(|n| n.ends_with("ESCAPED.log")),
        "the entry should be kept inside -o, not dropped: {names:?}"
    );
    for p in collect_files(&out) {
        let c = fs::read_to_string(&p).unwrap();
        assert!(
            !c.contains("@corp.com") && !c.contains("10.1.1.1") && !c.contains("10.2.2.2"),
            "{} not anonymized: {c}",
            p.display()
        );
    }
    // And the operator is told, rather than it being fixed in silence.
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("had a name that points outside the output")
            && stderr.contains("../../ESCAPED.log"),
        "rewritten entries must be reported by name. stderr: {stderr}"
    );
}

/// Repacking a traversal name unchanged hands the attack downstream: the archive
/// sent to support would itself write outside wherever the recipient extracts it.
#[test]
fn repacked_zip_carries_no_traversal_entry() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("evil.zip");
    let out_zip = dir.path().join("anon.zip");
    make_zip_raw(
        &in_zip,
        &[
            ("good/Svc.log", "legit admin@corp.com\n"),
            ("../../ESCAPED.log", "escaped erin@corp.com\n"),
        ],
    );

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    for (name, _) in read_zip(&out_zip) {
        assert!(
            !name.contains(".."),
            "traversal entry repacked into the output archive: {name}"
        );
        assert!(
            !name.starts_with('/'),
            "absolute entry repacked into the output archive: {name}"
        );
    }
}

/// Absolute and Windows drive-letter names escape just as effectively as `../..` —
/// `Path::join` discards the root it was given for both.
#[test]
fn zip_absolute_and_drive_letter_entries_are_contained() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("evil.zip");
    let out = dir.path().join("out");
    fs::create_dir_all(&out).unwrap();
    make_zip_raw(
        &in_zip,
        &[
            ("/tmp/ABS.log", "abs dave@corp.com\n"),
            ("C:/Windows/DRIVE.log", "drive carol@corp.com\n"),
            ("ok/Fine.log", "fine bob@corp.com\n"),
        ],
    );

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    for p in collect_files(&out) {
        assert!(
            p.starts_with(&out),
            "{} escaped the output directory",
            p.display()
        );
    }
    assert!(
        !Path::new("/tmp/ABS.log").exists(),
        "absolute entry was written to /tmp"
    );
}

/// A bundle with ordinary entry names must be completely unaffected by the
/// sanitising — same tree, same contents, and no warning.
#[test]
fn ordinary_zip_unaffected_by_path_sanitising() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("bundle.zip");
    let out_zip = dir.path().join("anon.zip");
    make_zip(
        &in_zip,
        &[
            ("Svc.log", "admin@corp.com\n"),
            ("sub/dir/Proxy.trace", "{\"m\":\"erin@corp.com\"}\n"),
        ],
    );

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
        "--keep-path-names",
    ]);
    assert!(o.status.success());
    let names: Vec<String> = read_zip(&out_zip).into_iter().map(|(n, _)| n).collect();
    assert!(names.contains(&"Svc.log".to_string()), "got {names:?}");
    assert!(
        names.contains(&"sub/dir/Proxy.trace".to_string()),
        "nested path must be preserved verbatim: {names:?}"
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        !stderr.contains("had a name that points outside the output"),
        "a clean bundle must not trigger the warning. stderr: {stderr}"
    );
}

// ── Issue #12: IPv4 collision must not abort the whole reverse run ─────

/// The exact scenario from issue #12: a proxy on 192.168.1.10 and a repo on
/// 10.0.1.10 share their last two octets, so IPv4 masking (last-two-octets-only,
/// by design — see README) sends both to `**.**.1.10`. Before this fix,
/// `reverse_anonymize` treated that expected collision as dictionary corruption
/// and `bail!`ed before restoring anything — not even `CORP\jdoe` and
/// `Job-CRM.vbk`, which live in the same file and are perfectly reversible.
/// This asserts the run now succeeds, the reversible entities come back
/// byte-for-byte, and the operator is told which value could not be resolved
/// and why.
#[test]
fn reverse_survives_ipv4_collision_and_restores_the_rest() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let back = TempDir::new().unwrap();
    let dict = TempDir::new().unwrap();

    let original = "proxy 192.168.1.10 talks to repo 10.0.1.10 / CORP\\jdoe opened Job-CRM.vbk\n";
    fs::write(src.path().join("a.log"), original).unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "-D",
        "--dict-output",
        dict.path().to_str().unwrap(),
    ]);
    assert!(
        o.status.success(),
        "forward stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let anonymized = fs::read_to_string(out.path().join("a.log")).unwrap();
    assert!(
        anonymized.contains("**.**.1.10"),
        "both colliding addresses must mask to the same last-two-octets string. Got: {anonymized}"
    );
    assert!(
        !anonymized.contains("192.168.1.10") && !anonymized.contains("10.0.1.10"),
        "originals must not leak in the anonymized output. Got: {anonymized}"
    );

    let dict_file = collect_files(dict.path())
        .into_iter()
        .find(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .expect("dictionary not written");

    // Before the fix: this call failed and wrote nothing at all.
    let o = run(&[
        "--reverse",
        dict_file.to_str().unwrap(),
        "-d",
        out.path().to_str().unwrap(),
        "-o",
        back.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        o.status.success(),
        "reverse must succeed despite the IPv4 collision. stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let restored_path = back.path().join("a.log");
    assert!(
        restored_path.exists(),
        "reverse must still produce output for the file. Got: {:?}",
        rel_paths(back.path())
    );
    let restored = fs::read_to_string(&restored_path).unwrap();

    // The reversible entities in the same file come back exactly.
    assert!(
        restored.contains("CORP\\jdoe"),
        "domain user in the same file must be restored. Got: {restored}"
    );
    assert!(
        restored.contains("Job-CRM.vbk"),
        "backup file name in the same file must be restored. Got: {restored}"
    );

    // The ambiguous IPv4 pair cannot be told apart, so it is left as the mask
    // rather than guessed at — neither original reappears, and the mask itself
    // is still present.
    assert!(
        !restored.contains("192.168.1.10") && !restored.contains("10.0.1.10"),
        "an ambiguous IPv4 mask must not be resolved to either candidate original. Got: {restored}"
    );
    assert!(
        restored.contains("**.**.1.10"),
        "the unresolved mask must be left as-is. Got: {restored}"
    );

    // The operator must be told clearly which value could not be restored,
    // and why — silence here would be worse than the old hard abort.
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("cannot be reversed") && stderr.contains("**.**.1.10"),
        "stderr must name the unresolved value. stderr: {stderr}"
    );
    assert!(
        stderr.contains("192.168.1.10") && stderr.contains("10.0.1.10"),
        "stderr must list both candidate originals. stderr: {stderr}"
    );
}

/// A dictionary is genuinely corrupt — not just recording an expected IPv4
/// collision — when a *collision-checked* section (here: domain_users, guarded
/// by `used_user_pairs` in build_map) contains two different originals mapped
/// to the same anonymized value. That can only happen if the JSON was
/// hand-edited, merged, or otherwise tampered with after export, and the fix
/// for issue #12 must not weaken this into silence: it should still abort.
#[test]
fn reverse_still_rejects_genuine_corruption_outside_ipv4() {
    let out = TempDir::new().unwrap();
    let back = TempDir::new().unwrap();
    let dict_dir = TempDir::new().unwrap();

    fs::write(out.path().join("a.log"), "irrelevant content\n").unwrap();

    // domain_users is collision-checked at generation time, so two distinct
    // originals sharing an anonymized value here is not something a real
    // forward run could ever produce — a hand-tampered dictionary is the only
    // explanation.
    let corrupt_dict = r#"{
        "metadata": {
            "version": "2.7.1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "files_processed": 1,
            "total_entities": 2
        },
        "mappings": {
            "domain_users": [
                {"original": "CORP\\alice", "anonymized": "ZZZZ\\wwww"},
                {"original": "CORP\\bob", "anonymized": "ZZZZ\\wwww"}
            ]
        }
    }"#;
    let dict_path = dict_dir.path().join("tampered.json");
    fs::write(&dict_path, corrupt_dict).unwrap();

    let o = run(&[
        "--reverse",
        dict_path.to_str().unwrap(),
        "-d",
        out.path().to_str().unwrap(),
        "-o",
        back.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(
        !o.status.success(),
        "a genuinely ambiguous non-IPv4 mapping must still abort the run"
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("Dictionary corruption"),
        "stderr must still call this out as corruption. stderr: {stderr}"
    );
    assert!(
        rel_paths(back.path()).is_empty(),
        "nothing should be written once genuine corruption is detected"
    );
}

/// Real bundles carry directory entries (`Svc/`) and `./` prefixes. Those are
/// spelling, not escapes — reporting them fires the hostile-bundle warning on
/// essentially every archive produced by `zip -r`, which buries the real signal.
/// `make_zip` only ever calls `start_file`, so a fixture built with it cannot
/// catch this; this one adds directory entries explicitly.
#[test]
fn ordinary_zip_with_directory_entries_raises_no_warning() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("bundle.zip");
    let out_zip = dir.path().join("anon.zip");
    {
        use std::io::Write;
        let file = fs::File::create(&in_zip).unwrap();
        let mut zw = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        zw.add_directory("Svc/", opts).unwrap();
        zw.start_file("Svc/a.log", opts).unwrap();
        zw.write_all(b"a admin@corp.com\n").unwrap();
        zw.add_directory("Svc/Util/", opts).unwrap();
        zw.start_file("Svc/Util/b.log", opts).unwrap();
        zw.write_all(b"b bob@corp.com\n").unwrap();
        zw.start_file("./c.log", opts).unwrap();
        zw.write_all(b"c carol@corp.com\n").unwrap();
        zw.finish().unwrap();
    }

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
        "--keep-path-names",
    ]);
    assert!(o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        !stderr.contains("had a name that points outside the output"),
        "directory entries and ./ prefixes are not escapes. stderr: {stderr}"
    );
    let names: Vec<String> = read_zip(&out_zip).into_iter().map(|(n, _)| n).collect();
    assert!(
        names.contains(&"Svc/Util/b.log".to_string()),
        "nested entry must survive: {names:?}"
    );
}

/// Stripping traversal collapses distinct entries onto one name. Overwriting one
/// of them loses anonymized content that was meant to be delivered; letting the
/// zip writer reject the duplicate aborts the run with a partial archive on disk.
/// Both are worse than a suffix.
#[test]
fn colliding_sanitised_names_keep_every_entry() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("col.zip");
    make_zip_raw(
        &in_zip,
        &[
            ("dup.log", "one admin@corp.com\n"),
            ("../dup.log", "two erin@corp.com\n"),
            ("./dup.log", "three carol@corp.com\n"),
            ("keep.log", "four bob@corp.com\n"),
        ],
    );

    // Repack: every entry present, unique names, run succeeds.
    let out_zip = dir.path().join("anon.zip");
    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(
        o.status.success(),
        "collision must not abort the run. stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let entries = read_zip(&out_zip);
    assert_eq!(entries.len(), 4, "every entry must survive: {entries:?}");
    let mut names: Vec<&String> = entries.iter().map(|(n, _)| n).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 4, "names must be unique: {names:?}");

    // Extract: same, on disk.
    let out_dir = TempDir::new().unwrap();
    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "-o",
        out_dir.path().to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(o.status.success());
    let files = collect_files(out_dir.path());
    assert_eq!(
        files.len(),
        4,
        "no entry may be silently overwritten: {files:?}"
    );
    // The four distinct payloads are all still there, none clobbered.
    let bodies: Vec<String> = files
        .iter()
        .map(|p| fs::read_to_string(p).unwrap_or_default())
        .collect();
    for marker in ["one", "two", "three", "four"] {
        assert!(
            bodies.iter().any(|b| b.starts_with(marker)),
            "{marker} lost to a collision; got {bodies:?}"
        );
    }
}

/// A dictionary exported twice, or concatenated with itself, repeats entries that
/// carry the *same* original. That says exactly one thing about the value, so it
/// must still reverse — only genuinely competing originals are ambiguous.
#[test]
fn repeated_identical_ipv4_entry_still_reverses() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");
    let back = dir.path().join("back");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("a.log"), "host at **.**.30.40 done\n").unwrap();
    let dict = dir.path().join("d.json");
    fs::write(
        &dict,
        r#"{"metadata":{"version":"2.7.2","created_at":"2026-08-08T00:00:00Z","files_processed":1,"total_entities":2},
            "mappings":{"ip_addresses":[
              {"original":"10.20.30.40","anonymized":"**.**.30.40"},
              {"original":"10.20.30.40","anonymized":"**.**.30.40"}]}}"#,
    )
    .unwrap();

    let o = run(&[
        "--reverse",
        dict.to_str().unwrap(),
        "-d",
        out.to_str().unwrap(),
        "-o",
        back.to_str().unwrap(),
        "-f",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        !stderr.contains("could be any of"),
        "an entry repeated identically is not ambiguous. stderr: {stderr}"
    );
    let restored = fs::read_to_string(back.join("a.log")).unwrap();
    assert!(
        restored.contains("10.20.30.40"),
        "should have been restored: {restored}"
    );
}

/// Two entries can want the same destination without anything hostile going on:
/// the filesystem-safe IP rendering is lossy, so `Agent.10.0.1.21.log` and
/// `Agent.192.168.1.21.log` both become `Agent.xx.xx.1.21.log`. Telling the
/// operator their bundle is untrusted for that would be the same false alarm the
/// escape reporting was rewritten to avoid.
#[test]
fn benign_collision_is_not_reported_as_hostile() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("b.zip");
    let out = TempDir::new().unwrap();
    make_zip_raw(
        &in_zip,
        &[
            ("Agent.10.0.1.21.log", "a admin@corp.com 10.0.1.21\n"),
            ("Agent.192.168.1.21.log", "b bob@corp.com 192.168.1.21\n"),
        ],
    );

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("wanted a destination already taken"),
        "the collision must be reported. stderr: {stderr}"
    );
    assert!(
        !stderr.contains("points outside the output")
            && !stderr.contains("Treat this bundle as malformed or hostile"),
        "an ordinary bundle must not be reported as an escape. stderr: {stderr}"
    );
    assert_eq!(
        collect_files(out.path()).len(),
        2,
        "v2.7.1 lost one of these; both must survive"
    );
}

/// `C:REL.log` is drive-*relative* — it carries no separator, so splitting never
/// isolates the prefix. On Windows `PathBuf::push` replaces the root for a path
/// with a prefix, so it escapes just as `../..` does.
#[test]
fn drive_relative_entry_is_contained_and_reported() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("d.zip");
    let out_zip = dir.path().join("o.zip");
    make_zip_raw(&in_zip, &[("C:REL.log", "x erin@corp.com\n")]);

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(o.status.success());
    let names: Vec<String> = read_zip(&out_zip).into_iter().map(|(n, _)| n).collect();
    assert!(
        names.contains(&"REL.log".to_string()),
        "drive prefix must be stripped, keeping the name it qualified: {names:?}"
    );
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("points outside the output"),
        "a drive-relative name is an escape and must be reported"
    );
}

/// A nested archive holding both `dup.log` and `../dup.log` used to abort the whole
/// staging run and write nothing — the same failure removed from the two output
/// writers, left behind in the third consumer of entry names.
#[test]
fn expand_archives_survives_colliding_nested_entries() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    make_zip_raw(
        &src.path().join("Inner.zip"),
        &[
            ("dup.log", "one admin@corp.com\n"),
            ("../dup.log", "two erin@corp.com\n"),
        ],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--aggressive",
        "--expand-archives",
    ]);
    assert!(
        o.status.success(),
        "a colliding nested archive must not kill the run. stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let bodies: Vec<String> = collect_files(out.path())
        .iter()
        .map(|p| fs::read_to_string(p).unwrap_or_default())
        .collect();
    for marker in ["one", "two"] {
        assert!(
            bodies.iter().any(|b| b.starts_with(marker)),
            "{marker} lost; got {bodies:?}"
        );
    }
}

/// `--exclude email` has to hold in file and entry *names* too. Preserving the
/// address in the content while the file name keeps a rewritten domain half is the
/// same half-anonymized result the exclusion exists to avoid — and the protection
/// list was originally wired only into the content pass.
#[test]
fn exclude_email_preserves_the_address_in_names_too() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(
        src.path().join("Task.admin@acme-corp.com.log"),
        "body mentions admin@acme-corp.com\n",
    )
    .unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--aggressive",
        "-e",
        "email",
    ]);
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let names = rel_paths(out.path());
    assert!(
        names.iter().any(|n| n.contains("admin@acme-corp.com")),
        "the excluded address must survive in the file name: {names:?}"
    );
    let body = fs::read_to_string(out.path().join("Task.admin@acme-corp.com.log")).unwrap();
    assert!(
        body.contains("admin@acme-corp.com"),
        "and in the content: {body}"
    );
}

/// The same, for zip entry names — a third consumer of the path pairs.
#[test]
fn exclude_email_preserves_the_address_in_zip_entry_names() {
    let dir = TempDir::new().unwrap();
    let in_zip = dir.path().join("b.zip");
    let out_zip = dir.path().join("anon.zip");
    make_zip(
        &in_zip,
        &[("Task.admin@acme-corp.com.log", "body admin@acme-corp.com\n")],
    );

    let o = run(&[
        "-d",
        in_zip.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
        "-e",
        "email",
    ]);
    assert!(o.status.success());
    let names: Vec<String> = read_zip(&out_zip).into_iter().map(|(n, _)| n).collect();
    assert!(
        names.iter().any(|n| n.contains("admin@acme-corp.com")),
        "excluded address must survive in the entry name: {names:?}"
    );
}

/// Without an exclusion, names are still anonymized — the protection must not leak
/// into the ordinary path.
#[test]
fn names_still_anonymized_without_exclusion() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(
        src.path().join("Task.admin@acme-corp.com.log"),
        "x admin@acme-corp.com\n",
    )
    .unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(o.status.success());
    let names = rel_paths(out.path());
    assert!(
        !names.iter().any(|n| n.contains("acme-corp")),
        "names must still be anonymized when nothing is excluded: {names:?}"
    );
}

/// Letting the MAC channel claim a six-group colon run cost an IPv6 leak: the tail
/// of `fd00::aa:bb:cc:dd:ee:ff` is six two-hex-digit groups, so it was taken for a
/// MAC — and `--exclude mac` then left the whole address in clear. A run sitting
/// inside a longer colon-separated address is never a MAC.
#[test]
fn exclude_mac_does_not_leak_a_compressed_ipv6() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(
        src.path().join("a.log"),
        "v6 fd00::aa:bb:cc:dd:ee:ff mac 00:50:56:96:AA:77\n",
    )
    .unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "-e",
        "mac",
    ]);
    assert!(o.status.success());
    let got = fs::read_to_string(out.path().join("a.log")).unwrap();
    assert!(
        !got.contains("fd00::aa:bb:cc:dd:ee:ff"),
        "the IPv6 address must still be masked under -e mac: {got}"
    );
    assert!(
        got.contains("00:50:56:96:AA:77"),
        "and the real MAC must still be preserved: {got}"
    );
}

/// `--paranoid` looks for original values in the output, but an address kept by
/// `--exclude email` still contains its domain — which is a live mapping. Scanning
/// naively made the tool report its own deliberate choice as a leak, in either
/// letter case.
#[test]
fn paranoid_does_not_flag_deliberately_excluded_emails() {
    for line in [
        "mail admin@acme-corp.com here\n",
        "mail Admin@Acme-Corp.COM here\n",
    ] {
        let src = TempDir::new().unwrap();
        let out = TempDir::new().unwrap();
        fs::write(src.path().join("a.log"), line).unwrap();

        let o = run(&[
            "-d",
            src.path().to_str().unwrap(),
            "-o",
            out.path().to_str().unwrap(),
            "-f",
            "--aggressive",
            "-e",
            "email",
            "--paranoid",
        ]);
        assert!(o.status.success());
        let stderr = String::from_utf8_lossy(&o.stderr);
        let stdout = String::from_utf8_lossy(&o.stdout);
        assert!(
            !stderr.contains("PARANOID CHECK:") && !stdout.contains("PARANOID CHECK:"),
            "preserved address reported as a leak for {line:?}: {stderr}{stdout}"
        );
    }
}

/// `--exclude domain` has to hold through the FQDN channel too. A 3+-segment email
/// domain lands in both sets, and under `--aggressive` the FQDN pass rewrote the
/// standalone occurrence while the address kept it — one string, two outcomes.
#[test]
fn exclude_domain_holds_through_the_fqdn_channel() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(
        src.path().join("a.log"),
        "a admin@mail.acme-corp.com b mail.acme-corp.com standalone\n",
    )
    .unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--aggressive",
        "-e",
        "domain",
    ]);
    assert!(o.status.success());
    let got = fs::read_to_string(out.path().join("a.log")).unwrap();
    assert!(
        got.contains("b mail.acme-corp.com standalone"),
        "the standalone occurrence must be preserved like the one in the address: {got}"
    );
}

/// A `.zip` entry inside a `.zip` input used to be bucketed with unhandled
/// extensions, whose report ends with "add text types with --ext". Following that
/// advice decodes and rewrites a binary file: the nested archive comes out corrupt
/// ("Bad magic number for central directory") rather than anonymized.
#[test]
fn nested_archive_in_zip_input_is_not_advised_as_an_extension() {
    let dir = TempDir::new().unwrap();
    let inner = dir.path().join("Inner.zip");
    make_zip(&inner, &[("Deep.log", "deep carol@corp.com\n")]);
    let inner_bytes = fs::read(&inner).unwrap();

    let bundle = dir.path().join("bundle.zip");
    {
        use std::io::Write;
        let f = fs::File::create(&bundle).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default();
        zw.start_file("ok.log", opts).unwrap();
        zw.write_all(b"ok admin@corp.com\n").unwrap();
        zw.start_file("Inner.zip", opts).unwrap();
        zw.write_all(&inner_bytes).unwrap();
        zw.finish().unwrap();
    }

    let out_zip = dir.path().join("anon.zip");
    let o = run(&[
        "-d",
        bundle.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
    ]);
    assert!(o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("found inside another archive") && stderr.contains("bundle.zip::Inner.zip"),
        "the nested archive must get the not-covered message. stderr: {stderr}"
    );
    assert!(
        !stderr.contains("1 .zip"),
        "it must not be listed as an unhandled extension. stderr: {stderr}"
    );
}

/// `zip` is not a text extension. Accepting it decodes the archive, rewrites bytes
/// that happen to match an entity and re-encodes — producing a corrupt archive —
/// and also shadows archive handling, so `--expand-archives` never expands.
#[test]
fn zip_is_refused_as_a_text_extension() {
    let dir = TempDir::new().unwrap();
    let inner = dir.path().join("Inner.zip");
    make_zip(&inner, &[("Deep.log", "deep carol@corp.com\n")]);
    let inner_bytes = fs::read(&inner).unwrap();

    let bundle = dir.path().join("bundle.zip");
    {
        use std::io::Write;
        let f = fs::File::create(&bundle).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default();
        zw.start_file("Inner.zip", opts).unwrap();
        zw.write_all(&inner_bytes).unwrap();
        zw.finish().unwrap();
    }

    let out_zip = dir.path().join("anon.zip");
    let o = run(&[
        "-d",
        bundle.to_str().unwrap(),
        "--output-zip",
        out_zip.to_str().unwrap(),
        "-f",
        "--aggressive",
        "--ext",
        "zip",
    ]);
    assert!(o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(
        stderr.matches("Ignoring `zip`").count(),
        1,
        "warned exactly once. stderr: {stderr}"
    );

    // The nested archive must come out byte-identical, still a readable zip.
    let out = fs::File::open(&out_zip).unwrap();
    let mut archive = zip::ZipArchive::new(out).unwrap();
    let mut got = Vec::new();
    {
        use std::io::Read;
        archive
            .by_name("Inner.zip")
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
    }
    assert_eq!(got, inner_bytes, "the nested archive was corrupted");
}

/// The same refusal must not disable expansion: with `--ext zip` the archive is
/// still an archive, so `--expand-archives` covers its entries.
#[test]
fn ext_zip_does_not_disable_expansion() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    make_zip(
        &src.path().join("rot.zip"),
        &[("r.log", "r bob@corp.com 10.4.4.4\n")],
    );

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--aggressive",
        "--expand-archives",
        "--ext",
        "zip",
    ]);
    assert!(o.status.success());
    let names = rel_paths(out.path());
    assert!(
        names.iter().any(|n| n.contains("rot.zip.extracted")),
        "the archive must still be expanded: {names:?}"
    );
    for p in collect_files(out.path()) {
        let c = fs::read_to_string(&p).unwrap_or_default();
        assert!(
            !c.contains("bob@corp.com"),
            "{} not anonymized",
            p.display()
        );
    }
}

/// Backing off from a MAC claim on *any* adjacent colon hands the match to nobody
/// whenever the IPv6 channel would not take it either: RE_IPV6 never matches the
/// hyphen form, and an all-digit six-group run is rejected as IPv6. Those MACs then
/// shipped in clear with no flags at all — and --paranoid could not see it, since
/// an entity in no map is in no scan list. Only a `::` prefix means "IPv6 tail".
#[test]
fn colon_adjacent_macs_are_still_anonymized() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    // The `::`-prefixed rows are the ones a prefix-only guard drops: the hyphen
    // form is never IPv6, and an all-digit six-group run is rejected as IPv6, so
    // backing off on the prefix alone leaves them claimed by nobody. The
    // C++-scope shapes are ordinary machine-generated trace output.
    let raw = concat!(
        "Adapter:00-50-56-96-AA-78 state up\n",
        "MAC:00-50-56-96-AA-01 here\n",
        "00-50-56-96-AA-02: link up\n",
        "label:00:11:22:33:44:07 end\n",
        "00:11:22:33:44:08: trailing\n",
        "hexctx mac:00:50:56:96:AA:7E end\n",
        "bare ::00:11:22:33:44:55 end\n",
        "bare ::00-50-56-96-AA-61 end\n",
        "pfx fd00::00:11:22:33:44:63 end\n",
        "pfx fd00::00-50-56-96-AA-64 end\n",
        "cpp Veeam::Backup::00-50-56-96-AA-66 end\n",
        "cpp Veeam::Net::00:11:22:33:44:67 end\n",
        "cls CNetAdapter::00-50-56-96-AA-78 end\n",
        "v6 fd00::aa:bb:cc:dd:ee:ff end\n",
    );
    fs::write(src.path().join("a.log"), raw).unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
    ]);
    assert!(o.status.success());
    let got = fs::read_to_string(out.path().join("a.log")).unwrap();
    for leaked in [
        "00-50-56-96-AA-78",
        "00-50-56-96-AA-01",
        "00-50-56-96-AA-02",
        "00:11:22:33:44:07",
        "00:11:22:33:44:08",
        "00:50:56:96:AA:7E",
        "00:11:22:33:44:55",
        "00-50-56-96-AA-61",
        "00:11:22:33:44:63",
        "00-50-56-96-AA-64",
        "00-50-56-96-AA-66",
        "00:11:22:33:44:67",
    ] {
        assert!(
            !got.contains(leaked),
            "{leaked} shipped in clear with no flags: {got}"
        );
    }
    assert!(
        !got.contains("fd00::aa:bb:cc:dd:ee:ff"),
        "the compressed IPv6 must still be masked: {got}"
    );
}

/// And `--exclude mac` must preserve all of those shapes — including the
/// colon-adjacent hex-letter MAC, which is what #13 was filed about.
#[test]
fn exclude_mac_preserves_colon_adjacent_shapes() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let raw = concat!(
        "Adapter:00-50-56-96-AA-78 up\n",
        "label:00:11:22:33:44:07 end\n",
        "hexctx mac:00:50:56:96:AA:7E end\n",
        "v6 fd00::aa:bb:cc:dd:ee:ff end\n",
    );
    fs::write(src.path().join("a.log"), raw).unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "-e",
        "mac",
    ]);
    assert!(o.status.success());
    let got = fs::read_to_string(out.path().join("a.log")).unwrap();
    for kept in [
        "00-50-56-96-AA-78",
        "00:11:22:33:44:07",
        "00:50:56:96:AA:7E",
    ] {
        assert!(got.contains(kept), "-e mac must preserve {kept}: {got}");
    }
    assert!(
        !got.contains("fd00::aa:bb:cc:dd:ee:ff"),
        "but the IPv6 must still be masked: {got}"
    );
}

/// #22: a MAC written with mixed separators (`aa-bb:cc-dd:ee-ff`) matches
/// `RE_MAC_COLON` — the `[:-]` alternates per separator — but the renderer
/// used to split on only one of the two characters, undercount the groups,
/// and give up, shipping the address in clear. `--paranoid` flagged it
/// (the literal was in `mac_addresses`, mapped to itself), which is the
/// only reason it wasn't worse. This is the end-to-end proof the leak is
/// closed: a file containing only mixed-separator MACs must come out
/// masked, and `--paranoid` must report zero leaks on it.
#[test]
fn paranoid_reports_no_leak_on_mixed_separator_macs() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(
        src.path().join("a.log"),
        "A aa-bb:cc-dd:ee-ff B 00:50-56:96-AA:33\n",
    )
    .unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "--paranoid",
    ]);
    assert!(o.status.success());
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        !stdout.contains("Leak detected"),
        "--paranoid must report no leak once mixed-separator MACs are masked. stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("Paranoid check") || stdout.contains("no leak"),
        "Should report a clean paranoid check. stdout: {}",
        stdout
    );

    let got = fs::read_to_string(out.path().join("a.log")).unwrap();
    assert!(
        !got.contains("aa-bb:cc-dd:ee-ff"),
        "mixed-separator MAC must not survive in clear: {got}"
    );
    assert!(
        !got.to_lowercase().contains("00:50-56:96-aa:33"),
        "mixed-separator MAC must not survive in clear: {got}"
    );
    assert!(
        got.contains("**-**:**-**:**-ff"),
        "mask must preserve each separator in place: {got}"
    );
    assert!(
        got.contains("**:**-**:**-**:33"),
        "mask must preserve each separator in place: {got}"
    );
}

/// `--exclude mac` must preserve a mixed-separator MAC untouched — the same
/// guarantee it already gives consistent-separator forms.
#[test]
fn exclude_mac_preserves_mixed_separator_mac_end_to_end() {
    let src = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    fs::write(
        src.path().join("a.log"),
        "A aa-bb:cc-dd:ee-ff B 00:50-56:96-AA:33\n",
    )
    .unwrap();

    let o = run(&[
        "-d",
        src.path().to_str().unwrap(),
        "-o",
        out.path().to_str().unwrap(),
        "-f",
        "-e",
        "mac",
    ]);
    assert!(o.status.success());
    let got = fs::read_to_string(out.path().join("a.log")).unwrap();
    assert!(
        got.contains("aa-bb:cc-dd:ee-ff"),
        "-e mac must preserve the mixed-separator MAC: {got}"
    );
    assert!(
        got.contains("00:50-56:96-AA:33"),
        "-e mac must preserve the mixed-separator MAC: {got}"
    );
}
