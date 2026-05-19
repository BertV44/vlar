//! Integration tests — run the compiled binary end-to-end
//! Run with: cargo test --test integration_test

use std::fs;
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
