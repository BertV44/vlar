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

| KB2462 sensitive data type | v2.6 status |
|---|---|
| User names | ✅ DOMAIN\user, .\user, --aggressive naked-user, --user-list |
| Object names (hosts, datastores, VMs, clusters) | ✅ via `--object-list` |
| VM file names and paths | ✅ backup files (.vbk/.vib/.vbm/.vrb) + file/directory **names** anonymized (v2.5); other objects via lists |
| FQDN / Hostname / NetBIOS names | ✅ FQDN via `--aggressive`, short hostnames via `--hostname-list` |
| IPv4 addresses | ✅ |
| IPv6 addresses | ✅ |
| Customer-specific paths to backup files | ✅ file & directory **names** anonymized in output paths (v2.5) |
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

## What's new in v2.7

Coverage beyond `.log`, from real VB365 bundle testing.

### Non-`.log` text files are anonymized by default

A Veeam bundle is not only `.log`: proxy traces are `.trace`, job reports are `.html`,
configuration dumps are `.xml` / `.config`. All carry the same mailboxes, hostnames and paths as
the logs. Previously only `.log` was handled, with two consequences — in directory mode the rest
was **silently dropped** (neither anonymized nor copied, so a partial run reported success), and
in `.zip` mode it was **copied byte-for-byte into the anonymized archive**, i.e. real customer
data shipped in the file sent to support.

The built-in set is now:

```
log  trace  txt  xml  html  htm  csv  json  config  err  out
```

- `--ext trace,html` — add extensions to the set
- `--only-ext log` — replace the set (restores the pre-v2.7 `.log`-only scope)

**Anything outside the set is now reported**, grouped by extension, in *both* input modes — a
directory run says what it skipped, and a `.zip` run says what it copied through unchanged. A
`.reg` export or an extensionless text file will show up there; add it with `--ext` if it matters.
Coverage is never silently partial.

### `--expand-archives` — nested `.zip` archives

Rotated logs are archived as `.zip` *inside* a bundle, and directory input used to ignore them
entirely. They are now reported by default, and `--expand-archives` stages their text entries so
the normal pipeline covers them.

Entries land in `<archive-name>.extracted/<entry>` beside the archive — one directory per
archive, named after the archive itself, so an expanded entry can never overwrite a live file or
another archive's entry (a live `Svc.log` and a rotated `Svc.log.zip` holding its own `Svc.log`
both survive). Staged files are hard-linked where the filesystem allows it, so a multi-GB bundle
is not duplicated; a temp directory on a different volume than the input falls back to copying.
The staging tree is removed on every exit path.

**Coverage reporting stays on with the flag.** Staging only ever moves files that are already in
the active extension set, so the ordinary directory walk that runs afterwards, over the staged
tree rather than the real input, would always find a clean floor — nothing outside the set is ever
placed there to trip its report. Left alone, that made `--expand-archives` the one thing that
turned the coverage warning *off*: a `.reg` sitting next to the archive was still dropped, only the
message saying so disappeared. Staging now tallies what it leaves behind itself — a plain
out-of-set file in the directory and an out-of-set entry found inside an archive are both counted
— and reports them with the same wording the non-expanding run uses, before the second walk ever
starts.

An archive found *inside* an archive is not opened, in either input mode. Reading one needs random
access into an entry that offers only a forward-only decompression stream, so it would have to be
materialised whole first — two stacked compression layers instead of one, which is the shape a zip
bomb exploits. It is named and reported as **not covered**, deliberately not folded into the
unhandled-extension report above: that one ends with "add text types with `--ext`", and no flag
reaches a second archive layer, so calling it "skipped" would imply one exists.

```
  ⚠ 1 archive(s) found inside another archive — NOT covered:
      Outer.zip::Inner.zip
    An archive nested one layer deeper is not opened: reading it needs random
    access into a forward-only decompression stream, so it would have to be
    materialised whole first — two stacked compression layers, the shape a zip
    bomb exploits. Deliberately no flag reaches this far, which is why this is
    worded as not covered rather than skipped.
    Its contents are neither anonymized nor written to the output in any form
    — extract it separately and re-run if it needs covering.
```

The last line differs by input mode, because the outcome does: expanding a directory leaves the
nested archive out of the output entirely, while a `.zip` input copies it through byte-for-byte —
so in that case the archive *is* in the bundle you send on, with its contents unanonymized.

Both reports come from the staging step itself, so a run never shows two summaries that disagree:
the ordinary directory walk that runs afterwards, over the now-complete staged tree, has nothing
left to add.

`zip` is refused as a value for `--ext` / `--only-ext`. An archive is not text: decoding it,
rewriting the bytes that happen to match an entity and re-encoding produces a corrupt archive
rather than an anonymized one, and a `.zip` claimed as text also shadows the archive handling
itself — it gets staged as an ordinary file, so `--expand-archives` reports `Expanded 0 archive(s)`
and its entries are never covered nor mentioned. The flag is ignored with a warning.

### Fewer false positives in JSON-encoded traces

`.trace` files are JSON per line, where a literal backslash is written `\\`. A lone backslash is
therefore always an escape, but `RE_DOMAIN_USER` read `col1\tsep2` as domain `col1` + user
`tsep2` — junk mappings that rewrote ordinary text, mangled the escape into invalid JSON, and
left `--paranoid` reporting phantom leaks. Single-backslash escapes (`\b \f \n \r \t \uXXXX`) are
no longer treated as `DOMAIN\user` in JSON-encoded content. Plain-text `.log` detection is
unchanged.

## What's new in v2.7.4

Two detection defects that reached the output, and one documentation gap.

### MAC addresses with mixed separators are no longer written in clear (#22)

`RE_MAC_COLON` alternates `:` and `-` *per separator*, so it matches `aa-bb:cc-dd:ee-ff` as one
address — but the masking picked a single separator, split on that alone, got fewer than six groups
and returned the input untouched. Detection was right; only rendering was broken, so the address
shipped in clear. Across 1280 generated contexts (all 32 separator patterns × 8 prefixes × 5
suffixes), v2.7.3 leaves 1200 MAC literals in the output; v2.7.4 leaves none.

The mask now keeps each separator where it was: `aa-bb:cc-dd:ee-ff` → `**-**:**-**:**-ff`.
Consistent-separator forms are byte-identical to v2.7.3.

The alternative — narrowing the pattern so mixed forms stop matching — was rejected. An undetected
entity is in no map, and `--paranoid` only scans literals it already knows about, so the tool would
have gone *silent* on exactly this shape. A flagged leak beats a silent miss.

### Bare SSH MD5 fingerprints are redacted rather than carved up (#23)

A 16-pair hex fingerprint written without the `MD5:` tag was being taken apart by both other
channels — spurious MAC matches and spurious IPv6 matches — and came out as a run of IPv6 masks with
fragments of the original still visible. It was in no SSH map, so `--exclude ssh-fp` could not
preserve it either.

Both MD5 forms are now claimed before the MAC and IPv6 passes, which back off where they overlap.
A 16-pair run can be neither a MAC (exactly six groups) nor an IPv6 (at most eight hextets), so
there is no other legitimate owner.

```
before:  ****:****:****:****:****:****:****:89:****:…:89
after:   [REDACTED SSH KEY]
```

### `--paranoid` and `.zip` input (#17)

`--paranoid` is skipped whenever the **input** is a `.zip` — not only when the output is one — and
that was documented nowhere while two other recommendations pointed straight at it. See
[the caveat](#--paranoid-does-not-cover-zip-output) above.

## What's new in v2.7.3

Three defects where a flag or a report did not do what it said. All three predate v2.7.

### `--exclude mac` now preserves MAC addresses with hex letters (#13)

A colon MAC containing hex letters also satisfied the IPv6 heuristic, so it was claimed by both
channels — and since `--exclude mac` only empties the MAC sets, the address stayed anonymized
through the untouched IPv6 one. It also got the IPv6 mask rather than the `**:**:**:**:**:77` form
this README documents. `00:50:56` is the VMware OUI, so hex-letter MACs are the norm in a Veeam
bundle, not the exception; the all-digit case worked only by accident of having no `a`–`f` digit.

The MAC channel now claims MAC-shaped strings first, standing aside only when two things both
hold: the match is immediately preceded by `::`, **and** the IPv6 pattern actually matches at that
position and passes the same gate the IPv6 pass applies.

The `::` is what makes the match a fragment rather than a whole value: the IPv6 pattern needs two
groups before a `::`, so it cannot begin at `fd00` in `fd00::aa:bb:cc:dd:ee:ff` and captures only
the tail. That is the one case the hand-off is for. A bare `00:50:56:96:AA:77` belongs to the MAC
channel, which is what #13 is about.

The second half asks the pattern instead of approximating it, and that distinction is the whole
lesson here. Every proxy for "IPv6 will take this" let some shape slip through to *neither* channel:
backing off on any adjacent colon dropped `Adapter:00-50-56-96-AA-78`; backing off on the `::`
prefix alone dropped `::00-50-56-96-AA-61` and `fd00::00:11:22:33:44:63`; adding "is
colon-separated" still dropped `fd00::aa-bb:cc-dd:ee-ff`, because the MAC pattern alternates `:`
and `-` *per separator* while the IPv6 pattern cannot cross a `-`. Each of those shipped in clear
with no flags — and `--paranoid` cannot see it, because an entity in no map is in no scan list.

`--exclude ipv6` changes too, in the same direction: a compressed address whose tail happens to be
six two-hex-digit groups (`fd00::aa:bb:cc:dd:ee:ff`) used to be masked *through the MAC channel*
even with `ipv6` excluded, because the MAC channel backstopped it. It is a genuine IPv6 address, so
`--exclude ipv6` now preserves it as asked.

Note that the loopback, unspecified and all-nodes addresses (`::1`, `::`, `ff02::1`) and `fe80::1`
are deliberately left visible, as before — a full tail such as `fe80::1234:5678:9abc:def0` is still
masked.

The invariant behind all of this is asserted directly in the test suite: no MAC-shaped match may end
up claimed by *neither* channel. (Both claiming it is allowed and harmless — it means the value is
masked twice over.) Three attempts at this hand-off each dropped a different shape, and none of them
showed up in a shape-by-shape corpus until someone tried that shape, so the property is asserted
rather than reasoned about — the test is verified to fail on each of the earlier versions.

The `--exclude` help text also listed only 9 of the 16 types the parser accepts; it now lists all
of them.

### `--exclude domain` is no longer undone by the email path (#14)

Building an email's replacement fabricated a domain mapping and registered it — but that branch
could only run once `--exclude domain` had emptied the map, so it existed solely to re-create the
mapping the operator asked to skip, and it applied to *every* occurrence of that domain, not just
the one inside the address. The run contradicted itself in its own output:

```
  Skipped 1 domain(s) (excluded)
  Found: 1 emails, 0 users, 1 domains, ...      <- 1 domain, right after "Skipped"
```

`--exclude email` also changed: it now preserves the whole address instead of keeping the local
part and rewriting the domain, which was neither readable nor anonymized. See
[`domain` and `email` overlap](#domain-and-email-overlap--how-the-two-compose) for how the two
flags compose. The protection applies to file and zip-entry names too, not only content — an
address kept in the body while the file name carried a rewritten domain half would be the same
half-anonymized result one step further along.

### `--expand-archives` no longer silences the coverage report (#15)

Passing the flag turned off the very warning that says coverage is incomplete, because staging
places only in-set files and the walk that follows therefore found a clean floor. Staging now
tallies what it leaves behind itself. A `.zip` nested inside an expanded archive is reported as
**not covered** rather than vanishing. Details in the
[`--expand-archives` section](#--expand-archives--nested-zip-archives) above.

## What's new in v2.7.2

Three defects found by a QA pass over the whole tool. All three predate v2.7.

### Hostile `.zip` entry names no longer escape the output (#10)

A support bundle is untrusted input — it arrives from a customer by mail or upload — and entry
names were joined onto the output path without sanitising. An entry named `../../ESCAPED.log`
landed **two levels above** the directory given to `-o`, with exit code 0 and no mention in the
output listing. `--output-zip` repacked the traversal name verbatim, so the archive you send to
support was itself a zip-slip archive aimed at whoever extracts it.

Both writers now reduce every destination to a safe relative path, covering `../`, absolute names
and Windows drive/UNC shapes. Entries are **contained rather than discarded** — the content is
still anonymized and still delivered — and every rewrite is reported:

```
  ⚠ 2 zip entr(ies) could not be written under their own name:
      ../../ESCAPED.log  ->  ESCAPED.log
      /tmp/ABS.log  ->  tmp/ABS.log
    Entry names come from the input archive, which is untrusted: an entry named
    `../../x` would otherwise land outside -o and be repacked into the archive
    you send on. Names that collide once made relative get a numeric suffix so
    no entry is lost. The content itself was anonymized as usual.
```

Silently fixing a hostile bundle would deny you the only signal that you received one — so that
warning has to stay meaningful. It fires only on a name that genuinely escapes: a leading `/`, a
`..` segment, or a Windows drive prefix. A trailing `/` on a directory entry and a `./` prefix are
normalisation, not escapes, and stay quiet; otherwise every archive produced by `zip -r` would
trip it and the signal would be worthless. An entry whose name reduces to nothing (`../..`) is
dropped and listed as such.

**Colliding destinations are a separate, benign case, and get their own message.** Two entries can
want the same name without anything hostile going on — most often because the filesystem-safe IP
rendering is lossy, so `Agent.10.0.1.21.log` and `Agent.192.168.1.21.log` both become
`Agent.xx.xx.1.21.log`. That is an ordinary bundle, and telling you it is untrusted would be a
false alarm:

```
  ⚠ 1 zip entr(ies) wanted a destination already taken, and were renamed:
      Agent.xx.xx.1.21.log  ->  Agent.xx.xx.1.21-1.log
    Nothing hostile about this on its own — the filesystem-safe IP rendering
    is lossy, so two addresses sharing their last two octets give one name.
    A numeric suffix keeps both. The content itself was anonymized as usual.
```

This case is worth calling out because v2.7.1 handled it badly on perfectly normal input:
`--output-zip` aborted with `Duplicate filename` and produced nothing, while `-o` silently
overwrote one file and exited 0. Both entries now survive, in every mode — including entries
expanded from a nested archive under `--expand-archives`.

Both messages are printed even when the run later fails part-way through, so an error on a corrupt
entry no longer hides the fact that the same archive also carried traversal names — which matters
in extract mode, where those files are already on disk by then.

### `--validate-only` no longer leaks names through file paths (#11)

The report documents "counts by entity kind and by file — never the original values", but
`by_file[].file` and `source` were the raw paths, which carry hostnames, VM names and job names.
This is the output most likely to leave the machine, since it exists to be piped into `jq` and
automation. Both fields now go through the same mapping the normal output tree uses, so IP/MAC
keep their documented `10.0.0.21` → `xx.xx.0.21` rendering.

The report ignores `--keep-path-names` deliberately: that flag opts a human out of renaming in an
output tree they inspect before sharing, and the report has no such inspection step. Combining the
two prints an explanatory note on stderr. stdout stays pure JSON.

### `--reverse` no longer aborts on a one-way IPv4 mask collision (#12)

IPv4 masking keeps only the last two octets and is deliberately one-way, but it was the only
entity kind with no collision guard. A proxy on `192.168.1.10` and a repository on `10.0.1.10` —
an ordinary addressing convention — both mask to `**.**.1.10`, and the reverse path treated that
as dictionary corruption and refused to run at all. **Nothing** was restored, including entities
in the same file that were perfectly reversible.

The check now separates the two cases it was conflating. A duplicate confined to IPv4 is expected,
since that mapping is many-to-one by design: those entries are left masked rather than guessed,
and named in a warning with every candidate original. A duplicate touching a collision-checked
kind can only come from a tampered dictionary, and still aborts.

```
  ⚠ 1 anonymized value(s) cannot be reversed — IPv4 masking keeps only the last two octets, so distinct addresses that share them produce the same masked string:
    **.**.1.10 <- could be any of: 10.0.1.10, 192.168.1.10
    Left as-is in the restored output. Everything else — including other entities in the same files — is restored normally.
```

Repeated entries carrying the same original — a dictionary exported twice, or concatenated — are
not ambiguous and reverse normally. The mask format in anonymized output is unchanged.

## What's new in v2.7.1

### `DOMAIN\user` is now detected in JSON-encoded traces

v2.7 stopped `RE_DOMAIN_USER` from firing on single-backslash escapes in `.trace` / `.json`
content, which removed a large class of false positives. The mirror-image problem remained: a
*genuine* account is written `DOMAIN\\svc_veeam` there, which a one-backslash pattern can never
match, so it went through in clear while `--paranoid` reported the file clean.

A second pattern now handles the escaped form. Two details matter:

- The mapping key is the raw matched text, doubled separator included — replacement is literal,
  over the bytes on disk.
- The replacement carries the same number of backslashes. Emitting one where the source had an
  escaped pair would turn `"ACME\\svc"` into `"XXXX\YYYY"`, an invalid JSON escape — the same
  corruption the v2.7 rule exists to avoid, from the other direction.

Multi-segment paths are still left alone. In JSON-encoded text a Windows path is a run of
`\\`-separated segments, so only a *doubled* neighbour marks a match as a path — testing for a
single one would reject the common real case, since a `DOMAIN\\user` at the end of a JSON string
is followed by the `\"` that closes it. `C:\\Program\\VeeamBackup\\Backup_Job_1\\run.log` and the
UNC form `\\\\fileserver\\Backups` both survive untouched.

> **Pre-existing false positive, now also reachable in JSON:** a *two-segment* path has no
> adjacent separator to give it away, so `SOFTWARE\Veeam` or `Temp\report.html` is captured as if
> it were an account and rewritten. This is not new — the same strings produce the same junk
> mappings in a plain `.log`, via the single-backslash pattern, in every release so far. What v2.7.1
> changes is only that the escaped spelling is now reachable too, so registry and relative paths in
> `.trace` files join the ones already affected in `.log` files. It costs readability, not safety:
> the replacement is consistent and reversible, and no customer data is exposed by it. Narrowing
> this class needs its own change, since it alters plain-text behaviour as well.

```
before:  {"m":"quoted \"ACME\\svc_veeam\" logged on"}   ->  unchanged, --paranoid clean
after:   {"m":"quoted \"CEinQneP\\8KnzghAb2Y\" logged on"}
```

For the covered case, `--reverse` restores the original bytes exactly. Closes #8.

> **Known gap:** the escaped-form pattern only runs where `ContentKind::for_name` selects
> `JsonEscaped` — i.e. the file extension is `.trace` or `.json`. A `.log` or `.txt` file that
> happens to carry a JSON payload (a common shape when a service logs a structured event into its
> plain-text log) is scanned as `Plain`, so `DOMAIN\\user` inside it is *not* matched: the account
> ships in clear and `--paranoid` reports the file clean, because detection never fires there in
> the first place. One mitigating factor: replacement is entity-wide, not file-scoped — so if the
> account is detected **from a `.trace` or `.json` file** anywhere in the bundle, the doubled-separator
> key enters the map and every escaped occurrence is rewritten, including the ones hiding in `.log`
> files. Note what does *not* help: detecting the same account in plain form elsewhere. A plain
> match yields only the single-backslash key, which cannot match the doubled bytes — so an account
> can be listed in the dictionary, rewritten in one `.log`, and still ship in clear from the escaped
> payload in another, with `--paranoid` reporting clean and an exit code of 0. That is the most
> misleading configuration, and the one to know about. Add such accounts to `--user-list` as a
> stopgap — it replaces the naked username wherever it occurs, domain prefix and backslash count
> notwithstanding:
>
> ```bash
> echo 'svc_veeam' >> ~/.vla/users.txt
> veeam-log-anonymizer -d ./logs -o ./anonymized --user-list ~/.vla/users.txt --paranoid
> ```

## What's new in v2.6.1

Fixes from real-world bundle testing:

- **IPv4 / IPv6 / MAC are now anonymized in file and directory names too.** A folder literally
  named `10.0.0.21` now becomes `xx.xx.0.21` in the output. Their masked forms contain characters
  illegal in Windows path components (`*`, `:`, `\`), so a filesystem-safe rendering is used
  (`*`→`x`, `:`→`-`). These remain **one-way redactions** in names (not reversible — consistent
  with how IP/MAC masking already works in content). Loopback (`localhost`, `127.0.0.1`) is left
  untouched as before.
- **Fewer `--paranoid` false positives.** Windows path segments such as
  `...\VeeamBackup\Backup_Job_1\...` were wrongly captured as `DOMAIN\user` and re-flagged as
  leaks. A `word\word` pair flanked by another path separator is now treated as a path, not an
  account. Genuine `DOMAIN\user` tokens (surrounded by whitespace) are still detected.

## What's new in v2.6

Three backlog features, all shipped together.

### `--validate-only` — dry-run audit with a JSON report

Scan a bundle **without writing anything** and emit a machine-readable JSON report of what
*would* be anonymized — counts by entity kind and by file, **never the original values**.
Built for pipelines / agent orchestration.

- Output to stdout (pure JSON — banner and progress go to stderr) or to `--report-output FILE`.
- **Deterministic exit code**: `0` if no entities detected, `2` if entities were detected,
  `1` on error.
- Reuses the exact same detection engine as anonymization (no logic drift).

```bash
veeam-log-anonymizer -d ./logs --validate-only | jq .summary
veeam-log-anonymizer -d bundle.zip --validate-only --report-output audit.json
```

### Direct `.zip` bundle input

Point `-d` at a support `.zip` directly (auto-detected by extension / PK magic bytes) — no
manual decompression.

- `--output-zip FILE` repacks an anonymized `.zip` (what you send back to support) — note that
  `--paranoid` does **not** re-scan it, see the caveat under the recommended workflow — preserving
  the internal tree and entry timestamps. Otherwise the bundle is extracted, anonymized, into
  `-o DIR`.
- `.log` entries get their content anonymized; other entries are copied byte-for-byte; **every
  entry name** is anonymized (path-safe entities). Processed entry-by-entry (memory bounded).
- The **dictionary is never written inside the zip**.

```bash
veeam-log-anonymizer -d 2026-05-16_VeeamBackupLogs.zip --output-zip anonymized.zip -f -D --dict-output ./keep-safe
```

### Optional dictionary encryption (`--encrypt-dict`)

Opt-in encryption of the reversible dictionary (a credential) with a passphrase, using the
[`age`](https://age-encryption.org/) format. Output gets a `.age` suffix.

- Passphrase from `VLAR_DICT_PASSPHRASE` (automation) or an interactive hidden prompt — **never**
  a CLI argument.
- `--reverse` transparently decrypts a `.age` dictionary (prompts / reads the env var).
- Losing the passphrase means the anonymization can never be reversed.

```bash
veeam-log-anonymizer -d ./logs -o ./out -f -D --dict-output ./keep-safe --encrypt-dict
veeam-log-anonymizer --reverse ./keep-safe/veeam-anonymizer-*.json.age -d ./out -o ./restored -f
```

## What's new in v2.5

### File & directory name anonymization

Resolves [issue #1](https://github.com/BertV44/vlar/issues/1): sensitive entities in
**file and directory names** (e.g. `Task.HOSTNAME-vm....log`, or a folder named after a VM/job)
were copied verbatim into the output. They are now anonymized too.

- **On by default**: path components are anonymized using the same consistent, reversible
  mappings as the file content. Recognizable prefixes (`Task.`, `Agent.`, `Svc.`) and the
  `.log` extension are preserved — only the sensitive token is replaced.
- **Path names are also scanned**: an email / FQDN / IP / backup-file name present *only* in a
  path (never in content) is now auto-detected and anonymized.
- **Reversible**: `--reverse` restores the original file and directory names along with content.
- **`--paranoid`** also re-scans output path names and flags any leaked entity still present.
- **Opt-out**: `--keep-path-names` keeps original names (content is still anonymized).
- Short bare hostnames in names still require `--hostname-list` / `--object-list` (not reliably
  auto-detectable), per the tool's "miss rather than corrupt" philosophy.
- *(Updated in v2.6.1: IPv4/IPv6/MAC are now also anonymized in path names — see below.)*

### Paranoid false-positive fix

Resolves [issue #2](https://github.com/BertV44/vlar/issues/2): backup-file paths such as
`disk.vib\next` or `chain.vbk\n1024` were wrongly captured as `DOMAIN\user` (the "domain"
segment being a file extension), then re-flagged by `--paranoid` as leaks. The `DOMAIN\user`
detector now rejects matches whose domain segment is a known file extension.

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

# Keep company domains readable but still anonymize who sent what:
# admin@acme-corp.com -> k8mN2xpQ@acme-corp.com (local part anonymized, domain kept)
veeam-log-anonymizer -d ./logs -o ./output -f -e domain

# Keep whole addresses readable but still anonymize other domains (see
# "domain and email overlap" below for how the two flags compose)
veeam-log-anonymizer -d ./logs -o ./output -f -e email
```

## Options

| Flag | Long | Description |
|---|---|---|
| `-i` | `--input FILE` | Input log file |
| `-d` | `--directory DIR` | Input directory (recursive) or a `.zip` bundle |
|  | `--ext LIST` | Extra text extensions to anonymize, on top of the built-in set |
|  | `--only-ext LIST` | Anonymize only these extensions, ignoring the built-in set |
|  | `--expand-archives` | Also anonymize `.zip` archives nested inside a `-d` directory |
| `-o` | `--output DIR` | Output directory (required, except with `--validate-only` / `--output-zip`) |
|  | `--output-zip FILE` | Repack the anonymized result into a new `.zip` (zip input) |
| `-f` | `--force` | Force overwrite / create directories |
| `-v` | `--verbose` | Show filenames in progress bar |
| `-m` | `--mapping` | Print mapping table to console |
| `-D` | `--dictionary` | Export mapping to JSON file |
|  | `--dict-output DIR` | Write dictionary to a separate directory (recommended) |
| `-s` | `--stats` | Show detailed statistics |
| `-e` | `--exclude TYPES` | Skip entity types (see below) |
|  | `--dry-run` | Preview without writing files (human-readable console listing) |
|  | `--validate-only` | Scan only; emit JSON report (exit 0/2); writes nothing |
|  | `--report-output FILE` | Write the `--validate-only` JSON report to a file |
|  | `--reverse FILE` | De-anonymize using dictionary JSON (decrypts `.age` transparently) |
|  | `--paranoid` | Re-scan output files to detect any leaked entities (**skipped for `.zip` input** — see below) |
|  | `--aggressive` | Enable detection of standalone FQDNs and naked usernames |
|  | `--user-list FILE` | Explicit list of usernames |
|  | `--hostname-list FILE` | Explicit list of short hostnames |
|  | `--object-list FILE` | Explicit list of customer object names (VMs, datastores, hosts) |
|  | `--db-list FILE` | Explicit list of database names |
|  | `--keep-path-names` | Keep original file/directory names (path anonymization is on by default) |
|  | `--encrypt-dict` | Encrypt the exported dictionary (`-D`) with a passphrase (age) |

### `--exclude` accepted types

`email`, `user`, `domain`, `ip`, `ipv6`, `mac`, `ssh-fp`, `backup-file`, `naked-user`, `fqdn`, `hostname`, `object`, `db`, `pem`, `private-key`, `jwt`

### `domain` and `email` overlap — how the two compose

A "domain" is only ever discovered as the second half of an email address (see
the *Domains (from emails)* row below), and the same domain string is then
replaced everywhere it appears in the corpus — bare or not — so the same
organization always maps to the same anonymized name. `domain` and `email`
therefore interact:

- `-e domain`: every occurrence of the domain is left alone, including the
  domain half of an address that isn't itself excluded — e.g.
  `admin@acme-corp.com` becomes `k8mN2xpQ@acme-corp.com` (local part
  anonymized, domain kept), and a standalone `acme-corp.com` elsewhere in the
  same run is left untouched too. This holds under `--aggressive` as well: a
  3+-segment domain such as `mail.acme-corp.com` is also an FQDN, and the FQDN
  channel honours the exclusion rather than rewriting the standalone
  occurrence while the address keeps it.
- `-e email`: the entire address is preserved byte-for-byte, domain half
  included — a half-rewritten address (original local part, randomized
  domain) is neither anonymized nor readable, which is worse than either. A
  domain that appears *outside* an excluded email is a separate occurrence and
  is still anonymized, unless `domain` is excluded too.
- `-e domain,email`: both the addresses and every domain are fully preserved.

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

### `--paranoid` does not cover `.zip` output

`--paranoid` is skipped whenever the **input** is a `.zip` — not just when the output is one. The
archive is read directly, so pointing `-o` at a directory does not enable the re-scan either. The run
says so at the time:

```
  ℹ --paranoid is skipped for a .zip input in this version, whatever the
     output form — pointing -o at a directory does not enable it either, since
     the archive is read directly. The same detection engine runs, so the
     anonymization is identical; only the re-scan is missing. To paranoid-check
     a bundle, unpack it yourself and run -d against the resulting directory.
```

This matters because two recommendations elsewhere pull against each other: `--output-zip` is
described above as the thing you send back to support, and the workflow below tells you to verify
`--paranoid` reports zero leaks. Combining them does not give you the safety net you would expect.

The route that does work is to unpack the archive with your own tool first:

```bash
mkdir bundle-extracted && (cd bundle-extracted && unzip -q ../bundle.zip)
veeam-log-anonymizer -d ./bundle-extracted -o ./anonymized -f --aggressive --paranoid
# review the report, then zip ./anonymized yourself
```

The same detection engine runs either way, so the anonymization itself is identical — what differs
is only whether the result is re-scanned afterwards.

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
#    NOTE: --paranoid is skipped whenever the INPUT is a .zip, whatever -o is.
#    Unpack the bundle yourself first if you need the re-scan; see the caveat.

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
