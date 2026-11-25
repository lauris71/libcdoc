# Filename handling

Entry names inside CDoc containers are attacker-controlled: a container can
contain names that are unsafe to write to disk (path traversal, reserved
devices, hidden files) or that clash after the target filesystem folds case
or Unicode normalization. libcdoc therefore applies a strict name policy when
writing and reading containers. CDoc1 follows the same rules as CDoc2 — there
is no separate CDoc1 name standard.

This document describes the name rules and the behavior of the library and
`cdoc-tool`. See also the [Tool](tool.md) and [Usage](usage.md) documents.

---

## Name rules

Names are judged by two independent criteria: **conformance** to the CDoc2
container format ([specification §5.3.1](https://open-eid.github.io/CDOC2/2.0/02_protocol_and_cryptography_spec/ch03_container_format/#requirements-for-posix-tar-archive-assembly))
and **suspicious traits** that are valid to store but hazardous to use.

### Conformant names

A name is conformant when all of the following hold; violations make the name
*non-conformant*:

- valid UTF-8 (RFC 3629 strictly: no overlong encodings, no UTF-16 surrogate
  halves, nothing above U+10FFFF)
- non-empty and at most 1000 bytes
- no Unicode control characters (including tab and DEL), U+202E (right-to-left
  override), U+FFFE or U+FFFF
- relative path only: no leading `/`, no Windows drive letter (`C:`)
- no empty, `.` or `..` path components
- unique in the container (compared case-insensitively, so `A.txt` and `a.txt`
  are duplicates)

### Suspicious names

A conformant name can still be hazardous. Such names are *repaired* on read
output and rejected on write:

| Trait | Repair |
|---|---|
| symbols `<>:\|?*` and `\` | removed |
| leading dots (hidden files on Unix) | each `.` becomes `_` |
| leading space/hyphen, trailing dot/space | trimmed |
| reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) | `_` prefix |
| path component longer than 255 bytes | truncated (short extension kept) |

Repair is idempotent and preserves path shape (it never flattens paths); an
unrepairable name becomes `unnamed`. Examples:

| Stored name | Repaired name |
|---|---|
| `.bashrc` | `_bashrc` |
| `a<b.txt` | `ab.txt` |
| `CON.txt` | `_CON.txt` |
| `x<NUL/ctrl>y.txt` | `x_y.txt` |
| `  -foo.  ` | `foo` |
| `a/../b` | `b` |
| `/etc/passwd` | `etc/passwd` |

---

## Writing (encryption)

**Library.** `CDocWriter::addFile()` and the pull-mode `encrypt()` enforce the
same rules — clean names are stored *verbatim*, anything else is rejected with
`DATA_FORMAT_ERROR`, as are duplicate names. The library never mutates names.

**cdoc-tool.** The tool prepares names before they reach the writer:

- by default the basename is taken (`dir/a.txt` is stored as `a.txt`)
- `--allow-pathnames` preserves clean relative paths (`a/b/file.txt`) and
  rejects absolute paths and `..` components with an error — the name is never
  silently truncated
- suspicious names are repaired (`a<b.txt` is stored as `ab.txt`); a warning
  is logged whenever a name is altered
- clashing names get a ` (N)` suffix before the extension

Note that containers storing pathnames cannot be read by the Java reference
implementation (DigiDoc4j), whose validator rejects `/` in entry names.

---

## Reading (decryption)

Readers return entry names according to the `FILENAME_MODE` configuration
value — `strict` (default), `safe` or `lenient` (`cdoc-tool` flags `--safe`
and `--lenient` select the latter two):

| Stored name | strict (default) | safe | lenient |
|---|---|---|---|
| non-conformant | **fails** (`DATA_FORMAT_ERROR`, no name returned) | repaired | raw |
| suspicious | repaired | repaired | raw |
| duplicate | **fails** | renamed `name (N).ext` | raw |
| clean (incl. relative paths) | verbatim | verbatim | raw |

Notes:

- strict is a conformance gate: a non-conformant container fails to decrypt
  and the error message suggests retrying with `--safe`. The raw offending
  name is never returned or logged — only its repaired form.
- the reader does **not** strip paths: relative paths stored in the container
  are returned as stored. Flattening is the extraction sink's job (below).
- duplicates are detected case-insensitively; a repair that collides with an
  earlier name is renamed rather than rejected.
- in `lenient` mode raw names (including duplicates) reach the caller
  unchanged — intended for inspection/forensics.

---

## Extraction (writing files to disk)

`cdoc-tool` and the library extraction sinks (`FileListConsumer`,
`CDocCipher::Decrypt`) always confine output regardless of the read mode:

- names are flattened to a repaired basename — extraction never creates
  subdirectories and never writes outside the output directory
- clashing names are renamed (`name (N).ext`), case-insensitively
- files that already exist are **never overwritten** by default; `--overwrite`
  opts into replacing them. Files created during the same run are never
  overwritten, even with `--overwrite`.
- collisions are detected by probing the filesystem, which applies its own
  case and Unicode normalization folding (NFC/NFD on macOS APFS, case folding
  on NTFS) — two Unicode spellings of one name cannot silently clobber each
  other
- when extraction aborts with a payload integrity failure or a name policy
  violation, the files created during the run are deleted again
  ([specification §5.3.2](https://open-eid.github.io/CDOC2/2.0/02_protocol_and_cryptography_spec/ch03_container_format/#requirements-for-payload-unpacking))

---

## CLI quick reference

| Flag | Command | Meaning |
|---|---|---|
| `--allow-pathnames` | encrypt | store clean relative input paths instead of basenames |
| `--safe` | decrypt, re-encrypt | extract non-conformant containers with repaired names |
| `--lenient` | decrypt, re-encrypt | extract with entry names as stored (no name checks) |
| `--overwrite` | decrypt | allow replacing pre-existing files (default: rename) |
| `--no-overwrite` | decrypt | no-op alias; never overwriting is the default |

**Re-encrypt** is "decrypt + encrypt without writing files": the read mode
fixes wrong names and the writer validates the result. Use `--safe` to
re-encrypt a container with non-conformant names into a conformant one.

---

## API notes for integrators

- writers accept/reject only, in both push (`addFile`) and pull (`encrypt`)
  entry paths — sanitize names with `libcdoc::repairFilename()` before storing
  if your input may be untrusted
- `libcdoc::isConformantName()` / `libcdoc::hasSuspiciousTraits()` implement
  the two classes above; `repairFilename()` implements the repair table
- readers share one policy engine (`applyFilenamePolicy`); the bulk
  `CDocReader::decrypt()` path and `nextFile()` enforce identical rules
- `FileListConsumer::removeCreated()` deletes the run's files on abort
- clients of `CDocReader` must call `finishDecryption()` after the extraction
  loop in all cases (including error exits): it verifies the payload
  integrity and its verdict is the main error (see [Usage](usage.md))

## References

- [CDoc2 container format, §5.3](https://open-eid.github.io/CDOC2/2.0/02_protocol_and_cryptography_spec/ch03_container_format/)
  — entry name requirements for archive assembly and unpacking
- `Filename-handling-proposal.md` in the repository root — the design and
  decision record behind these rules
