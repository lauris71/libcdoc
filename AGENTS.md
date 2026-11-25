# AGENTS.md — libcdoc

C++ library for Estonian CDoc (encrypted document) containers — CDoc1 (legacy
DDoc/ENCDOC-XML) and CDoc2 — with a CLI tool (`cdoc-tool`) and language
bindings (Java, C#, Python via SWIG).

CDoc2 standard is available at: https://open-eid.github.io/CDOC2/2.0/

## Repository layout

- `cdoc/` — library sources, headers, and `cdoc-tool.cpp` (CLI)
- `cdoc/schema/` — FlatBuffers schemas (`header.fbs`, `recipients.fbs`) for the
  CDoc2 header
- `doc/` — user and integrator documentation (`doc/filenames.md` documents the
  entry-name policy implemented by this codebase)
- `test/libcdoc_boost.cpp` — Boost.Test unit suite; `test/libcdoc_live_boost.cpp`
  — opt-in live tests against RIA dev servers (SID/MID round-trips, need VPN)
- `test/data/` — RSA/EC test keys and certs (DER)
- `examples/java/` — SWIG Java bindings usage (`CDocTool.java`, Gradle build)
- `libcdoc.i` + `std_*.i` — SWIG interface files
- CMake + vcpkg (`vcpkg.json` manifest; openssl from `open-eid/vcpkg-ports`)

## Main components and interactions

```
                    cdoc-tool.cpp / bindings (libcdoc.i)
                                  |
                              CDocCipher            <- tool-level orchestration
                    (Encrypt/Decrypt, ToolConf, RcptInfo)
                     /            |              \
            CDocWriter/Reader  CryptoBackend   NetworkBackend
            (version dispatch)  (ToolCrypto,    (keyserver, SID/MID
             CDoc1*/CDoc2*       ToolPKCS11,     share servers, TLS)
                                 PKCS11Backend,
                                 WinBackend)
```

- **Format layer** — `CDocWriter`/`CDocReader` (in `CDoc.cpp`) dispatch by
  version to `CDoc1Writer/Reader` (XML via `XmlWriter/Reader`, `DDoc*`) or
  `CDoc2Writer/Reader`. CDoc2 layout: FlatBuffers header (recipients/capsules)
  + header HMAC, then payload = ChaCha20-Poly1305 stream → zlib → tar (PAX
  headers for long/Unicode names).
- **Streaming I/O** (`Io.h/cpp`) — `DataSource`/`DataConsumer` abstractions:
  `IStreamSource`/`OStreamConsumer` (files), `VectorSource`/`VectorConsumer`
  (memory), `FileListSource`/`FileListConsumer` (multi-entry extraction),
  `MultiDataSource`/`MultiDataConsumer` for tar-style entry iteration.
  `DecryptionSource` (`Crypto.cpp`) does streaming AEAD and verifies the tag in
  `close()`; `ZSource` (`ZStream.h`) inflates with a decompression-bomb cap.
  `TarSource`/`TarConsumer` (`Tar.cpp`) wrap/unwrap tar entries.
- **Crypto** (`Crypto.h/cpp`) — OpenSSL wrappers (HKDF extract/expand, PBKDF2,
  HMAC, ChaCha20-Poly1305, AES-GCM, RSA-OAEP with implicit-reject unpadding,
  EC/ECDH). `CryptoBackend` is the pluggable interface (`getSecret`,
  `decryptRSA`, `deriveECDH1`, `deriveHMACExtract`, `extractHKDF`, `sign`,
  `random`); `PKCS11Backend` adds token-based keys (`connectToKey` selects
  key by slot/PIN/id/label), `WinBackend` for NCrypt. Memory hygiene:
  `SecureBytes`/`SecureTarget`/`Cleanser` (`cdoc/utils/memory.h`).
- **Recipients/Locks** — `Recipient` (encryption side: `makeCertificate`,
  `makePublicKey`, `makeSymmetric`, `makeShare`) and `Lock` (decryption side,
  parsed from the container; supports machine-readable `data:,label=...`
  labels).
- **Network** (`NetworkBackend.h/cpp`, bundled `httplib.h`) — keyserver
  send/fetch, SID/MID authentication for share-based recipients
  (`KeyShares.cpp`: `SIDSigner`/`MIDSigner`), TLS peer cert handling
  (`TLSKey.cpp`).
- **Config** (`Configuration.h/cpp`, `ToolConf.h`) — `Configuration::getValue`
  key/value model; `ToolConf` adds servers, `params` map (e.g.
  `ALLOW_PATHNAMES`), `input_files`/`out`, `no_overwrite`. Notable keys:
  `ALLOW_PATHNAMES`, `CDOC2_MAX_DECOMPRESSED_SIZE`, `KEYSERVER_SEND_URL`/
  `KEYSERVER_FETCH_URL`, `SHARE_SIGNER`, SID/MID domain settings.
- **Utils** — `isValidUtf8` (strict RFC 3629: rejects overlong encodings,
  surrogates, > U+10FFFF), `sanitiseExtractedFilename`, `deduplicateFilename`/
  `filenameDedupKey` (ASCII-case-folded clash detection, `" (N)"` rename),
  `encodeName`/`decodeName` (UTF-8 ↔ `fs::path`, Windows-safe).

## Security-sensitive invariants

These were added deliberately; preserve them when touching the code:

1. **Payload integrity is always the main error.** Per the CDoc2 standard, if
   the AEAD tag check fails, report that (`HASH_MISMATCH`) *instead of* any
   earlier mid-decryption error. Every failure path in `CDoc2Reader` calls
   `verifyPayloadIntegrity()` first (see `nextFile`, `readData`, `decrypt`).
   `decryptAllAndClose()` drains the stream before `close()` verifies the tag.
   Clients must call `finishDecryption()` after the extraction loop *in all
   cases* (including error exits): it always drains + verifies and its
   verdict — or the previously recorded one — overrides local errors.
2. **Filenames from containers are attacker-controlled.** `sanitiseExtractedFilename`
   runs before any path composition (rejects separators, `..`, drive letters,
   NUL, reserved Windows device names). Writers/Readers reject duplicate entry
   names (case-insensitively); `FileListSource`/`FileListConsumer`/`CDocCipher::Decrypt`
   rename on clash instead of overwriting.
3. **Pathnames are opt-in.** With `ALLOW_PATHNAMES` unset (default), names are
   stripped to basenames both on write and read. When set, clean relative paths
   (`a/b/file.txt`) are preserved but absolute paths and `..` are rejected.
   `cdoc-tool --allow-pathnames` enables it; `--no-overwrite` additionally
   dedups against existing on-disk files (covers Unicode-normalization clashes).
4. **Key material is wiped.** FMK/KEK/shared secrets use `SecureTarget`/
   `Cleanser` so early-return paths cannot leak; don't replace with raw
   `std::vector<uint8_t>`.
5. **PBKDF2 iteration counts are bounds-checked** at parse and write time
   (`CryptoBackend::KDF_ITER_MIN_ENCRYPT`/`MAX_ENCRYPT`/`MAX_DECRYPT`).

## Build and test

- Configure: CMake with vcpkg toolchain (presets in `CMakePresets.json`,
  e.g. `macos-debug`). `vcpkg.json` pins a `builtin-baseline`; if vcpkg errors
  on a missing baseline/commit, run `git -C $VCPKG_ROOT fetch origin master`
  and re-bootstrap if the tool is old.
- Build tests: `cmake --build build/macos-debug --target unittests`
- Run tests: `cd test && ../build/macos-debug/test/unittests` (also
  `--run_test=SuiteName`). The suite must pass with **No errors detected**.
- Java: `cd examples/java && ./gradlew test` (needs `cdoc_java` built first;
  `SKIP_JAVA_TESTS=YES` skips the Gradle build when cross-compiling).
- Live SID/MID tests are excluded by default; enable with
  `LIBCDOC_LIVE_TESTS=1` and a build configured with
  `-DLIBCDOC_ALLOW_INSECURE_TLS=ON` (RIA dev servers, VPN required).

## Conventions

- Errors are `libcdoc::result_t` codes (`CDoc.h`); `FAIL("msg", code)` in
  writers returns `fail(...)`. Logging via `LOG_ERROR/WARN/INFO/DBG/TRACE`
  (and `LOG_TRACE_KEY` for secrets — compiled out unless trace-key logging).
- `std::string` file names are UTF-8; convert to filesystem paths with
  `encodeName`/`decodeName`, never via implicit `fs::path(std::string)` on
  Windows.
- `ToolConf::getValue` is `final`; extend config behavior by subclassing
  `libcdoc::Configuration` (see `RawPathConf` in `CDocCipher.cpp`) or by
  adding to `ToolConf::params`.

## Coding style

- **Naming**: Use `snake_case` for variables and functions, `CamelCase` for types and classes.
- **Memory**: Prefer `SecureBytes`/`SecureTarget` over raw `std::vector<uint8_t>` for cryptographic material.
- **Error handling**: Return `result_t` codes; never throw exceptions from library functions.
- **Logging**: Use `LOG_*` macros; never log secrets (use `LOG_TRACE_KEY` only when enabled).
- **Testing**: Add unit tests for new features; use existing patterns for error handling and edge cases.
- **Comment**: Add doxygen comment for public api. Always explain why something is done, not only what is done.
- **Code organization**: Try to keep code human readable - break long blocks into semantic units with comments explaining the intent.

