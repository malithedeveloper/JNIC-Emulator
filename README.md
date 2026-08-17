# JNIC Emulator

[![Rust 1.85+](https://img.shields.io/badge/Rust-1.85%2B-b7410e?logo=rust&logoColor=white)](https://www.rust-lang.org/)

JNIC Emulator is a safe, source-only Rust analyzer and emulator for inspecting JNIC-protected Java archives and their embedded Windows x86-64 payloads. It supports both bounded static control-flow analysis and isolated dynamic execution with direct Java code recovery, without ever loading or executing target code on the host system.

> [!IMPORTANT]
> Analyze only software you own or are explicitly authorized to inspect. Malicious or unauthorized use is prohibited by the project license.

The project is independent and is not affiliated with, endorsed by, or sponsored by any third-party product, project, or vendor.

## What it does

- Reads JAR/ZIP members with path, size, CRC, and decompression safeguards.
- Parses JVM class files and modified UTF-8 without starting a JVM.
- Finds the loader and `.dat` resource from class/archive evidence instead of a target-specific path or identifier.
- Decodes raw LZMA2 resources entirely in memory under a configurable limit.
- Locates and validates an embedded PE32+ x86-64 image.
- Parses PE sections, exports, imports, exception-directory function boundaries, and image metadata.
- Maps loader exports to native Java methods through registration-stub analysis.
- **Static mode**: decodes x86-64 instructions as inert data, computes basic blocks, branches, loops, and traces JNI function-table calls.
- **Dynamic mode**: runs target methods inside isolated Unicorn emulator memory with synthetic JNI/import stubs and keystream seed recovery to recover clean, readable Java source code.
- Produces deterministic, human-readable text reports and optional Java source files with SHA-256 provenance.

It does **not** start Java on the host, execute target DLLs natively, call `DllMain`, resolve host OS imports, or execute any target instructions on the host CPU.

## Version support

Support is based on the native resource layout and loader structure, not only a version string. The following matrix separates versions tested end to end from formats that are merely expected to be similar:

| Product / format | Status | Evidence |
| --- | --- | --- |
| JNIC 3.5.1, Windows x86-64 | **Verified (Static + Dynamic)** | JavaObfuscatorTest fixture: 50/50 native methods mapped, isolated dynamic trace and Java recovery verified |
| JNIC 3.7.0, Windows x86-64 | **Verified (Static + Dynamic)** | JavaObfuscatorTest fixture: 50/50 native methods mapped, isolated dynamic trace and Java recovery verified |
| Other JNIC 3.x releases using the same loader, raw LZMA2, and PE32+ layout | **Expected, not guaranteed** | Format-driven discovery should apply, but no fixture has been verified yet |
| Newer or older JNIC layouts | **Unverified** | A format change may require parser or mapper updates |
| Standalone Windows x86-64 PE32+ payloads | **Metadata supported** | Sections, imports, exports, and function tables are parsed; Java method mapping is unavailable |
| ARM64 native payloads | **Not supported** | The current instruction engine is x86-64 only |

“Verified” means that archive discovery, class parsing, resource decoding, PE validation, native registration mapping, x86-64 decoding, JNI-origin tracing, and report generation all completed successfully. It does not promise exact source-code recovery or compatibility with every configuration of that release.

## Processing pipeline

![Processing workflow](docs/images/workflow.svg)

1. The input is size-checked and hashed.
2. JAR entries and Java class files are parsed as data.
3. Loader/resource evidence is cross-checked; ambiguous pairs are rejected.
4. The raw LZMA2 stream is decoded under a strict output limit.
5. The embedded PE32+ image is validated and its metadata tables are read.
6. Native methods are mapped, decoded, and explored with bounded state counts.
7. A text report is written. Target instructions executed on the host: **zero**.

## Requirements

- Rust 1.85 or newer
- Cargo
- Linux, macOS, or Windows host

All runtime parsing and decoding dependencies are Rust crates. No copied DLL, prebuilt analyzer, Java installation, Capstone installation, or Unicorn installation is required.

## Build

### Static mode only (default, lightweight)

```bash
git clone https://github.com/malithedeveloper/JNIC-Emulator.git
cd JNIC-Emulator
cargo build --release
```

### Static + Dynamic mode (with Unicorn backend)

Requires `libunicorn-dev` (or `unicorn` on Arch/CachyOS/macOS).

```bash
cargo build --release --features dynamic
```

The executable will be at:

- Linux/macOS: `target/release/jnic-emulator`
- Windows: `target\release\jnic-emulator.exe`

## Usage

### Static analysis

```bash
jnic-emulator analyze input.jar --output analysis.txt
```

### Dynamic analysis & Java code recovery

```bash
jnic-emulator analyze input.jar   --mode dynamic   --output analysis.txt   --java-output recovered.java
```

Inspect a raw Windows x86-64 payload:

```bash
jnic-emulator analyze native.dll --output pe-analysis.txt
```

Run deterministic internal checks:

```bash
jnic-emulator self-test
```

During analysis, the terminal explicitly confirms the safety model:

```text
[*] Parsing input as inert data: input.jar
[*] Target machine code will not be loaded or invoked.
[+] Report written: analysis.txt
[+] Classes: 31 | Methods: 50 | Mapped: 50 | Warnings: 0
```

### Resource limits

Every large allocation or traversal has a defensive bound. Defaults can be changed for an unusually large sample:

| Option | Default | Meaning |
| --- | ---: | --- |
| `--max-input-mib` | 1024 | Largest accepted input file |
| `--max-entry-mib` | 512 | Largest uncompressed JAR member |
| `--max-decoded-mib` | 1024 | Largest decoded native resource |
| `--mode` | `static` | Analysis mode: `static` or `dynamic` |
| `--java-output` | none | Output file path for recovered Java source code |
| `--max-method-instructions` | 250,000 | Decode budget per native method in static mode |
| `--max-path-states` | 25,000 | Control-flow state budget per native method in static mode |
| `--max-dynamic-instructions` | 2,000,000 | Maximum emulated instructions per dynamic path |
| `--max-dynamic-scenarios` | 16 | Maximum explored dynamic branch scenarios per method |
| `--dynamic-timeout-ms` | 500 | Emulation timeout per dynamic path in milliseconds |

Example:

```bash
jnic-emulator analyze input.jar \
  --output analysis.txt \
  --max-input-mib 256 \
  --max-decoded-mib 512 \
  --max-path-states 10000
```

Do not raise limits for untrusted samples unless the analysis environment has enough memory and CPU capacity.

## Understanding the report

The report is split into four evidence layers:

### 1. Input provenance and safety state

The header records input type, byte size, SHA-256, loader class, resource name, decoded size, PE base, and entry point. The entry point is metadata and is never called.

### 2. PE metadata

The section list shows which ranges are executable in the target image. “Executable” describes PE flags only; the bytes remain ordinary data in this process. Imports are names and IAT offsets only. They are never resolved against host libraries.

### 3. Java-to-native mapping

For each protected class, the report displays its loader export, declared native method count, and discovered registration targets. Each method includes its Java declaration and mapped native RVA.

### 4. Bounded static emulation

For every mapped function, the engine reports:

- decoded instruction and basic-block counts;
- conditional branches and backward-edge loop candidates;
- explored control-flow states and whether a safety limit was reached;
- direct and indirect call counts;
- recognized JNI functions and their call-site RVAs.

These are conservative observations, not reconstructed original source code. Optimizations, obfuscation, unusual calling conventions, incomplete PE unwind metadata, or newer protection layouts can reduce precision.

## Architecture

```text
src/
├── main.rs          CLI, limit validation, report and Java source writing
├── analyzer.rs      pipeline orchestration and Java/native mapping
├── archive.rs       bounded ZIP/JAR and raw LZMA2 handling
├── classfile.rs     JVM class-file and modified UTF-8 parser
├── descriptor.rs    Java type/method descriptor parser
├── pe.rs            PE32+ parser and registration target scanner
├── emulator.rs      bounded static x86 control-flow and JNIEnv-origin tracing
├── dynamic.rs       isolated x86-64 emulator and Java source reconstruction
├── dynamic_model.rs execution modes and dynamic analysis data structures
├── loader_seeds.rs  deterministic ChaCha20 keystream and seed recovery
├── jni.rs           public JNI ABI slot names
├── report.rs        deterministic evidence report and Java source renderer
├── limits.rs        centralized defensive defaults
└── lib.rs           public library surface and safety contract
```

Parsing helpers use checked offsets and integer conversions; malformed or ambiguous data returns an error instead of selecting a guessed payload.

## Tests and quality checks

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo run -- self-test
```

The test suite covers descriptor validation, modified UTF-8, bounded writers, JNI ABI slots, loader-export decoding, report units, and parser truncation behavior. Real samples are deliberately not distributed in this repository.

### JavaObfuscatorTest validation

End-to-end compatibility was checked against the public [huzpsb/JavaObfuscatorTest](https://github.com/huzpsb/JavaObfuscatorTest) repository at commit [`d3e2539`](https://github.com/huzpsb/JavaObfuscatorTest/commit/d3e2539fb244477ca0972cf88b45b6a35c8c6594). That revision documents both samples as built with JNIC flow obfuscation and string obfuscation enabled.

The fixtures were analyzed with the release build and default safety limits:

```bash
cargo build --release

target/release/jnic-emulator analyze \
  ../JavaObfuscatorTest/sample/JNIC-3.5.1.jar \
  --output /tmp/jnic-3.5.1-analysis.txt

target/release/jnic-emulator analyze \
  ../JavaObfuscatorTest/sample/JNIC-3.7.0.jar \
  --output /tmp/jnic-3.7.0-analysis.txt
```

Results recorded on 2026-08-09:

| Fixture | SHA-256 | Classes parsed | Protected classes | Methods mapped | x86 instructions | JNI sites | Warnings |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| JNIC 3.5.1 | `403814307b00bb5902ec336a3bef158c33e3dd349fed7fdb0cb683f77cd82e19` | 50 | 31 | 50/50 | 17,261 | 804 | 0 |
| JNIC 3.7.0 | `b26db8ed5c425fa492ed633d16942fd3d751c7a4c928b9d0b8dc9ebf688ab70a` | 50 | 31 | 50/50 | 15,858 | 862 | 0 |

The third-party fixtures and generated reports are not redistributed here. The counts above describe this project revision and the linked fixture revision; later changes to either repository may produce different evidence counts.

## Supported scope

Currently supported:

- standard ZIP/JAR containers;
- JVM class files using current constant-pool tags;
- raw LZMA2 native resource streams;
- embedded or standalone Windows PE32+ x86-64 images;
- native method mapping through the loader-export/registration pattern;
- x86-64 static control flow and JNI table-call recognition.

Known limitations:

- ARM64 payloads are not decoded.
- ZIP64-specific layouts and encrypted members are intentionally outside the core workflow.
- Exact high-level decompilation is not attempted.
- Self-modifying code, runtime-generated registration, and environment-dependent paths may not be visible statically.
- Raw DLL input lacks Java class metadata, so method names cannot be mapped.

## License and responsible use

The [project license](LICENSE) permits lawful analysis, education, and interoperability work. Copies and derived work must reference this repository. Malicious activity and unauthorized access are prohibited.

This is a source-available license, not an OSI-approved open-source license. Review it before using or redistributing the project.

For academic or technical work, use the metadata in [`CITATION.cff`](CITATION.cff). A concise acknowledgement is:

```text
JNIC Emulator — https://github.com/malithedeveloper/JNIC-Emulator
```

## Responsible disclosure

Do not submit real customer archives, private payloads, credentials, or proprietary analysis reports to public issues. For a parser bug, provide the smallest synthetic reproduction you can legally share. Security issues should follow [`SECURITY.md`](SECURITY.md).
