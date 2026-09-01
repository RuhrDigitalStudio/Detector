# Detector 2.0 design

## Purpose

Detector 2.0 is a local Windows triage workbench for defenders who need a fast, explainable first view of a suspicious script, source tree, managed assembly, native PE or captured runtime trace. It brings evidence from the existing scanners into one case instead of presenting unrelated alerts.

Detector does not execute samples. Live features observe already-running processes and Windows telemetry with read-only APIs. Runtime behavior from a detonation environment is imported as evidence rather than reproduced on the analyst workstation.

## Product boundaries

- No sample execution, injection, persistence, quarantine, deletion or automatic remediation.
- No claim that a clean result proves an artifact is safe.
- No cloud upload and no hidden network activity.
- No opaque risk number without the evidence, confidence and coverage that produced it.
- Parsers are bounded. A malformed artifact becomes an analysis error, not a process crash.
- Rules identify observable behavior and suspicious combinations. They do not label ordinary APIs as malware in isolation.

## Primary workflow

1. The analyst opens one or more files, a source directory, or a JSONL runtime trace.
2. Detector fingerprints each artifact and selects safe parsers from content, not only the extension.
3. Modules emit findings, indicators, artifact facts and coverage records into an analysis case.
4. The correlation engine groups related evidence into capabilities with explicit confidence.
5. The GUI shows an executive summary first, then findings, indicators, artifacts and timeline details.
6. The case can be exported as stable JSON and a self-contained, HTML-encoded report.

The CLI exposes the same service for scripts and repeatable collection pipelines.

## Analysis case model

An `AnalysisCase` has a schema version, case id, creation time, optional title, artifact profiles, findings, indicators, capabilities, timeline events and coverage records.

- **Artifact profile:** path label, size, SHA-256, detected kind, architecture, managed/native status, target framework, entry point, signature/trust summary, PE sections, assembly references, native imports and notable metadata.
- **Finding:** stable rule id, source module, target, severity, verdict, explanation and optional evidence location.
- **Indicator:** typed value (`url`, `domain`, `ip`, `file`, `registry`, `mutex`, `command`, `hash`), normalized value, source and context. Duplicates are merged while preserving sources.
- **Capability:** stable id, plain-language title, confidence (`low`, `medium`, `high`), supporting rule ids and a short explanation.
- **Timeline event:** UTC timestamp when known, provider, event name, process identity and a bounded property map.
- **Coverage:** module name, state (`completed`, `partial`, `unavailable`, `failed`) and a reason. This prevents an inaccessible process or unavailable AMSI provider from looking like a clean scan.

Exports order collections deterministically so two scans can be meaningfully diffed.

## Static artifact analysis

### Common fingerprint

Every readable file gets bounded metadata: size, SHA-256, Shannon entropy, magic-based kind and extension mismatch. Oversized files can still be fingerprinted through streaming, but content modules record that deep analysis was skipped.

### PE and .NET

`System.Reflection.PortableExecutable` and `System.Reflection.Metadata` are used in metadata-only mode. Detector never loads the inspected assembly into the runtime.

The analyzer reports:

- PE machine, subsystem, timestamp, image characteristics and section layout;
- managed/native classification, assembly identity, target framework and entry point;
- assembly references, declared types and method names within documented bounds;
- P/Invoke modules and entry points;
- native import names when safely available;
- notable API families such as process access, memory modification, remote-thread creation, networking, registry, services, scheduled tasks, credential APIs and dynamic assembly loading.

Single API references are context. Combinations such as process access + remote memory write + remote execution produce a stronger capability.

### PowerShell and C# source

PowerShell analysis keeps the original and safely decoded text layers. It adds bounded extraction of URLs, IP addresses, domains, registry paths, suspicious command lines and relevant file paths. Rules cover download/execute chains, encoded content, reflection loading, process injection primitives, persistence locations, Defender exclusions and credential access.

C# source analysis uses lexical patterns rather than compilation. It reports interop declarations, dynamic loading, process/memory APIs, persistence APIs, network retrieval and command execution. Comments and string context are retained as evidence, and rules remain explicit about false positives.

## Correlation and assessment

Correlation is deterministic and rule based. Capabilities require one strong signal or a defined combination of weaker signals. Examples:

- `capability.process-injection`: remote process access plus memory write/allocation plus remote execution;
- `capability.download-execute`: network retrieval plus process/script execution;
- `capability.persistence`: scheduled task, service or autorun modification;
- `capability.dynamic-loading`: reflection or unmanaged dynamic library loading;
- `capability.defense-evasion`: execution-policy bypass, hidden launch or security-setting modification;
- `capability.credential-access`: credential store, LSASS or browser credential evidence.

The case assessment reports the highest supported verdict, counts by severity, coverage gaps and the strongest capabilities. It never upgrades a clean AMSI result into a guarantee.

## Runtime evidence import

Detector accepts bounded UTF-8 JSON Lines. The native schema contains `timestamp`, `provider`, `event`, optional `processId`, `processName`, `image`, `commandLine` and a string property object. A tolerant adapter also recognizes common Sysmon field names. Unknown fields are retained only within per-line and property-count limits.

Import normalizes time to UTC, extracts indicators from command lines and properties, and emits findings for documented event combinations. Invalid lines create coverage errors with line numbers; they do not abort valid earlier evidence unless the configured error limit is exceeded.

Detector does not launch a sandbox or execute the referenced image. The README describes how to collect traces in an isolated lab and then import them.

## GUI

The WPF app becomes a case dashboard with a calm, high-contrast dark theme:

- left navigation for New analysis, Runtime trace, Live monitor and Processes;
- top health strip for AMSI, elevation and current coverage;
- summary cards for assessment, artifacts, indicators and coverage gaps;
- filterable findings table with a readable details pane;
- separate Indicators, Artifacts and Timeline views;
- progress, cancellation, drag-and-drop and empty states;
- export to JSON or HTML.

The main view model consumes an analysis service interface. Dialogs and dispatching stay in the window layer so case behavior can be tested without a live WPF application.

## Compatibility

Existing `scan-file`, `scan-dir`, `scan-ps`, `scan-proc`, `watch`, `monitor` and `selftest` commands remain. New `analyze` and `import-trace` commands produce the case model. Existing JSONL finding output remains supported.

## Testing

- Synthetic PE/.NET fixtures come from the test assembly itself or small generated metadata, never malware.
- Script and source fixtures use inert tokens and placeholder domains.
- Import tests use synthetic JSONL events.
- Parser tests cover truncation, excessive sizes, invalid UTF-8, duplicate indicators and deterministic ordering.
- Correlation tests prove both positive combinations and near-miss false-positive controls.
- View-model tests use an in-memory analysis service.
- Existing AMSI/process tests remain provider- and privilege-tolerant.

## Release evidence

CI builds Windows x64, runs all tests and verifies formatting. Tag releases publish the CLI and GUI, include checksums and state that binaries are unsigned unless signing is explicitly added. Public screenshots contain only synthetic paths and results.
