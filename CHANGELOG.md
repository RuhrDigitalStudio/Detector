# Changelog

## 2.0.0-rc.1 — 2026-09-01

Detector now builds an analysis case instead of presenting unrelated scanner
lines as one undifferentiated result.

### Added

- Metadata-only PE and managed .NET profiling with hashes, sections, imports,
  trust, assembly metadata, P/Invoke and API-family evidence.
- Bounded C# and PowerShell source analysis, safe decoding layers, and indicator
  extraction.
- Capability correlation with explicit confidence and supporting rule IDs.
- Normalized JSONL and common Sysmon-shaped runtime event import.
- Stable case schema plus deterministic JSON and self-contained HTML reports.
- Redesigned WPF workbench with findings, capabilities, indicators, artifacts,
  timeline, coverage, live sensors, process inspection, filters, and cancellation.
- Synthetic GUI screenshot, schema documentation, runtime import guide, and
  automated build/release workflows.

### Preserved

- Focused AMSI, file, directory, PowerShell, process-memory, polling, and ETW
  commands remain available.

### Safety boundary

- Selected samples are inspected as data and are never launched.
- Runtime behavior is imported from another environment or observed from
  activity already occurring on the current host.
- Detector does not inject, hook, quarantine, delete, persist, or remediate.
