# Detector case schema

`detector analyze` and `detector import-trace` write the same case format. JSON
properties use camel case and enum values use lowercase names. The current
`schemaVersion` is `1`.

## Top-level fields

| Field | Type | Purpose |
| --- | --- | --- |
| `schemaVersion` | integer | Contract version. Reject versions your integration does not support. |
| `caseId` | string | Random identifier for one analysis run. |
| `title` | string | Display name derived from the selected input unless supplied by the caller. |
| `createdAt` | ISO 8601 timestamp | UTC creation time. |
| `artifacts` | array | Hashes and metadata for inspected files. |
| `findings` | array | Individual rules and their evidence. |
| `indicators` | array | Deduplicated observable values with source and context. |
| `capabilities` | array | Correlated behavior groups and their supporting rules. |
| `timeline` | array | Imported runtime events. Empty for a static-only case. |
| `coverage` | array | Completed, partial, unavailable, and failed analysis modules. |
| `assessment` | object | Coverage-aware roll-up of the case. |

Collections are emitted in stable order. The case ID and creation time vary by
run; artifact hashes and analysis content remain deterministic for the same
input and engine revision.

## Findings

Each finding has `source`, `target`, `severity`, `verdict`, `rule`, and
`details`. `rule` is the stable machine-facing identifier. Display text may be
improved between releases, so integrations should key on the rule.

Severities are `info`, `low`, `medium`, `high`, and `critical`. Verdicts are
`clean`, `suspicious`, `malicious`, and `error`. An error is not a clean result;
read the matching Coverage record.

## Capabilities

A capability contains:

- `id`: stable identifier such as `capability.process-injection`;
- `title`: concise analyst-facing name;
- `confidence`: `low`, `medium`, or `high`;
- `explanation`: why the evidence was grouped; and
- `supportingRules`: sorted rule IDs used for the correlation.

Capabilities describe observed evidence, not intent, attribution, or reachable
code. Keep the underlying findings in any downstream report.

## Artifacts and indicators

Artifacts include SHA-256, size, detected kind, entropy, optional trust and
PE/.NET metadata, sections, imports, declared members, and API references.
Large metadata collections are bounded; the corresponding Coverage entry says
when inspection was partial.

Indicators carry a `kind`, normalized `value`, and arrays of `sources` and
`contexts`. Supported kinds include URLs, domains, IP addresses, paths,
registry paths, mutexes, commands, and hashes. Detector does not enrich or
contact an extracted endpoint.

## Coverage and assessment

Coverage states are:

- `completed`: the module ran for the stated scope;
- `partial`: only part of the input or event stream was inspected;
- `unavailable`: an optional dependency or permission was absent; and
- `failed`: the module attempted work but could not finish.

The assessment contains finding counts, the strongest severity and verdict, a
short summary, and `coverageWarnings`. Treat those warnings as part of the
result, not optional diagnostics.

## Compatibility

Consumers should reject unknown schema versions, ignore unknown properties in a
known version, and tolerate new rule and capability IDs. Detector rejects null
collections, oversized reports, empty required text, negative artifact sizes,
and unsupported schema versions when reading its own report format.
