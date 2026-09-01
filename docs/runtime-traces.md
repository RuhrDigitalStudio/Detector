# Runtime trace input

Detector imports one JSON object per line. It accepts its compact normalized
shape and common field names found in JSON exports of Sysmon events. Importing a
trace is an offline operation: Detector parses the file and does not replay or
execute any command it contains.

## Minimal normalized event

```json
{"timestamp":"2026-09-01T08:12:04Z","provider":"Sysmon","event":"ProcessAccess","processId":4120,"processName":"sample.exe","properties":{"GrantedAccess":"0x0020","TargetImage":"C:\\Windows\\System32\\notepad.exe"}}
```

Recognized top-level aliases:

| Meaning | Accepted fields |
| --- | --- |
| Event name | `event`, `EventName`, `eventType`, or a mapped `EventID` |
| Provider | `provider`, `ProviderName` |
| Process ID | `processId`, `ProcessId`, `SourceProcessId` |
| Process image | `processName`, `SourceImage`, `Image` |
| Timestamp | `timestamp`, `timeCreated`, `UtcTime`, `@timestamp` |

Scalar top-level fields and scalar members of `properties` are preserved in the
timeline. Nested objects and arrays are ignored. Timestamps are normalized to
UTC.

## Sysmon event IDs

When no event name is present, Detector maps these IDs:

| ID | Event |
| --- | --- |
| 1 | ProcessCreate |
| 3 | NetworkConnect |
| 7 | ImageLoad |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess |
| 11 | FileCreate |
| 12–14 | RegistryValueSet |
| 22 | DnsQuery |
| 25 | ProcessTampering |

The initial rule set highlights remote-thread creation, process access carrying
memory or thread-modification rights, provider-reported process tampering,
autorun/service registry writes, encoded PowerShell, and Office applications
starting selected script or living-off-the-land processes.

## Bounds and malformed lines

The importer is intentionally bounded. Defaults are 64 MiB of trace text,
1 MiB per line, 100,000 timeline events, 64 scalar properties per event, and
1,000 malformed lines. Invalid lines become `runtime.invalid-line` findings;
valid later lines continue to import until the error limit is reached. Any
truncation or parse error changes Runtime trace coverage to `partial`.

## Collection guidance

- Capture runtime evidence in an isolated VM or established sandbox.
- Export JSONL without secrets that are irrelevant to the investigation.
- Preserve timezone and UTC fields whenever possible.
- Keep the original event export and collection configuration with the case.
- Do not assume Detector's accepted aliases imply compatibility with every
  exporter version; validate a small known trace first.
