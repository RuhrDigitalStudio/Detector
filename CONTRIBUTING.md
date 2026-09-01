# Contributing to Detector

Detector is a defensive, read-only analysis project. Useful contributions make
evidence easier to understand without weakening that boundary.

## Good changes

- A detector backed by a small synthetic fixture and a focused test.
- Better normalization of an established, documented event format.
- Lower false-positive rates with an explanation of the trade-off.
- Clearer coverage reporting, report validation, or analyst-facing language.
- Parser bounds, error handling, accessibility, and reproducible builds.

Do not submit malware, weaponized samples, process injection, hooks, persistence,
evasion, destructive remediation, security-setting changes, credentials,
personal paths, dumps, native binaries, or unexplained generated code.

## Working agreement

1. Open an issue for a material format or architecture change. Use private
   vulnerability reporting for security-sensitive findings.
2. Add a focused failing test before production behavior changes.
3. Keep rules narrow. A match should say what was observed, not declare intent
   or attribution that the evidence cannot support.
4. Add or update Coverage whenever a module can skip, truncate, or fail work.
5. Keep public strings, rule IDs, comments, and documentation in English.
6. Explain non-obvious constraints in comments; avoid narrating straightforward
   code line by line.

Run the full gate before opening a pull request:

```powershell
dotnet restore Detector.slnx
dotnet build Detector.slnx -c Release --no-restore
dotnet test Detector.slnx -c Release --no-build
dotnet format Detector.slnx --verify-no-changes --no-restore
git diff --check
```

For a new rule, test a positive match, a close benign case, stable rule metadata,
and any size/error boundary it introduces. Runtime-event changes should include
valid aliases and malformed-line behavior. Export changes must test untrusted
HTML characters and JSON round trips.

## Provenance

You must have the right to submit every file. Name third-party algorithms,
formats, datasets, icons, and copied test material in the pull request and
include their license where required. Public fixtures must contain no customer
or machine data.
