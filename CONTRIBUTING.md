# Contributing to Detector

Detector is defensive, read-only analysis software. Contributions must preserve
that boundary.

## Before opening a change

1. Discuss material design changes in an issue or private security report.
2. Do not add malware, payloads, persistence, process injection, evasion,
   destructive remediation, credentials, personal paths, or built artifacts.
3. Use harmless synthetic fixtures, EICAR, or official AMSI test artifacts only.
4. Add a focused failing test before changing production behavior.
5. Run the relevant tests, then the full test project, Release build, and
   format verification.

## Development checks

```powershell
dotnet test tests/Detector.Tests/Detector.Tests.csproj
dotnet build Detector.slnx -c Release
dotnet format Detector.slnx --verify-no-changes
```

Keep public strings and comments in English. Do not present a clean summary as
proof of complete coverage when process access is denied or AMSI initialization
fails; make those conditions visible to the user.

## Provenance

Contributors must have the right to submit their code and assets. Third-party
code, native binaries, and generated files need documented provenance before
they can be accepted into a public release.
