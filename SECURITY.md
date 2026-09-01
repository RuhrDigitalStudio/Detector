# Security policy

## Supported versions

Detector is currently a release candidate. Security fixes are made on the
latest published release line; old source snapshots are not maintained. Verify
the commit or release checksum before investigating sensitive material.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting for this repository when available, or contact the
maintainer privately through the RuhrDigitalStudio organization profile.

Include the affected version or commit, impact, environment, and minimal safe
reproduction steps. Do not attach malware, credentials, private source code,
memory dumps, customer data, or production logs. A synthetic input that
demonstrates the same parser or boundary issue is strongly preferred.

## Security boundary

Detector is intended to read evidence. The following are security invariants:

- Selecting a file, directory, report, or trace must not execute its content.
- PE and managed metadata inspection must not load the inspected assembly.
- Report rendering must encode untrusted strings and remain self-contained.
- Input sizes, decoding work, event counts, metadata collections, and report
  reads must remain bounded.
- Process inspection must use read-only access and must not write, inject, hook,
  suspend, resume, or terminate another process.
- Detector must not create persistence, alter security settings, quarantine, or
  delete an inspected file.
- Coverage loss and parser failures must be visible rather than converted into
  a clean result.

Reports about violating these invariants, unsafe path handling, HTML/script
injection in reports, denial of service through crafted input, sensitive-data
leakage, dependency provenance, or update/release integrity are in scope.

AMSI provider quality, a heuristic false positive/negative by itself, and lack
of access to a protected process are normally operational limitations rather
than product vulnerabilities. They are security issues when Detector hides or
misrepresents the resulting loss of coverage.

## Safe verification

Use repository fixtures, harmless synthetic files, or official EICAR/AMSI test
artifacts. Run unknown samples only in tooling and environments designed for
malware detonation; Detector itself is deliberately not such an environment.
