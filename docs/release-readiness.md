# Detector 2.0 release-candidate checklist

Target tag: `v2.0.0-rc.1`

## Public boundary

The source tree contains only the managed read-only analyzer, case/report
model, CLI, WPF workbench, importers, sensors, documentation, and safe synthetic
tests. It deliberately excludes experimental injector, hook, AMSI-provider
registration, launcher, elevation-manifest, and native-binary work from local
development folders. Self-contained archives include Microsoft .NET runtime
dependencies produced by `dotnet publish`; they contain no project-owned native
component.

The public product does not execute selected samples. Its runtime view consumes
exported evidence or observes activity already occurring on the current host.

## Required evidence

- Release build completes without warnings or errors.
- All tests pass in Release configuration.
- Format verification and `git diff --check` pass.
- Framework-dependent and self-contained Windows x64 CLI/GUI publishes succeed.
- CLI static-analysis and runtime-import smoke cases create readable JSON and
  HTML reports.
- The WPF window starts, exposes its controls to UI Automation, and renders the
  reviewed synthetic screenshot in `docs/images/detector-workbench.png`.
- Tracked-file review finds no build output, native binary, dump, credential,
  personal path, or live sample.
- README, security policy, contribution guide, schema, runtime trace guide,
  changelog, CI, and tag-release workflow describe the shipped behavior.

Record the exact commands and results below immediately before handing the
candidate to the maintainer. A release candidate invites validation; it is not
a claim that heuristic or runtime coverage is complete.

## Verification record

Verified locally on 2026-09-01 against the complete candidate tree:

- `dotnet build Detector.slnx -c Release --no-restore`: succeeded with zero
  warnings and zero errors.
- `dotnet test Detector.slnx -c Release --no-build`: 141 passed, zero failed,
  zero skipped.
- `dotnet format Detector.slnx --verify-no-changes --no-restore` and
  `git diff --check`: succeeded.
- Self-contained `win-x64` CLI and GUI publishes: succeeded.
- Static CLI smoke: suspicious exit code, 9 findings, 4 correlated
  capabilities, valid JSON and HTML.
- Runtime import smoke: 2 events, 2 findings, 2 indicators, 1 correlated
  capability, valid JSON and HTML.
- Published GUI smoke: responsive window; Analyze, Import, and Export actions
  present through UI Automation.
- Synthetic 1180 × 760 WPF render inspected; no personal or live sample data.

## Maintainer actions

1. Enable GitHub private vulnerability reporting for the repository.
2. Review organization ownership, MIT licensing, and dependency provenance.
3. Push the reviewed branch, merge it to `main`, then create the target tag.
4. Verify `SHA256SUMS.txt` from the automated release before announcing it.
