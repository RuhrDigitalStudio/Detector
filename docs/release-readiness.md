# Detector public-release readiness

**Status: gated. Do not publish, push, package, tag, or create a release yet.**

## Verified public boundary

This branch deliberately excludes experimental process-injection, hook,
registry-registration, native-binary, launcher, and elevation-manifest work.
The shipped .NET projects contain only the read-only scanner, reporting,
watching, and GUI paths reviewed for this public boundary.

The ignore rules cover the named local native compiler-output paths; they are
only a guardrail and do not replace staged-file review. Native source and
binaries are not part of this public branch.

## Required release evidence

Before a public release, record fresh evidence for all of the following:

1. `dotnet build Detector.slnx -c Release` succeeds with no warnings or errors.
2. `dotnet test tests/Detector.Tests/Detector.Tests.csproj` passes.
3. `dotnet format Detector.slnx --verify-no-changes` passes.
4. No tracked or staged file is a native binary, build output, memory dump,
   credential, personal path, or unreviewed sample.
5. Public text is English and accurately describes the shipped behavior.
6. Ownership and third-party dependency provenance are reviewed against the
   selected MIT License.
7. A dedicated private vulnerability-reporting channel is published.

## Known gates

- The MIT License has been selected; owner confirmation and dependency
  provenance review remain required before publication.
- The security policy has no dedicated reporting address yet.
- The architecture image contains no machine or sample data. A GUI screenshot
  remains optional until a reviewed synthetic scan can be captured.
