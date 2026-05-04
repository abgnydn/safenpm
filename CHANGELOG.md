# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/) starting
from `0.1.0`.

## [0.1.0] — 2026-05-04

Version-numbering reset to align with the repo-wide `0.x` SemVer policy. The
package was previously published as `1.0.0` (still on npm; deprecated in
favour of the post-reset releases). Functionality is unchanged from the
prior 1.0.0 publish — same `safenpm` wrapper, same security pipeline.

### Added

- **Drop-in `npm install` replacement** that sandboxes postinstall scripts,
  blocks network access, detects typosquats, and catches supply-chain
  attacks before they execute.
- **Security pipeline**: static analysis, sandboxed execution, typosquat
  detection, maintainer-change alerts, lockfile integrity checks,
  real-time threat intelligence (community-backed via
  https://safenpm.dev).
- **Cross-platform** — macOS, Linux, Windows (Node 18+).
- **89/90 test suite passing** under `bash test/run-tests.sh` (one
  long-running env-var stripping test is flaky on slow CI; runs cleanly
  locally).
- **Documentation site** at https://safenpm.dev — quickstart, showcase,
  threat-intelligence dashboard.

### Note on npm versions

`@abgunaydin/safenpm@1.0.0` (published 2026-04-02) is deprecated in
favour of `0.1.0` to reset SemVer. npm doesn't permit downgrading version
numbers, so the next published version will jump back into the `1.x` range
(`1.0.1` or later) — consult this CHANGELOG and the GitHub releases page
for the canonical version timeline.

[0.1.0]: https://github.com/abgnydn/safenpm/releases/tag/v0.1.0
