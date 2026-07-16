# Changelog

## 1.3.0 - 2026-07-16

- Added a Caido-inspired Overview dashboard with risk cards, triage progress, recent signals, scan controls, and a vulnerability-queue shortcut.
- Added a first-class `VULNERABILITY` finding kind and eight statically detected, confidence-calibrated client-side security checks.
- Added rule descriptions and remediation guidance to finding details, JSON/CSV reports, and reviewed Burp audit issues.
- Ported Caido's sensitive-configuration flag and cross-finding preview redaction so nearby secrets cannot leak through unrelated evidence.
- Redact credentials and sensitive query parameters in link tables, clipboard copies, and redacted exports while preserving explicit raw export and Repeater workflows.
- Fixed decoded-view line attribution and whitespace-trimmed match offsets.

## 1.2.0 - 2026-07-16

- Added LinkFinder-inspired quoted endpoint discovery with low-confidence classification and specialized-rule deduplication.
- Discover ES module exports, inline module imports, Web Workers, Shared Workers, and Service Workers.
- Added configurable background asset exclusions; existing History responses are always analyzed locally.
- Upgraded Links and Assets with search, filters, correct severity sorting, resolved relative URLs, and direct Repeater handoff.
- Added Base64URL decoding and content-aware response fingerprints so same-size response revisions are not skipped.
- Record discovered assets when automatic fetching is disabled and clear stale response-editor content.

## 1.1.2 - 2026-07-14

- Analyze all stored Proxy History and live responses locally by default, including migration from the old scope-only default.
- Keep every automatic background HTTP fetch strictly limited to Target Scope.
- Added a Sensitive Files tab that groups findings by source file and displays the stored History Request/Response.
- Added file-level Reviewed, False Positive, and Needs Review actions with persisted per-finding state.

## 1.1.1 - 2026-07-14

- Added a dedicated Links tab for endpoint and configuration discoveries.
- Disabled Proxy History note annotations by default and made them an explicit setting.
- Remove stale JS Secret Hunter note segments during rescans while preserving analyst notes.
- Show a clear status message when Target Scope contains no matching Proxy history responses.

## 1.1.0 - 2026-07-14

- Fixed clipped and apparently unresponsive Findings actions with a responsive action grid and explicit selection states.
- Made Clear, Cancel, and Rescan generation-safe so stale work cannot restore cleared results.
- Added scan progress, confidence/status filters, filtered exports, and cancelled asset states.
- Added Target-Scope-first scanning for JSON, XML, HTML, source maps, and other text responses.
- Added extensionless script discovery, Burp context-menu scans, and redacted manual audit issues.
- Added bounded history/result retention, coalesced Swing updates, and temporary-file-backed message retention.
- Expanded the test suite for layout, repository state, content classification, redaction, and discovery.
