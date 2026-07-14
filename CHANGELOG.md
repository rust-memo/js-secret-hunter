# Changelog

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
