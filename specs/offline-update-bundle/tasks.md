# Implementation Plan: Offline Update Bundle Import

## Overview

Implement offline bundle export/import as an admin-only workflow. Export creates a signed or unsigned integrity-checked `.tar.gz`; import stages, verifies, reviews, and applies selected content without deploying it to sensors.

## Tasks

- [ ] 1. Add bundle operation persistence
  - [ ] 1.1 Create `bundle_operations` migration
  - [ ] 1.2 Create `ConfigManager.Bundles.Operation` schema and changesets
  - [ ] 1.3 Add context functions for listing, creating, updating status, and expiring downloads
  - _Requirements: 1.6, 5.1-5.4_

- [ ] 2. Implement manifest model and validation
  - [ ] 2.1 Create `ConfigManager.Bundles.Manifest`
  - [ ] 2.2 Validate required fields, format version, allowed content types, file paths, hashes, and sizes
  - [ ] 2.3 Add unit tests for valid and invalid manifests
  - _Requirements: 1.4, 3.6, 6.3_

- [ ] 3. Implement safe archive handling
  - [ ] 3.1 Implement safe `.tar.gz` extraction into a temporary directory
  - [ ] 3.2 Reject absolute paths, parent traversal, links, and entries resolving outside staging
  - [ ] 3.3 Ignore and warn about unlisted files after manifest verification
  - [ ] 3.4 Add property test for path traversal rejection
  - _Requirements: 2.3, 2.4, 3.3, 3.4, 3.7_

- [ ] 4. Implement bundle verification
  - [ ] 4.1 Verify SHA-256 and file size for every manifest entry
  - [ ] 4.2 Implement optional signature verification when a trusted signing key is configured
  - [ ] 4.3 Produce a verification result with per-content counts and failures
  - [ ] 4.4 Add property test for complete hash verification
  - _Requirements: 3.1-3.9_

- [ ] 5. Implement content exporters
  - [ ] 5.1 Export Suricata repositories and rule files
  - [ ] 5.2 Export Zeek package registry and package archives
  - [ ] 5.3 Export YARA rules
  - [ ] 5.4 Export BPF profile templates
  - [ ] 5.5 Export forwarding templates with all secret values omitted
  - [ ] 5.6 Add property test proving secrets are absent from exported files
  - _Requirements: 1.2-1.5, 6.1, 6.4_

- [ ] 6. Implement bundle builder
  - [ ] 6.1 Stage selected content into archive layout
  - [ ] 6.2 Generate `manifest.json`
  - [ ] 6.3 Generate `manifest.sig` when signing is configured
  - [ ] 6.4 Create `.tar.gz` archive and time-limited download metadata
  - [ ] 6.5 Record `bundle_exported` audit entry
  - _Requirements: 1.3-1.9, 7.2, 7.3_

- [ ] 7. Implement content applier
  - [ ] 7.1 Apply Suricata content using SID/revision upsert while preserving enabled state
  - [ ] 7.2 Register Zeek packages as available only
  - [ ] 7.3 Import YARA rules disabled by default
  - [ ] 7.4 Import BPF profiles as templates
  - [ ] 7.5 Import forwarding templates without secrets
  - [ ] 7.6 Increment desired-state versions only when content changes
  - [ ] 7.7 Add test proving no Sensor_Agent deployment call is made during import
  - _Requirements: 4.1-4.8_

- [ ] 8. Implement LiveView pages
  - [ ] 8.1 Create `BundleLive.HistoryLive` at `/admin/bundles`
  - [ ] 8.2 Create `BundleLive.ExportLive` at `/admin/bundles/export`
  - [ ] 8.3 Create `BundleLive.ImportLive` at `/admin/bundles/import`
  - [ ] 8.4 Implement upload, verification result display, content selection, review, and apply confirmation
  - [ ] 8.5 Implement export content selection and bundle download link
  - _Requirements: 1.1, 2.1-2.8, 5.1-5.4, 6.1-6.4_

- [ ] 9. Wire RBAC, routes, and audit
  - [ ] 9.1 Add routes with `system:manage` permission
  - [ ] 9.2 Enforce `system:manage` in every LiveView event handler
  - [ ] 9.3 Record `bundle_imported`, `bundle_integrity_failed`, `bundle_content_applied`, and `bundle_download`
  - [ ] 9.4 Add unauthorized route and event tests
  - _Requirements: 7.1-7.4_

- [ ] 10. Final verification
  - [ ] 10.1 Run formatter
  - [ ] 10.2 Run bundle unit, property, context, and LiveView tests
  - [ ] 10.3 Manually verify an export/import round trip in dev
  - [ ] 10.4 Confirm deferred capabilities were not implemented
  - _Requirements: 8.1-8.4_

## Notes

- Imported content updates desired state only. Operators must use deployment-tracking workflows to push changes to sensors.
- Bundle payload encryption, differential bundles, scheduled exports, and automatic transfer remain deferred.
