# Changelog

All notable changes to the Software Supply Chain Security Framework are documented here.
Format: `[version] — [date] — [summary of changes]`

---

## [Unreleased]

- Added CHANGELOG.md (this file) for version tracking
- Added "Learning Resources" section to README.md linking to Book 2, techstream-learn labs, and techstream.app
- docs/best-practices.md: Added SBOM Fleet Management Operational Patterns section covering fleet query patterns (Dependency-Track REST API, batch Grype), SBOM accuracy validation with completeness thresholds by artifact type, dependency drift detection for runtime environments, and SBOM retention requirements table (2026-04-07)


---

## [1.0.0] — 2026-05-17

### Added — Governance and Documentation

- `SECURITY.md` — security reporting policy and supported versions
- `CITATION.cff` — academic and industry citation metadata (CFF v1.2.0)
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1
- `README.md` "Related Publications" section linking the TechStream article series

### Federal-standards alignment (this release)

- Continued alignment with Executive Order 14028 (Improving the Nation's Cybersecurity)
- Continued alignment with Executive Order 14306 (June 2025)
- Continued alignment with NIST SP 800-218 (SSDF) v1.1
- Acknowledgment of NIST SP 1800-44 (NCCoE DevSecOps Practices) preliminary draft, March 2026

### Related publications referenced in this release

  - "The Four Layers of Software Supply Chain Integrity" (Medium, May 2026)
  - "Why Your AI Agent Is the Next SolarWinds" (Medium, May 2026)

### Changed

- Documentation cross-references updated to reflect the public TechStream framework portfolio at https://github.com/sotille

## [1.0.0] — 2024-01-15

- Initial public release of the Software Supply Chain Security Framework
- Core framework documentation: introduction, architecture, framework, implementation, best-practices, roadmap
- SBOM format and tool selection guide (CycloneDX vs SPDX, Syft/Trivy/cdxgen comparison)
- SBOM at scale guide for enterprise SBOM lifecycle management
- SLSA level advancement guide from Level 1 to Level 4
- VEX and SBOM lifecycle management documentation
- Open source component assessment methodology
- License compliance integration patterns
- Vendor security assessment framework
- Incident response playbook for supply chain compromise events
- Apache 2.0 license and contribution guidelines
