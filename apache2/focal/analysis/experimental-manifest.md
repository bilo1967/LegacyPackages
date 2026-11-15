# EXPERIMENTAL Apache Focal partial patch import

Not for production use. No security completeness claim. Jammy source patches are not equivalent to verified Focal ESM.

Version: \`2.4.41-4ubuntu3.23+unibo0~experiment1\`. Applied: 63; skipped: 4.

| Patch | Decision | Reason |
|---|---|---|
| \`fix-macro.patch\` | applied | zero-fuzz sequential patch |
| \`fix-a-possible-listener-deadlock.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`handle-children-killed-pathologically.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`mod_proxy_hcheck_jammy_fix_to_detect_support.patch\` | skipped | Focal mod_proxy_hcheck lacks AJP optional-hook detection block; Jammy relocation is not directly applicable |
| \`reenable-workers-in-standard-error-state-jammy-apache2.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2024-42516.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2024-43204-pre1.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2024-43204.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2024-47252.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-23048.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-49630.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-49812.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-53020.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-23048-regression.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2025-23048-regression-2.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-58098.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-65082.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-66200.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2025-55753.patch\` | skipped | 17 out of 25 hunks FAILED |
| \`CVE-2025-55753-3.patch\` | skipped | 1 out of 1 hunk ignored |
| \`CVE-2026-23918.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-24072.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-28780.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-29168.patch\` | skipped | 2 out of 2 hunks ignored |
| \`CVE-2026-29169.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-33006-1.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-33006-2.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-33007.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-33523.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-33857.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-34032.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-34059.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-49975.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-29167.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-29170.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-34355.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-34356.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-42535.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-42536.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-43951.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2026-44119.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2026-44185.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-44186.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-44631.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2026-48913.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2026-48913-2.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-56154.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-57941.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-59797.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-58415.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-63045.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-63292.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-63686.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-63718.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-7363X.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2026-79768.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-93546.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-46729.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-47360.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-56153.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-56449.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-106023.patch\` | applied | Focal context adapted; see source diff (fuzz=0) |
| \`CVE-2026-109163.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-119618.patch\` | applied | zero-fuzz sequential patch |
| \`CVE-2026-42528.patch\` | applied | zero-fuzz sequential patch |
| \`unibo-focal-sni-policy-hash-member.patch\` | applied | Focal-only SSLSrvConfigRec SNI policy hash member |
| \`unibo-focal-sni-command-declaration.patch\` | applied | Focal-only prototype for SNI directive; regression-1/2 required |

CVE-2025-55753-3: upstream MDStapleOthers regression fix; the directive and newer OCSP implementation are absent in native Focal mod_md (verified by CI). Not imported.

CVE-2026-29168: the upstream patch exclusively changes modules/md/md_ocsp.c, absent from native Focal mod_md (verified by CI). Not imported; mod_ssl OCSP is separate.

Additional Focal-only hardening (not counted as a Jammy CVE fix): unibo-focal-mod-md-bounded-backoff.patch. CVE-2025-55753 remains excluded.

Next: review each source diff, add prerequisite patches and complete missing CVEs, then run regression and ABI tests.
