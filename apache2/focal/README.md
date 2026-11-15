# Apache 2.4.41 security backport - Ubuntu 20.04 Focal

**Status: experimental, not deployable.** Last human-maintained status: **2026-11-15**, branch `backport/focal`. This file is the operational handoff if work has to resume.

## 1. Goal and baseline

- Preserve `apache2 2.4.41-4ubuntu3.23` packaging/layout, the Focal module ABI and external DSO compatibility; update it with reviewed security changes rather than replacing all of Apache with Jammy binaries.
- Public Focal source: `apache2=2.4.41-4ubuntu3.23`, downloaded through Ubuntu source packages. Security comparison source: Jammy `apache2=2.4.52-1ubuntu4.27`, with its Ubuntu quilt patches already applied by `apt-get source`.
- Experimental version: `2.4.41-4ubuntu3.23+unibo0~experiment1`. CI builds inside `ubuntu:20.04` Docker, never on the live host.
- Official vendor reference: [USN-9090-1](https://ubuntu.com/security/notices/USN-9090-1) identifies Focal `+esm11` as the Ubuntu Pro/ESM security build. Our packages are **not equivalent to the ESM build** and have not been certified to reproduce all its changes.

The [original production inventory](gojira-inventory.md) includes MPM prefork, `mod_php7.4`, `mod_fcgid`, `mod_maxminddb`, SSL, rewrite, proxy HTTP/FCGI/WebSocket. Preserve **module magic major 20120211** and the existing MPM choice; compile/link success alone does not guarantee ABI compatibility. The legacy host was only inventoried; no CI install is a production deployment.

## 2. Current concrete result

- Patch import: **63 applied and 4 excluded** in the [latest CI manifest](analysis/experimental-manifest.md). This counts *Jammy patch files*, **not CVEs**; Focal-specific patches are separate.
- Accepted patches were applied in upstream sequence with `patch --fuzz=0`. Where contexts differed, `tools/prepare-experimental.py` constructs explicit reviewed rebase patches; do not assume `patch --dry-run` alone proves a security fix.
- Additional Focal-only quilt changes: SNI policy structure-member fix, SSL command declaration, and `unibo-focal-mod-md-bounded-backoff.patch` (CVE applicability still under review).
- GitHub Actions experimental package workflows **#81 through #84 passed**. #84 includes an actual C/UBSan boundary test for the native `mod_md` backoff expression.
- Output artifacts: `apache2-focal-EXPERIMENTAL` from the experimental workflow (seven-day artifact retention), containing rebuilt `.deb`, SHA256 checksums, patch manifest, audits and test logs. They are **not release artifacts**.
- Production release: **none**. Do not remove experimental labels or deploy solely because CI is green.

### The four excluded Jammy patches

| Patch | Decision / reason |
| --- | --- |
| `CVE-2025-55753.patch` | Broad newer-`mod_md` ACME/OCSP changes do not cleanly apply to Focal 2.0.10. A Focal-native exponential backoff correction has been added; full CVE equivalence **not yet established**. |
| `CVE-2025-55753-3.patch` | Regression fix involving `MDStapleOthers` in newer `mod_md`; this directive and new OCSP components are absent from native Focal; checked by CI. |
| `CVE-2026-29168.patch` | Only modifies newer `modules/md/md_ocsp.c`, absent from native Focal; CI checks the *exact patch path set* and absence of those OCSP units. Does **not** clear the independent `mod_ssl` OCSP implementation. |
| `mod_proxy_hcheck_jammy_fix_to_detect_support.patch` | Jammy AJP optional hook relocation refers to a detection block absent from Focal. Its source architecture differs; importing this patch is not appropriate. |

Do not increment the 63 count for the native backoff patch or reclassify the first CVE without a substantive review. See [mod_md architecture audit](analysis/mod-md-compatibility-latest.md), [native Focal source audit](analysis/mod-md-native-port-latest.md), and [patch manifests](analysis/).

## 3. How the build actually works

Main automation: [`.github/workflows/apache2-focal-experimental.yml`](../../.github/workflows/apache2-focal-experimental.yml).

1. Docker `ubuntu:20.04` installs Focal build dependencies and retrieves **exact** Focal source `2.4.41-4ubuntu3.23` and Jammy source `2.4.52-1ubuntu4.27` from Ubuntu archive sources. These are **source** packages, not mixing Jammy binary libraries into Focal.
2. `tools/prepare-experimental.py FOCAL_SOURCE JAMMY_SOURCE REPORT_DIRECTORY` iterates Jammy `debian/patches/series`; checks applicability with fuzz zero, ports known differing contexts, copies the accepted diffs into Focal `debian/patches/` and appends the quilt series. The script also creates necessary Focal-specific compatibility patches, adds experimental `debian/changelog` entry and writes a machine-generated manifest.
3. The workflow runs the module architecture audit and the native C/UBSan backoff test (since #84), then `dpkg-buildpackage -b -us -uc -j2` and records `.deb` plus SHA256 sums.
4. **Separate disposable Focal containers** install only the just-built experimental `.deb` and test runtime behavior. No test touches production.
5. The workflow tries to publish its generated `analysis/experimental-manifest.md`, but **skips publication if another commit moved the branch**. Thus an artifact from the exact run is authoritative if the checked-in manifest is stale. Avoid simultaneous manual pushes while CI publishes.

Useful commands inside a disposable Focal build container:

```sh
sed -n 's/^deb /deb-src /p' /etc/apt/sources.list >> /etc/apt/sources.list
apt-get update
apt-get install -y --no-install-recommends build-essential fakeroot dpkg-dev patch python3 ca-certificates
apt-get build-dep -y apache2
mkdir -p /tmp/focal /tmp/jammy /tmp/report
(cd /tmp/focal && apt-get source apache2=2.4.41-4ubuntu3.23)
# Add jammy, jammy-updates and jammy-security deb-src entries, then apt-get update:
(cd /tmp/jammy && apt-get source apache2=2.4.52-1ubuntu4.27)
python3 /repo/apache2/focal/tools/prepare-experimental.py /tmp/focal/apache2-2.4.41 /tmp/jammy/apache2-2.4.52 /tmp/report
(cd /tmp/focal/apache2-2.4.41 && dpkg-buildpackage -b -us -uc -j2)
```

The above reproduces the *build logic*, not an independently configured complete container; the GitHub workflow is the executable reference (including mounts, sources, dependencies and tests). Never install Jammy binaries as a shortcut.

## 4. Established CI coverage

The experimental workflow has already exercised:
- Apache package load, `apache2ctl -t`, HTTP header behavior, HTTP/2 paths as available.
- Event MPM and worker MPM startup/graceful restart; prefork MPM with distro PHP 7.4.
- Released PHP **8.3 and 8.4** Apache DSOs under prefork; PHP **8.3 and 8.4 FPM** via `proxy_fcgi` under event MPM. Released external packages are obtained by `tools/fetch-legacy-php.py`.
- TLS/`mod_ssl`, rewrite, `mod_fcgid`, WebSocket proxy, `mod_proxy_hcheck`, `mod_auth_digest`, and a non-core `apxs` module compatibility smoke test.
- Native Focal `mod_md` loads in the **built experimental packages**, without live ACME network calls. A separate attempt to transplant *full Jammy mod_md* was rejected due to missing Focal SSL hooks; **do not substitute that diagnostic module**.
- Native `mod_md` exponential backoff now caps delay at 3600 seconds *before an undefined shift*; test in `tools/test-mod-md-backoff.py` covers 9 boundary counts (including `INT_MAX`) with UBSan. **#84 passed**.

Limitations: no full ACME certificate issuance/renewal or OCSP end-to-end validation; no proof of complete ESM equivalence; no production vhost replay. `mod_maxminddb` was inventoried but its exact deployed manually built binary has not been reproduced by CI. Some diagnostic probes are *informational only* and intentionally do not fail the whole build; read their artifacts and do not mistake green status for blanket success.

## 5. Key code, workflow and reports

| Item | Role |
| --- | --- |
| `tools/prepare-experimental.py` | Authoritative patch importer, Focal-specific ports/guards and manifest generation. |
| `.github/workflows/apache2-focal-experimental.yml` | Rebuild `.deb` and run existing full compatibility matrix. |
| `tools/test-mod-md-backoff.py` | Source-derived, UBSan-assisted native Focal arithmetic regression (#84 onwards). |
| `tools/audit-mod-md.py`, `tools/inspect-md-native.py` | Newer-module applicability and native source review. |
| `.github/workflows/apache2-focal-md-native.yml` | Source-analysis CI; *diagnostic*, not packaging. |
| `tools/probe-mod-md-build.py`, `.github/workflows/apache2-focal-md-compatibility.yml` | Abandoned full Jammy `mod_md` transplant diagnostic. No release code from it. |
| `analysis/experimental-manifest.md` | Exact 63/4 mapping from latest published CI run. |
| `analysis/mod-md-native-port-latest.md` | Focal/ Jammy retry and OCSP source contexts; contains excerpts and may be truncated. |
| `analysis/jammy-patch-compare.md`, `analysis/jammy-applicability.md` | Upstream candidate inventory and independent dry runs; may be stale vs final patches. |
| `cve-gap.md`, `esm-milestones.md`, `source-provenance.md` | Earlier security/provenance planning; **some status text is outdated**. |
| `gojira-inventory.md`, `external-modules.md` | Module/ABI requirements and operator-collected environment facts. |

For complete run history, use the [branch Actions listing](https://github.com/bilo1967/LegacyPackages/actions). Run IDs: [#81](https://github.com/bilo1967/LegacyPackages/actions/runs/43656089490), [#82](https://github.com/bilo1967/LegacyPackages/actions/runs/43657438364), [#83](https://github.com/bilo1967/LegacyPackages/actions/runs/43658453251), [#84](https://github.com/bilo1967/LegacyPackages/actions/runs/43659608147).

## 6. Decisions, failures and lessons

- `http_ssl.h` is missing in stock Focal. Copying only Jammy's header allowed compilation but does not supply runtime APIs.
- Jammy `mod_md` enforces Apache >=2.4.48. Bypassing that check for CI diagnostics only allowed compilation of 28 sources; **it was never accepted for installation**.
- Runtime load then failed for `ap_ssl_conn_is_ssl` and later `ap_hook_ssl_add_fallback_cert_files`. A local experimental SSL compatibility shim got past the first but did not establish safety. **Do not continue accumulating SSL shims**; native Focal `mod_md` is retained.
- `apxs -c` returned success but the expected DSO name was absent until explicit `-o mod_md.so` was specified. For similar probes, check produced DSO name and `.libs` location before diagnosing compilation.
- `apache2-dev` **does not by itself install `a2enmod` and `a2dismod`** in the stripped CI image; the runtime `apache2` package is required.
- `dpkg-source` warning about unsandboxed root download when `_apt` cannot access the working directory did not indicate an invalid source or failed patch.
- Always isolate repo pushes: package build workflow watches only `apache2/focal/build/**` and its own workflow; patch-comparison workflow watches only `compare-patches.py` and its own workflow. Experimental workflow watches its tools and workflow. GitHub Actions may commit generated manifests; check latest branch HEAD before updates and never force-push.
- No local build compiler or host maintenance is a substitute for the disposable workflow plus a test VM/snapshot when approaching deployment.

## 7. Remaining work and release gates

1. The **#84** UBSan boundary test and existing build/runtime matrix passed; do not rerun them without a new code change or concrete regression.
2. Decide whether the native `mod_md` backoff adjustment covers the **actual vulnerable Focal path** for `CVE-2025-55753` (not the entire unrelated Jammy 2.6 codebase). Keep excluded status if unresolved. The newer `MDStapleOthers` regression and `md_ocsp.c`-only patch are separately documented as not applicable to Focal's code structure.
3. Review final Ubuntu ESM advisories and any relevant security gaps not represented by the Jammy patch list; **63 imported files do not equal complete ESM coverage**. If exact Canonical ESM sources are available with authorization, compare source changes instead of making equivalence assumptions.
4. Only after security review, choose candidate Debian package version and changelog, verify dependency metadata/`dpkg` conffile behavior, preserve existing modules/MPM and prepare test-VM install + rollback. Use existing CI suite once; add a targeted test only when an uncovered functional risk is concrete.
5. Produce signed/distributable artifacts only after acceptance. Current GitHub CI packages are labeled **EXPERIMENTAL / DO NOT DEPLOY** and must not be renamed release-ready automatically.

**No production server has been changed by this repository workflow.** Keep its build output and the precise source SHA; re-run a workflow for ephemeral artifacts only when needed. For Ubuntu 18.04, see [Bionic assessment](../bionic-evaluation.md).
