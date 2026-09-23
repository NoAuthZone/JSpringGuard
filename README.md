
# JSpringGuard

**Static security scanner for Spring Boot / JVM projects — one Python file, zero dependencies.**

[![Version](https://img.shields.io/badge/version-4.0-blue)](https://github.com/NoAuthZone/JSpringGuard)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](#requirements)
[![Single file](https://img.shields.io/badge/install-none-lightgrey)](#quick-start)
[![Offline](https://img.shields.io/badge/runs-offline-success)](#osvdev-and-air-gapped-scans)

JSpringGuard scans Java, Kotlin, Groovy and Scala projects for XML, Spring Security,
OAuth2/JWT, TLS, injection, dependency and build risks. It writes text, JSON, SARIF,
Markdown or a self-contained HTML report that opens directly from disk. Version 4.0
adds a **Security Flow Explorer** that maps every entry point to the security controls
on its processing path.

```bash
python3 jspringguard.py /path/to/your/project
```

> [!NOTE]
> JSpringGuard is a heuristic static linter, not a complete taint-analysis engine.
> Review findings in the context of the actual application and deployment.

## Quick start

```bash
python3 jspringguard.py .
python3 jspringguard.py . --format html --out security-report.html
python3 jspringguard.py . --coverage
python3 jspringguard.py --selftest
```

## New in 4.0

- **Security Flow Explorer (HTML):** every HTTP endpoint, Kafka/Rabbit/JMS listener and
  `@Scheduled` job with its reachable call path, sensitive sinks, source previews and
  "find all references".
- **Security-control coverage matrix** for authentication, authorization, tenant binding,
  input validation, rate limiting, audit and path resolution — with a per-control
  rationale, inspected evidence and stated uncertainty.
- **Effective route policy:** `SecurityFilterChain` order, `securityMatcher` scope and
  first-match-wins matcher order, including `@Profile` / `@ConditionalOn…` conditions.
- **Roles and permissions matrix**, **risk-ranked attack paths** and explicit reporting of
  unresolved call boundaries.
- **Security-policy snapshots:** export the current policy and compare it with an earlier
  snapshot to see degraded, improved, added and removed entry points (policy drift).
- **Triage in the report:** status and notes per finding and per flow/control decision,
  stored in the browser and portable via JSON export/import. Fingerprints stay stable
  across rescans.
- **New rule families:** JOSE header abuse (`jku`, `x5u`, `kid`, embedded `jwk`/`x5c`),
  nested JWT inner signatures, JWE compression, key/issuer binding, token-type confusion,
  DPoP proof validation, refresh-token rotation and logout revocation, password reset,
  MFA fail-open, login throttling, OAuth2 PKCE `plain`, redirect prefix matching,
  tokens/secrets in URLs, issuer mix-up, ID token used as access token, missing `azp`.
- **TLS and certificates:** obsolete protocols, weak cipher suites, trusted self-signed
  certificates, disabled revocation, optional mTLS, hardcoded keystore/truststore
  passwords, empty PKCS12 passwords and committed private keys (`.pem` / `.key` files).
- **Authorization analysis:** shadowed matchers, filter-chain order, missing fallback chain,
  `@PreAuthorize` without enabled method security, and IDOR/tenant data flow across
  controller → service → repository calls.
- Structured intraprocedural data flow for SpEL, SQL, LDAP, log and XSS sinks, plus
  deduplication of overlapping findings.

<details>
<summary>New in 3.8</summary>

- Local SQLite OSV database for offline Maven and Gradle dependency checks.
- Download, create, update or import the complete OSV Maven export.
- Exact package coordinates, corrected CVE mappings and no guessed Spring Boot-managed versions.
- Improved multiline detection and more conservative XXE `HARDENED` assessments.
- Explicit reporting of unresolved dependencies and incomplete OSV coverage.

</details>

## Requirements

Python 3.8 or newer is required. No `pip install`, Java toolchain, Semgrep or CodeQL
installation is needed for the native rules. Local OSV databases require Python's
standard-library SQLite support. Maven or Gradle is needed only for `--resolve-deps`.
Online OSV checks and database downloads require internet access.

Examples use `jspringguard.py`; substitute your downloaded filename if it differs.

## What it checks

| Area | Examples |
|---|---|
| **XXE and XML** | DOM/SAX/StAX, Transformer, SchemaFactory, dom4j, JDOM, JAXB, Spring OXM, Jackson XML, SOAP, Xerces and Digester |
| **Deserialization** | XMLDecoder, XStream, native `ObjectInputStream`, Jackson default typing, SnakeYAML and Fastjson |
| **Spring Security** | CSRF (incl. CSRF disabled with cookie-based JWT), broad `permitAll`, matcher and `SecurityFilterChain` order, missing fallback chain, method security, HTTP Basic, sessions, headers, CORS, password encoders, Actuator, Remember-Me, SAML, secrets and trust-all TLS |
| **OAuth2 / OIDC / JWT** | `alg=none`, algorithm confusion, missing expiry/issuer/audience, weak secrets, `jku`/`x5u`/`kid` injection, embedded `jwk`/`x5c` trust, nested JWT, JWE `zip`, token-type confusion, PKCE, `state`, redirect matching, tokens in URLs or logs, issuer mix-up, `azp`, DPoP, refresh-token lifecycle |
| **Reactive security** | WebFlux `SecurityWebFilterChain`, `authorizeExchange`, functional `RouterFunction` routes, RSocket payload security, reactive JWT decoders and X.509 configuration |
| **Authentication flows** | Password-reset tokens (expiry, reuse, predictability), login throttling, MFA fail-open |
| **TLS and certificates** | SSLv3/TLS 1.0/1.1, weak cipher suites, self-signed trust, disabled revocation, optional mTLS, hardcoded store passwords, empty PKCS12 passwords, committed private keys |
| **Injection and crypto** | SQL, SSRF, path traversal, open redirect, LDAP, SpEL, JNDI, XPath, regex, reflection, command execution, CRLF, log injection, SSTI via view names, static IVs, RSA without OAEP, predictable seeds and weak hashes/ciphers |
| **Data handling** | XSS response sinks/templates, IDOR and tenant data flow, mass assignment, missing `@Valid`, archive/decompression limits, sensitive logs/URLs and resource exhaustion |
| **Security-control coverage** | Per-entry-point authentication, authorization, tenant binding, validation, rate limiting, audit and unresolved call boundaries (`--coverage`) |
| **Dependencies** | Spring Security/Boot, Log4j, Jackson, SnakeYAML, Commons, H2, Logback, Tomcat, dom4j, XStream, JDOM, risky Spring Boot combinations and optional online or local [OSV.dev](https://osv.dev) advisory checks |
| **Build hygiene** | HTTP repositories, insecure Gradle protocols, `mavenLocal()`, JCenter, dynamic/SNAPSHOT versions and insecure Gradle wrappers |
| **Configuration** | `application*.properties` / `.yml`: Actuator exposure, debug logging, cookies, plaintext secrets, TLS, client auth, H2 console and `ddl-auto=create(-drop)` |

XXE checks use method context and selected helper-factory patterns. Hardening is
recognized conservatively: late, conditional or unsupported protection patterns may
still require review. Most checks work within one method; tenant and object-ID data
flow, and the coverage call graph, follow calls across methods within the same build
module (bounded, see [Limits](#limits-and-validation)).

## Usage and options

```bash
python3 jspringguard.py . --fail-on HIGH
python3 jspringguard.py . --format sarif --out report.sarif
python3 jspringguard.py . --format markdown --out report.md --context 3
python3 jspringguard.py . --skip-tests --min-severity MEDIUM
python3 jspringguard.py . --coverage --fail-on-coverage-gap
python3 jspringguard.py . --include-rule 'JWT-*,OAUTH2-*' --exclude-rule '*-HARDCODED'
python3 jspringguard.py . --show-fix
python3 jspringguard.py --list-rules
```

| Option | Purpose |
|---|---|
| `--format {text,json,sarif,markdown,html}` | Output format; non-text formats get an auto-generated filename if `--out` is omitted |
| `--out FILE` | Output destination |
| `--fail-on LEVEL` | Exit 1 at or above the severity (default `MEDIUM`) |
| `--min-severity LEVEL` | Hide findings below the severity (default `LOW`) |
| `--context N` | Lines before and after each finding; `0` = matched line only. Default: entire file |
| `--coverage` | Add the security-control coverage matrix and coverage findings (always on for HTML) |
| `--coverage-format {table,json}` | Coverage rendering in text output |
| `--fail-on-coverage-gap` | Exit 1 if any required control is `MISSING` |
| `--skip-tests` / `--no-deps` | Skip tests or dependency checks |
| `--show-hardened` / `--hide-hardened` | Hardening results are shown by default; hide them with `--hide-hardened` |
| `--show-fix` | Display remediation templates; does not edit source files |
| `--osv-db FILE` | Check dependencies against a local SQLite advisory snapshot |
| `--osv-db-update FILE` | Download the Maven export and create or update the database |
| `--osv-db-build ZIP` | Import a downloaded Maven archive; requires `--osv-db FILE` |
| `--osv-db-info FILE` | Display snapshot metadata |
| `--check-osv` / `--check-osv-read FILE` | Online OSV queries or offline query-cache reuse |
| `--resolve-deps` / `--resolver-timeout S` | Opt-in effective dependency resolution via Maven/Gradle |
| `--codeql-sarif FILE` | Merge CodeQL SARIF results; repeatable |
| `--jobs N` / `--exclude DIRS` | Parallel readers or additional directories to skip |
| `--include-rule GLOB` | Only report matching rule IDs; repeatable or comma-separated |
| `--exclude-rule GLOB` | Suppress matching rule IDs; exclusion wins |
| `--list-rules` | List rule IDs, severities and descriptions |
| `--baseline FILE` / `--write-baseline FILE` | Hide known findings in CI |
| `--fix [RULE…]` / `--poc` | Print hardened code templates or XXE counter-test payloads |

Run `python3 jspringguard.py --help` for the complete option list.

> [!TIP]
> The default context is the whole file, so every finding can be judged in full context.
> For large projects, use `--context 5` to keep HTML and JSON reports small.

## HTML and SARIF reports

HTML output is self-contained and works from `file://`; nothing leaves the file. It has
two views:

- **Findings:** dark/light themes, severity chips, text/type/severity/status filters,
  source context with the matched line highlighted, collapsible fix templates and a
  triage row (Confirmed, In review, Fixed, False positive, Accepted risk + note).
- **Security Flow Explorer:** entry-point list with flow filters, effective security
  configuration, reachable processing flow, source preview, reference search, control
  status with rationale, per-control and complete-flow triage, roles/permissions matrix,
  risk-ranked attack paths and security-policy drift.

Triage decisions are stored in the browser's `localStorage`. Use **Export all triage** to
keep them: the fingerprint-based export can be imported into the next report and still
matches unchanged code.

SARIF includes rule metadata, context regions and `helpUri` links for GitHub Code Scanning.
JSON output includes a `coverage` object when `--coverage` is used.

## Security-control coverage

```bash
python3 jspringguard.py . --coverage
python3 jspringguard.py . --coverage --coverage-format json
python3 jspringguard.py . --coverage --format html --out coverage.html
```

For each entry point the matrix shows one status per control:

| Status | Meaning |
|---|---|
| `COVERED` | Static evidence of the control was found on the recognized path; runtime enforcement still needs review |
| `MISSING` | The path requires the control, but no enforcement is visible |
| `UNKNOWN` | Configuration is dynamic, conditional, ambiguous or external |
| `NOT_REQUIRED` | The recognized path does not need the control |

Coverage gaps become findings such as `AUTHZ-SENSITIVE-SINK-UNCOVERED`,
`AUTHZ-PARTIALLY-PROTECTED-SERVICE`, `TENANT-CONTEXT-LOST`, `VALIDATION-COVERAGE-GAP`,
`RATE-LIMIT-COVERAGE-GAP`, `AUDIT-COVERAGE-GAP` and `SECURITY-CONTROL-UNRESOLVED-PATH`.

## OSV.dev and air-gapped scans

### Local database for Maven and Gradle

On a connected machine, download the complete Maven advisory export and create a
local SQLite database:

```bash
python3 jspringguard.py --osv-db-update ./osv-maven.sqlite
```

If the file does not exist, it is created automatically. Running the command again
updates it. An existing database is replaced only after the new import succeeds.

Copy the script and database to the offline machine, then scan:

```bash
python3 jspringguard.py . --osv-db ./osv-maven.sqlite --format html
python3 jspringguard.py --osv-db-info ./osv-maven.sqlite
```

`--osv-db` performs no network request and does not execute build tools. The database
contains the snapshot's advisories and needs an explicit update to receive new data.

> [!NOTE]
> OSV uses **Maven** as the Java package ecosystem name. Maven-coordinate dependencies
> in **Gradle projects** use the same database; no separate Gradle export is required.

The archive is also available directly from the official
[Maven export](https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip).
Import a downloaded archive without network access:

```bash
python3 jspringguard.py --osv-db-build ./all.zip --osv-db ./osv-maven.sqlite
```

The database covers the Maven ecosystem, not all OSV ecosystems. See the
[OSV export documentation](https://google.github.io/osv.dev/data/) for source details.

### Online queries and offline query cache

```bash
python3 jspringguard.py . --check-osv --osv-cache-write osv-cache.json
python3 jspringguard.py . --check-osv-read osv-cache.json
```

The second command performs no network request. Without `--osv-cache-write`, a live
check still writes an auto-named cache file. The JSON cache only contains results for
previously queried package/version pairs; it is not a complete advisory database. Use
the SQLite snapshot when scanning other dependencies offline.

Failed queries, missing cache entries, unresolved dependency versions and unsupported
offline comparisons are reported as incomplete coverage. A local advisory database
cannot resolve remote BOMs or evaluate dynamic Gradle build logic.

`--osv-db` cannot be combined with `--resolve-deps`, `--no-deps`, or API cache
read/write options.

## Effective Maven / Gradle dependencies

Runtime dependency resolution is opt-in because it executes the project wrapper or build:

```bash
python3 jspringguard.py . --resolve-deps --resolver-timeout 180
```

This can access the network and should be used only with trusted build scripts.
Without it, the scanner reads supported declarations in `pom.xml` (including local
parent chains and `<dependencyManagement>`), `build.gradle`, `build.gradle.kts` and
version catalogs. It does not guess versions from Spring Boot release lines. Missing or
dynamic versions are reported for review.

## CodeQL SARIF import

Existing CodeQL CLI or GitHub Code Scanning results can be merged without bundling
CodeQL rules:

```bash
python3 jspringguard.py . --codeql-sarif codeql-results.sarif \
  --format html --out combined-report.html
```

Imported findings receive the `CODEQL-` prefix; native findings remain traceable.

## CI integration

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- name: JSpringGuard
  run: python3 jspringguard.py . --format sarif --out results.sarif --fail-on HIGH --context 5
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with: { sarif_file: results.sarif }
```

To gate on missing security controls, add a second step:

```yaml
- name: JSpringGuard coverage gate
  run: python3 jspringguard.py . --coverage --fail-on-coverage-gap --fail-on NONE
```

## Suppression and baselines

```java
// sec-check:ignore
ObjectInputStream in = new ObjectInputStream(stream);

// sec-check:ignore[SRC-SSRF]
URI target = URI.create(configuredUrl);
```

A marker directly above a method declaration applies to the whole method body.
Markers also work in properties/YAML and build files.

For CI:

```bash
python3 jspringguard.py . --write-baseline .sec-baseline.json
python3 jspringguard.py . --baseline .sec-baseline.json --fail-on HIGH
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No retained findings meet the configured failure threshold |
| `1` | Retained, non-`HARDENED` findings meet the threshold, or `--fail-on-coverage-gap` found a `MISSING` control |
| `2` | Invalid invocation, scan error or incomplete OSV/dependency-resolution coverage |

The default failure threshold is `MEDIUM`. `REVIEW` findings can also trigger it.
`--fail-on NONE` disables the finding threshold but does not suppress errors,
incomplete-coverage or coverage-gap exit codes.

## Limits and validation

JSpringGuard combines pattern matching, method-scoped analysis, selected intraprocedural
data flow and a bounded project call graph (depth 8, at most 250 methods per entry
point). Receiver types are resolved heuristically; reflection, proxies, library
implementations and ambiguous overloads stay visible as unresolved boundaries. The tool
can produce false positives and miss framework semantics that require a full taint
engine or runtime context. Treat `REVIEW` and `UNKNOWN` as prompts for manual analysis.

`HARDENED` and `COVERED` mean a supported protection pattern was recognized, not that
the application is certified secure. The Flow Explorer's risk score is a heuristic
ranking, not CVSS. An advisory match needs deployment context; a missing advisory does
not prove that a package is safe.

## References and licensing

This project was compared with the following projects, rule catalogues and test targets.
**No source files, rule files, CSS, HTML or Java code from these projects are
redistributed by JSpringGuard.** The scanner contains independently written Python
implementations. External results can only enter a report through explicit integrations
such as the OSV API, a local OSV database or `--codeql-sarif`.

| Project or service | License / terms | How it was used |
|---|---|---|
| [vianbas/sprig](https://github.com/vianbas/sprig) | MIT | Rule coverage comparison. Missing categories were implemented independently. |
| [Semgrep Registry](https://semgrep.dev/r) (`p/java`, `p/secrets`) | Varies by rule | Used as a validation reference. Semgrep rule files are not bundled or redistributed. |
| [OSV.dev](https://osv.dev) | Advisory records retain their upstream source terms | Public API queries, offline query caches and local SQLite imports from the official Maven export. Snapshot data is separate from the scanner script. |
| [GitHub CodeQL](https://codeql.github.com) | [CodeQL terms](https://securitylab.github.com/tools/codeql/license) | Used as a coverage and data-flow reference. CodeQL is optional; existing SARIF results can be imported. |
| [CodeQL Community Packs](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs) | Repository/package-specific terms | Rule categories were reviewed for coverage gaps. No `.ql` query is copied or redistributed. |
| [Spring Security Samples](https://github.com/spring-projects/spring-security-samples) | Apache-2.0 source headers | Used as a local scan target to validate servlet, WebFlux, RSocket, OAuth2 and X.509 detection. No sample source is included in JSpringGuard. |
| [Amaya-18/BootShield](https://github.com/Amaya-18/BootShield) | No license file found in the inspected snapshot | Compared only for ideas and feature coverage. No source or report assets were copied. |
| [NoAuthZone/Bookmark-Cleaner](https://github.com/NoAuthZone/Bookmark-cleaner) | MIT | Its dark/light report approach was an inspiration; JSpringGuard's report stylesheet and markup were written independently. |
| [JoyChou93/java-sec-code](https://github.com/JoyChou93/java-sec-code) | No license / unlicensed | Used only as a local test target. No files, excerpts or generated scan reports from it are included. |

The phrases “compared”, “validated” and “inspired” describe engineering research only;
they do not imply that those projects endorse JSpringGuard.

See the repository license file for the applicable project terms.

Built by [NoAuthZone](https://github.com/NoAuthZone/JSpringGuard) · JSpringGuard 4.0 · Offline scanning · One file, no dependencies.
