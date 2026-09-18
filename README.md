# JSpringGuard

**Static security scanner for Spring Boot / JVM projects — one Python file, zero dependencies.**

[![Version](https://img.shields.io/badge/version-3.8-blue)](https://github.com/NoAuthZone/JSpringGuard)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/) 
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](#requirements) 
[![Single file](https://img.shields.io/badge/install-none-lightgrey)](#quick-start) 
[![Offline](https://img.shields.io/badge/runs-offline-success)](#osvdev-and-air-gapped-scans)

JSpringGuard scans Java, Kotlin, Groovy and Scala projects for XML, Spring Security,
injection, dependency and build risks. It writes text, JSON, SARIF, Markdown or a
self-contained HTML report that opens directly from disk.

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
python3 jspringguard.py --selftest
```

## New in 3.8

- Local SQLite OSV database for offline Maven and Gradle dependency checks.
- Download, create, update or import the complete OSV Maven export.
- Exact package coordinates, corrected CVE mappings and no guessed Spring Boot-managed versions.
- Improved multiline detection and more conservative XXE `HARDENED` assessments.
- Explicit reporting of unresolved dependencies and incomplete OSV coverage.

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
| **Spring Security** | CSRF, broad `permitAll`, HTTP Basic, sessions, headers, CORS, password encoders, Actuator, Remember-Me, JWT/OAuth2, SAML, secrets and trust-all TLS |
| **Reactive security** | WebFlux `SecurityWebFilterChain`, `authorizeExchange`, functional `RouterFunction` routes, RSocket payload security, reactive JWT decoders and X.509 configuration |
| **Injection and crypto** | SQL, SSRF, path traversal, open redirect, LDAP, SpEL, JNDI, XPath, regex, reflection, command execution, CRLF, log injection and weak crypto |
| **Data handling** | XSS response sinks/templates, IDOR, mass assignment, missing `@Valid`, archive/decompression limits, sensitive logs/URLs and resource exhaustion |
| **Dependencies** | Spring Security/Boot, Log4j, Jackson, SnakeYAML, Commons, H2, Logback, Tomcat, dom4j, XStream, JDOM and optional online or local [OSV.dev](https://osv.dev) advisory checks |
| **Build hygiene** | HTTP repositories, insecure Gradle protocols, `mavenLocal()`, JCenter, dynamic/SNAPSHOT versions and insecure Gradle wrappers |
| **Configuration** | `application*.properties` / `.yml`: Actuator exposure, debug logging, cookies, plaintext secrets, TLS and `ddl-auto=create(-drop)` |

XXE checks use method context and selected helper-factory patterns. Hardening is
recognized conservatively: late, conditional or unsupported protection patterns may
still require review. Several injection checks correlate source and sink across lines
within the same method; general method-to-method data-flow analysis is not implemented.

## Usage and options

```bash
python3 jspringguard.py . --fail-on HIGH
python3 jspringguard.py . --format sarif --out report.sarif
python3 jspringguard.py . --format markdown --out report.md --context 3
python3 jspringguard.py . --skip-tests --min-severity MEDIUM
python3 jspringguard.py . --show-fix
python3 jspringguard.py --list-rules
```

| Option | Purpose |
|---|---|
| `--format {text,json,sarif,markdown,html}` | Output format |
| `--out FILE` | Output destination |
| `--fail-on LEVEL` | Exit 1 at or above the severity |
| `--min-severity LEVEL` | Hide findings below the severity |
| `--context N` | Show N lines before and after each finding |
| `--skip-tests` / `--no-deps` | Skip tests or dependency checks |
| `--show-hardened` / `--hide-hardened` | Include or hide recognized hardening; use `--min-severity INFO` for informational results |
| `--show-fix` | Display remediation templates; does not edit source files |
| `--osv-db FILE` | Check dependencies against a local SQLite advisory snapshot |
| `--osv-db-update FILE` | Download the Maven export and create or update the database |
| `--osv-db-build ZIP` | Import a downloaded Maven archive; requires `--osv-db FILE` |
| `--osv-db-info FILE` | Display snapshot metadata |
| `--check-osv` / `--check-osv-read FILE` | Online OSV queries or offline query-cache reuse |
| `--jobs N` / `--exclude DIRS` | Parallel readers or additional directories to skip |
| `--include-rule GLOB` | Only report matching rule IDs; repeatable |
| `--exclude-rule GLOB` | Suppress matching rule IDs; exclusion wins |
| `--list-rules` | List rule IDs, severities and descriptions |
| `--baseline FILE` / `--write-baseline FILE` | Hide known findings in CI |

Run `python3 jspringguard.py --help` for the complete option list.

## HTML and SARIF reports

HTML output is self-contained and works from `file://`: it provides dark/light themes,
severity and text/type filters, context lines and collapsible fix templates. SARIF
includes rule metadata and `helpUri` links for GitHub Code Scanning.

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

The second command performs no network request. The JSON cache only contains results
for previously queried package/version pairs; it is not a complete advisory database.
Use the SQLite snapshot when scanning other dependencies offline.

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
Without it, the scanner reads supported declarations in `pom.xml`, `build.gradle`,
`build.gradle.kts` and version catalogs. It does not guess versions from Spring Boot
release lines. Missing or dynamic versions are reported for review.

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
  run: python3 jspringguard.py . --format sarif --out results.sarif --fail-on HIGH
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with: { sarif_file: results.sarif }
```

## Suppression and baselines

```java
// sec-check:ignore
ObjectInputStream in = new ObjectInputStream(stream);

// sec-check:ignore[SRC-SSRF]
URI target = URI.create(configuredUrl);
```

For CI:

```bash
python3 jspringguard.py . --write-baseline .sec-baseline.json
python3 jspringguard.py . --baseline .sec-baseline.json --fail-on HIGH
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No retained findings meet the configured failure threshold |
| `1` | Retained, non-`HARDENED` findings meet the threshold |
| `2` | Invalid invocation, scan error or incomplete OSV/dependency-resolution coverage |

The default failure threshold is `MEDIUM`. `REVIEW` findings can also trigger it.
`--fail-on NONE` disables the finding threshold but does not suppress errors or
incomplete-coverage exit codes.

## Limits and validation

JSpringGuard is pattern- and method-scoped analysis with selected intraprocedural data
flow. It can produce false positives and miss framework semantics that require a full
taint engine or runtime context. Treat `REVIEW` findings as prompts for manual analysis.

`HARDENED` means a supported protection pattern was recognized, not that the application
is certified secure. An advisory match needs deployment context; a missing advisory
does not prove that a package is safe.


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

Built by [NoAuthZone](https://github.com/NoAuthZone/JSpringGuard) · JSpringGuard 3.8 · Offline scanning · One file, no dependencies.
