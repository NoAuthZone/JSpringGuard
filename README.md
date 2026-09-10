# JSpringGuard

**Static security scanner for Spring Boot / JVM projects — one Python file, zero dependencies.**

[![Version](https://img.shields.io/badge/version-3.4.3-blue)](https://github.com/NoAuthZone/JSpringGuard)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/) 
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](#requirements) 
[![Single file](https://img.shields.io/badge/install-none-lightgrey)](#quick-start) 
[![Offline](https://img.shields.io/badge/runs-offline-success)](#osvdev-und-air-gapped-scans)

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

## Requirements

Python 3.8 or newer is required. No `pip install`, Java toolchain, Semgrep or CodeQL
installation is needed for the native rules.

## What it checks

| Area | Examples |
|---|---|
| **XXE and XML** | DOM/SAX/StAX, Transformer, SchemaFactory, dom4j, JDOM, JAXB, Spring OXM, Jackson XML, SOAP, Xerces and Digester |
| **Deserialization** | XMLDecoder, XStream, native `ObjectInputStream`, Jackson default typing, SnakeYAML and Fastjson |
| **Spring Security** | CSRF, broad `permitAll`, HTTP Basic, sessions, headers, CORS, password encoders, Actuator, Remember-Me, JWT/OAuth2, SAML, secrets and trust-all TLS |
| **Reactive security** | WebFlux `SecurityWebFilterChain`, `authorizeExchange`, functional `RouterFunction` routes, RSocket payload security, reactive JWT decoders and X.509 configuration |
| **Injection and crypto** | SQL, SSRF, path traversal, open redirect, LDAP, SpEL, JNDI, XPath, regex, reflection, command execution, CRLF, log injection and weak crypto |
| **Data handling** | XSS response sinks/templates, IDOR, mass assignment, missing `@Valid`, archive/decompression limits, sensitive logs/URLs and resource exhaustion |
| **Dependencies** | Spring Security/Boot, Log4j, Jackson, SnakeYAML, Commons, H2, Logback, Tomcat, dom4j, XStream, JDOM and optional live [OSV.dev](https://osv.dev) lookup |
| **Build hygiene** | HTTP repositories, insecure Gradle protocols, `mavenLocal()`, JCenter, dynamic/SNAPSHOT versions and insecure Gradle wrappers |
| **Configuration** | `application*.properties` / `.yml`: Actuator exposure, debug logging, cookies, plaintext secrets, TLS and `ddl-auto=create(-drop)` |

XXE checks are method-scoped and resolve helper factories across the project. Several
injection checks correlate source and sink across lines within the same method.

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
| `--show-hardened` / `--show-fix` | Show hardened locations or fix templates |
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

```bash
python3 jspringguard.py . --check-osv --osv-cache-write osv-cache.json
python3 jspringguard.py . --check-osv-read osv-cache.json
```

The second command performs no network request and is suitable for an air-gapped build.

## Effective Maven / Gradle dependencies

Runtime dependency resolution is opt-in because it executes the project wrapper or build:

```bash
python3 jspringguard.py . --resolve-deps --resolver-timeout 180
```

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
| `0` | No findings at or above the failure threshold |
| `1` | Findings at or above the threshold |
| `2` | Invalid invocation or scan error |

## Limits and validation

JSpringGuard is pattern- and method-scoped analysis with selected intraprocedural data
flow. It can produce false positives and miss framework semantics that require a full
taint engine or runtime context. Treat `REVIEW` findings as prompts for manual analysis.

Version 3.4.3 is validated by 46 regression tests and Python compilation checks. A scan
of the Spring Security Samples archive covered 441 source files and 76 build files. That
ZIP omitted 35 Git symlink targets, so those targets could not be read from the archive.

## References and licensing

This project was compared with the following projects, rule catalogues and test targets.
**No source files, rule files, CSS, HTML or Java code from these projects are
redistributed by JSpringGuard.** The scanner contains independently written Python
implementations. External results can only enter a report through explicit integrations
such as the OSV API or `--codeql-sarif`.

| Project or service | License / terms | How it was used |
|---|---|---|
| [vianbas/sprig](https://github.com/vianbas/sprig) | MIT | Rule coverage comparison. Missing categories were implemented independently. |
| [Semgrep Registry](https://semgrep.dev/r) (`p/java`, `p/secrets`) | Varies by rule | Used as a validation reference. Semgrep rule files are not bundled or redistributed. |
| [OSV.dev](https://osv.dev) | OSV data terms include CC-BY 4.0 and Apache-2.0 sources | Queried through the public API when `--check-osv` is selected. No vulnerability database is bundled. |
| [GitHub CodeQL](https://codeql.github.com) | [CodeQL terms](https://securitylab.github.com/tools/codeql/license) | Used as a coverage and data-flow reference. CodeQL is optional; existing SARIF results can be imported. |
| [CodeQL Community Packs](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs) | Repository/package-specific terms | Rule categories were reviewed for coverage gaps. No `.ql` query is copied or redistributed. |
| [Spring Security Samples](https://github.com/spring-projects/spring-security-samples) | Apache-2.0 source headers | Used as a local scan target to validate servlet, WebFlux, RSocket, OAuth2 and X.509 detection. No sample source is included in JSpringGuard. |
| [Amaya-18/BootShield](https://github.com/Amaya-18/BootShield) | No license file found in the inspected snapshot | Compared only for ideas and feature coverage. No source or report assets were copied. |
| [NoAuthZone/Bookmark-Cleaner](https://github.com/NoAuthZone/Bookmark-cleaner) | MIT | Its dark/light report approach was an inspiration; JSpringGuard's report stylesheet and markup were written independently. |
| [JoyChou93/java-sec-code](https://github.com/JoyChou93/java-sec-code) | No license / unlicensed | Used only as a local test target. No files, excerpts or generated scan reports from it are included. |

The phrases “compared”, “validated” and “inspired” describe engineering research only;
they do not imply that those projects endorse JSpringGuard.

See the repository license file for the applicable project terms.

Built by [NoAuthZone](https://github.com/NoAuthZone/JSpringGuard) · Runs offline · One file, no dependencies.
