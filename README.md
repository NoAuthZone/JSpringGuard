# JSpringGuard

**Static security scanner for Spring Boot / JVM projects — one Python file, zero dependencies.**

[![Version](https://img.shields.io/badge/version-3.1.0-blue)](https://github.com/NoAuthZone/JSpringGuard/releases)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](#requirements)
[![Single file](https://img.shields.io/badge/install-none-lightgrey)](#quick-start)
[![Offline](https://img.shields.io/badge/runs-offline-success)](#optional-osvdev-dependency-check)

Drop one file into your project, run it, get a report. No install, no build step, no
server, no account. Finds XXE, Spring Security misconfiguration, injection patterns,
vulnerable dependencies and build/supply-chain issues — and writes a self-contained
HTML report you can open straight in a browser.

```bash
python3 jspringguard.py /path/to/your/project
```

> [!NOTE]
> This is a **heuristic linter**, not a full taint-analysis engine. It is a fast
> early-warning gate, not a substitute for a professional security review. See
> [Limits](#limits) before relying on it as a merge gate.

## Table of contents

- [Quick start](#quick-start)
- [Requirements](#requirements)
- [What it checks](#what-it-checks)
- [Usage](#usage)
- [HTML report](#html-report)
- [Optional: OSV.dev dependency check](#optional-osvdev-dependency-check)
- [Air-gapped workflow](#air-gapped-workflow)
- [CI integration](#ci-integration)
- [Maven / Gradle](#maven--gradle)
- [Suppressing findings](#suppressing-findings)
- [Exit codes](#exit-codes)
- [Limits](#limits)
- [Origin & methodology](#origin--methodology)
- [Third-party references & licensing](#third-party-references--licensing)

## Quick start

1. **Download** [`jspringguard.py`](jspringguard.py) into your project (or anywhere).
2. **Run it** against your source tree:
   ```bash
   python3 jspringguard.py .
   ```
3. **Get an HTML report** you can browse and filter:
   ```bash
   python3 jspringguard.py . --format html
   ```
   The report path is printed as a clickable `file://` link.

Verify the tool works as expected at any time:

```bash
python3 jspringguard.py --selftest
```

## Requirements

Python 3.8 or newer. Nothing else — no `pip install`, no third-party packages,
no Semgrep, no CodeQL, no Java toolchain. The scanner reads source files as text.

## What it checks

| Area | Examples |
|---|---|
| **XXE** | JAXP/DOM, SAX, StAX, Transformer/XSLT, SchemaFactory, dom4j, JDOM, JAXB, Spring OXM, Jackson XmlMapper, SOAP/SAAJ, XmlPullParser, Xerces, Commons Digester |
| **Unsafe deserialization** | `XMLDecoder`, `XStream` without allowlist, native `ObjectInputStream`, Jackson default typing, SnakeYAML without `SafeConstructor`, Fastjson |
| **Spring Security** | CSRF disabled, `permitAll()` on sensitive/actuator paths, missing auth, session fixation/timeout, missing CSP/HSTS/X-Frame-Options, CORS wildcard or Origin reflection, weak password encoders, exposed Actuator, remember-me issues, JWT (`alg: none`, algorithm confusion, missing issuer, long expiry), OAuth2 wildcard redirect / missing PKCE, missing `@EnableMethodSecurity`, SAML unsigned assertions, hardcoded secrets, trust-all TLS |
| **Injection & crypto** | Command execution, dynamic SpEL, JNDI lookups, SQL string concatenation (incl. the cross-line "build then execute" shape), SSRF, path traversal, open redirect, LDAP injection, CRLF/response splitting, log injection, MD5/SHA-1, `java.util.Random` for security values |
| **Dependencies** | Known-vulnerable versions of Spring Security/Boot, Log4j, Jackson, SnakeYAML, Commons Collections/Text, H2, Logback, Tomcat, dom4j, XStream, JDOM and more — plus optional live [OSV.dev](https://osv.dev) lookup |
| **Build hygiene** | HTTP (non-HTTPS) repositories, `allowInsecureProtocol`, `mavenLocal()`, `jcenter()`, dynamic/SNAPSHOT versions, Gradle wrapper over HTTP |
| **Config files** | `application*.properties` / `.yml`: exposed Actuator endpoints, debug logging, insecure cookies, plaintext secrets, disabled TLS, `ddl-auto=create(-drop)` |

**Beyond plain pattern matching:** XXE checks are *method-scoped* and resolve
helper factories across the whole project, so a hardened `XmlUtils.secureFactory()`
used elsewhere is correctly recognised as safe. Several injection checks correlate
a source and a sink *across lines within the same method* — for example a SQL string
built by concatenation on one line and executed on the next, which a per-line rule
would miss entirely.

**Build files:** Maven (`pom.xml`) and Gradle in all its common forms — inline
`'group:artifact:version'` strings, Kotlin DSL `version { }` blocks, `constraints { }`
blocks, and version catalogs (`libs.versions.toml`). Dependency findings show the
**actual declaration** from your build file plus a ready-to-paste fix snippet with
the corrected version already filled in.

## Usage

```bash
python3 jspringguard.py .                          # text report
python3 jspringguard.py . --fail-on HIGH           # gate: exit 1 on HIGH findings
python3 jspringguard.py . --format html            # self-contained HTML report
python3 jspringguard.py . --format sarif --out report.sarif
python3 jspringguard.py . --format markdown --out report.md
python3 jspringguard.py . --format json --out report.json
python3 jspringguard.py . --skip-tests --min-severity MEDIUM
python3 jspringguard.py . --check-osv              # add live OSV.dev CVE lookup
python3 jspringguard.py --selftest                 # built-in self-test
python3 jspringguard.py --fix CSRF CORS            # print hardened code templates
python3 jspringguard.py --poc                      # XXE counter-test payloads
```

### Options

| Option | Purpose |
|---|---|
| `--format {text,json,sarif,markdown,html}` | Output format (default `text`) |
| `--out FILE` | Output file. If omitted for non-text formats, a timestamped name is generated automatically (e.g. `jspringguard-myproject-20260905-142301.html`) |
| `--fail-on {INFO,LOW,MEDIUM,HIGH,CRITICAL,NONE}` | Exit 1 at or above this severity (default `MEDIUM`) |
| `--min-severity ...` | Hide findings below this severity |
| `--skip-tests` | Skip test directories |
| `--no-deps` | Skip the dependency check |
| `--show-hardened` | Also list locations that are already hardened |
| `--show-fix` | Print a fix snippet with each finding |
| `--baseline FILE` / `--write-baseline FILE` | Hide already-known findings (for CI) |
| `--check-osv` / `--check-osv-read FILE` | Live or offline OSV.dev lookup |
| `--jobs N` | Parallel workers (default 4) |

Run `python3 jspringguard.py --help` for the full list.

## HTML report

`--format html` writes one self-contained file — no external assets, no network
requests, opens straight from disk (`file://`):

- **Dark theme by default**, light-theme toggle remembered via `localStorage`
- **Severity chip bar** — click a chip to filter by that severity
- **Text filter + vulnerability-type dropdown**, combinable
- **One card per finding**: severity badge, type badge, location, code excerpt,
  guards set/missing, and a collapsible fix template
- **Expand/collapse all fix templates** with one button

## Optional: OSV.dev dependency check

The built-in dependency rules are a hand-maintained snapshot and go stale as new
advisories appear. `--check-osv` additionally checks every dependency against
[OSV.dev](https://osv.dev) — Google's free, open vulnerability database, no API key
needed.

```bash
python3 jspringguard.py . --check-osv
```

Queries are **deduplicated** (a dependency shared across several build files — e.g.
a multi-module Maven project — is queried once) and run **in parallel**. Every run
also writes a cache file for later offline reuse.

> [!TIP]
> Use `--check-osv` *together with* the built-in rules (i.e. without `--no-deps`).
> OSV covers Maven via GitHub Security Advisories, which does not include every
> older CVE — the two sources complement each other.

### Air-gapped workflow

```bash
# 1) On an internet-connected machine:
python3 jspringguard.py . --check-osv
# -> writes e.g. osv-cache-myproject-20260905-142301.json

# 2) Copy that file to the air-gapped machine, then run there:
python3 jspringguard.py . --check-osv-read osv-cache-myproject-20260905-142301.json
```

`--check-osv-read` works standalone and makes **no network call at all**. If queries
fail (no internet, proxy/firewall, SSL problem), the tool says so explicitly instead
of silently reporting zero findings.

## CI integration

Any CI system works — the tool is one file and returns a meaningful exit code.
GitHub Actions with SARIF upload to the Security tab:

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }

- name: Security scan
  run: python3 jspringguard.py . --format sarif --out results.sarif --fail-on HIGH

- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with: { sarif_file: results.sarif }
```

`upload-sarif` accepts any valid SARIF file — CodeQL itself is **not** required.

## Maven / Gradle

Optional — running the scanner from the command line is enough. To wire it into a
build, both integrations simply shell out to the same file.

<details>
<summary><b>Maven</b> — <code>exec-maven-plugin</code> in the <code>verify</code> phase</summary>

```xml
<plugin>
  <groupId>org.codehaus.mojo</groupId>
  <artifactId>exec-maven-plugin</artifactId>
  <version>3.5.1</version>
  <executions>
    <execution>
      <phase>verify</phase>
      <goals><goal>exec</goal></goals>
      <configuration>
        <executable>python3</executable>
        <arguments>
          <argument>jspringguard.py</argument>
          <argument>.</argument>
          <argument>--fail-on</argument><argument>HIGH</argument>
        </arguments>
      </configuration>
    </execution>
  </executions>
</plugin>
```
</details>

<details>
<summary><b>Gradle</b> — an <code>Exec</code> task wired into <code>check</code></summary>

```groovy
tasks.register('securityScan', Exec) {
    commandLine 'python3', 'jspringguard.py', '.', '--fail-on', 'HIGH'
}
tasks.named('check') { dependsOn 'securityScan' }
```
</details>

## Suppressing findings

Add `sec-check:ignore` on or above the line to silence a finding, optionally
limited to specific rules:

```java
// sec-check:ignore - internal, self-generated XML only
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// sec-check:ignore[XXE-DOM,XXE-SAX]
```

For CI, a **baseline** is usually better than inline suppressions — it records all
current findings so only *new* ones fail the build:

```bash
python3 jspringguard.py . --write-baseline .sec-baseline.json   # once
python3 jspringguard.py . --baseline .sec-baseline.json --fail-on HIGH
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the `--fail-on` threshold |
| `1` | Findings at or above the threshold |
| `2` | Invalid invocation or error |

## Limits

JSpringGuard is a **heuristic linter** — pattern- and regex-based, with
method-scoped context for several checks, but not a full data-flow/taint engine.
It will produce false positives, and it will miss things a taint engine would catch.

It was **AI-drafted and cross-validated** rather than hand-written and
battle-tested in production over years. Use `--selftest` and your own fixtures to
build confidence before relying on it as a merge gate — exactly as you would with
any new static-analysis tool.

## Origin & methodology

Drafted with AI assistance (Claude), then iteratively extended and validated:

- Rule coverage cross-checked against the [sprig](https://github.com/vianbas/sprig)
  ruleset; the gaps found are documented in `SPRIG-GAP-ANALYSIS.md` and closed with
  independently written rules.
- Cross-checked against Semgrep's registry rulesets (`p/java`, `p/secrets`) *during
  development only* — no Semgrep install is needed to run this tool.
- Several detectors were found and corrected by test-scanning
  [JoyChou93/java-sec-code](https://github.com/JoyChou93/java-sec-code), a well-known
  intentionally-vulnerable Spring Boot benchmark. That test surfaced real gaps —
  for example a SQL-injection shape split across two lines that the original rule
  missed completely.
- All of it is re-checked by the built-in `--selftest`, which should pass before any
  change is relied upon.

## Third-party references & licensing

This project references, was validated against, or drew design inspiration from the
projects below. **No source code from any of them is copied into this repository** —
only ideas, comparisons, and an independently written stylesheet.

| Project | License | How it was used |
|---|---|---|
| [vianbas/sprig](https://github.com/vianbas/sprig) | MIT | Rule coverage cross-checked; gaps documented in `SPRIG-GAP-ANALYSIS.md` and closed with independently written rules. |
| [Semgrep registry](https://semgrep.dev/r) (`p/java`, `p/secrets`) | mixed open-source (varies per rule) | Used during development via Semgrep's own CLI as a validation reference. No Semgrep rule files are redistributed here. |
| [OSV.dev](https://osv.dev) | data under CC-BY 4.0 / Apache-2.0 (see their site) | Consumed live via its public HTTP API, which is designed for exactly this kind of automated integration. No OSV data is bundled. |
| [GitHub CodeQL](https://codeql.github.com) | [CodeQL Terms & Conditions](https://securitylab.github.com/tools/codeql/license) | Optional custom `.ql` queries were written from scratch; GitHub's standard `codeql/java-all` pack is referenced, not redistributed. |
| [NoAuthZone/Bookmark-Cleaner](https://github.com/NoAuthZone/Bookmark-cleaner) | MIT | The HTML report's dark/light theme approach drew inspiration from this project. No CSS/HTML/JS is copied; the stylesheet is written for this project. |
| [JoyChou93/java-sec-code](https://github.com/JoyChou93/java-sec-code) | **none — [unlicensed](https://github.com/JoyChou93/java-sec-code/issues/97)** | Used only as a **local test target** during development. **No files, code excerpts, or scan reports from it are included here**, since it carries no license permitting redistribution. To reproduce that validation, clone it yourself and scan your own local copy — do not commit its contents into a public repo. |



---

Built by **[NoAuthZone](https://github.com/NoAuthZone)** · Runs entirely offline · One file, no dependencies
