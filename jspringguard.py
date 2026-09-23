```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSpringGuard 4.0 - Static security analysis for JVM projects with offline OSV support.

STANDALONE TOOL: this single file is everything you need for its native rules. No Semgrep,
CodeQL CLI/database, no other scripts, and no third-party Python packages -
just this file and a Python 3.8+ interpreter. Any mention of "CodeQL" below
refers to detection techniques that have been ported into this file's own
Python rules; it does not mean CodeQL needs to be installed or run.

New in 4.0 (report aligned with the supplied Security Flow Explorer):
  * interactive source previews, reverse references, control explanations
  * role/authority matrix, conditional configuration evidence, risk ranking
  * unresolved call boundaries, policy snapshots/drift, flow/control triage
  * single offline file; heuristic analysis, not a proof of runtime security

No third-party dependencies. Python 3.8+.

Examples:
    python3 jspringguard.py ./src
    python3 jspringguard.py . --skip-tests --min-severity MEDIUM
    python3 jspringguard.py . --format html --out report.html
    python3 jspringguard.py . --coverage
    python3 jspringguard.py . --coverage --format html --out coverage.html
    python3 jspringguard.py . --coverage --fail-on-coverage-gap
    python3 jspringguard.py . --write-baseline .sec-baseline.json
    python3 jspringguard.py . --baseline .sec-baseline.json --fail-on HIGH
    python3 jspringguard.py . --include-rule 'SRC-XSS-*' --exclude-rule '*-WRITER'
    python3 jspringguard.py . --resolve-deps --check-osv
    python3 jspringguard.py --selftest
    python3 jspringguard.py --fix CSRF CORS
    python3 jspringguard.py --poc

Exit codes: 0 = nothing above threshold, 1 = findings above threshold, 2 = error.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import html as html_mod
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

VERSION = "4.0"
AUTHOR = "NoAuthZone"
AUTHOR_URL = "https://github.com/NoAuthZone"
REPO_URL = "https://github.com/NoAuthZone/JSpringGuard"

DEFAULT_EXTS = (".java", ".kt", ".jsp", ".groovy", ".scala")
CERT_TEXT_EXTS = (".pem", ".key")
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg", ".idea", ".vscode", "node_modules",
    "target", "build", "out", "bin", "dist", ".gradle", ".mvn", "generated",
}
BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts", "ivy.xml", "libs.versions.toml")

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_LIST = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SUPPRESS_MARKER = re.compile(r"sec-check\s*:\s*ignore(?:\s*\[([^\]]*)\])?", re.I)

# --------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------

FALSE = r"(?:false|Boolean\s*\.\s*FALSE)"
TRUE = r"(?:true|Boolean\s*\.\s*TRUE)"

GUARD_PATTERNS: Dict[str, re.Pattern] = {
    "DISALLOW_DOCTYPE": re.compile(r"disallow-doctype-decl\s*\"\s*,\s*" + TRUE, re.I),
    "EXT_GENERAL_ENTITIES": re.compile(r"external-general-entities\s*\"\s*,\s*" + FALSE, re.I),
    "EXT_PARAM_ENTITIES": re.compile(r"external-parameter-entities\s*\"\s*,\s*" + FALSE, re.I),
    "LOAD_EXTERNAL_DTD": re.compile(r"load-external-dtd\s*\"\s*,\s*" + FALSE, re.I),
    "EXPAND_ENTITY_REF": re.compile(r"setExpandEntityReferences\s*\(\s*" + FALSE + r"\s*\)", re.I),
    "XINCLUDE_OFF": re.compile(r"setXIncludeAware\s*\(\s*" + FALSE + r"\s*\)", re.I),
    "STAX_SUPPORT_DTD": re.compile(
        r"(?:XMLInputFactory\s*\.\s*SUPPORT_DTD|\"\s*javax\.xml\.stream\.supportDTD\s*\")"
        r"\s*,\s*" + FALSE, re.I),
    "STAX_EXT_ENTITIES": re.compile(
        r"(?:IS_SUPPORTING_EXTERNAL_ENTITIES|\"\s*javax\.xml\.stream\.isSupportingExternalEntities\s*\")"
        r"\s*,\s*" + FALSE, re.I),
    "ACCESS_EXTERNAL_DTD": re.compile(
        r"(?:ACCESS_EXTERNAL_DTD|accessExternalDTD\s*\")\s*,\s*\"\s*\"", re.I),
    "ACCESS_EXTERNAL_SCHEMA": re.compile(
        r"(?:ACCESS_EXTERNAL_SCHEMA|accessExternalSchema\s*\")\s*,\s*\"\s*\"", re.I),
    "ACCESS_EXTERNAL_STYLESHEET": re.compile(
        r"(?:ACCESS_EXTERNAL_STYLESHEET|accessExternalStylesheet\s*\")\s*,\s*\"\s*\"", re.I),
    "SECURE_PROCESSING": re.compile(r"FEATURE_SECURE_PROCESSING\s*,\s*" + TRUE, re.I),
    "ENTITY_RESOLVER": re.compile(r"setEntityResolver\s*\(", re.I),
    "VALIDATION_OFF": re.compile(r"setValidation\s*\(\s*" + FALSE + r"\s*\)", re.I),
    # Spring OXM
    "SPRING_SUPPORT_DTD": re.compile(r"setSupportDtd\s*\(\s*" + FALSE + r"\s*\)", re.I),
    "SPRING_EXT_ENTITIES": re.compile(r"setProcessExternalEntities\s*\(\s*" + FALSE + r"\s*\)", re.I),
    # XStream
    "XSTREAM_ALLOWLIST": re.compile(r"\.\s*(?:allowTypes|allowTypesByWildcard|allowTypeHierarchy)\s*\(", re.I),
    # Android XmlPullParser
    "PULL_NO_DOCDECL": re.compile(r"FEATURE_PROCESS_DOCDECL\s*,\s*" + FALSE, re.I),
}

GUARD_HINTS: Dict[str, str] = {
    "DISALLOW_DOCTYPE": 'setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)',
    "EXT_GENERAL_ENTITIES": 'setFeature("http://xml.org/sax/features/external-general-entities", false)',
    "EXT_PARAM_ENTITIES": 'setFeature("http://xml.org/sax/features/external-parameter-entities", false)',
    "LOAD_EXTERNAL_DTD": 'setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)',
    "EXPAND_ENTITY_REF": "setExpandEntityReferences(false)",
    "XINCLUDE_OFF": "setXIncludeAware(false)",
    "STAX_SUPPORT_DTD": "setProperty(XMLInputFactory.SUPPORT_DTD, false)",
    "STAX_EXT_ENTITIES": "setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)",
    "ACCESS_EXTERNAL_DTD": 'setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")',
    "ACCESS_EXTERNAL_SCHEMA": 'setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")',
    "ACCESS_EXTERNAL_STYLESHEET": 'setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")',
    "SECURE_PROCESSING": "setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
    "ENTITY_RESOLVER": "setEntityResolver(<resolver that rejects external entities>)",
    "SPRING_SUPPORT_DTD": "setSupportDtd(false)",
    "SPRING_EXT_ENTITIES": "setProcessExternalEntities(false)",
    "XSTREAM_ALLOWLIST": "xstream.allowTypes(new Class[]{ ... })  // allowlist instead of denylist",
    "PULL_NO_DOCDECL": "setFeature(XmlPullParser.FEATURE_PROCESS_DOCDECL, false)",
    "VALIDATION_OFF": "setValidation(false)",
}

# --------------------------------------------------------------------------
# Sinks
# --------------------------------------------------------------------------


@dataclass
class Rule:
    rid: str
    name: str
    pattern: re.Pattern
    severity: str
    sufficient: Sequence[Sequence[str]]
    partial: Sequence[str] = ()
    note: str = ""
    always_report: bool = False
    fix: str = ""
    kind: str = "sink"          # sink | antipattern | hardening


FIX_JAXP = """DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);"""

FIX_SAX = """SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setNamespaceAware(true);
XMLReader reader = spf.newSAXParser().getXMLReader();
reader.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));"""

FIX_STAX = """XMLInputFactory xif = XMLInputFactory.newFactory();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);"""

FIX_TRANSFORMER = """TransformerFactory tf = TransformerFactory.newInstance();
tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");"""

FIX_SCHEMA = """SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
Validator v = schema.newValidator();
v.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
v.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");"""

FIX_JAXB = """// Do not use unmarshal(File/InputStream); use a SAXSource with a hardened reader:
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setNamespaceAware(true);
Source source = new SAXSource(spf.newSAXParser().getXMLReader(), new InputSource(in));
Object result = JAXBContext.newInstance(MyType.class).createUnmarshaller().unmarshal(source);"""

FIX_DOM4J = """SAXReader reader = new SAXReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
// also use dom4j >= 2.1.3"""

FIX_JDOM = """SAXBuilder builder = new SAXBuilder(XMLReaders.NONVALIDATING);
builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
builder.setExpandEntities(false);"""

FIX_SPRING = """Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
marshaller.setSupportDtd(false);
marshaller.setProcessExternalEntities(false);"""

FIX_XSTREAM = """XStream xstream = new XStream();
XStream.setupDefaultSecurity(xstream);          // for XStream < 1.4.18
xstream.allowTypes(new Class[]{ MyDto.class }); // allowlist, not a denylist"""

FIX_XMLDECODER = """// No safe setup possible. Replace XMLDecoder with a data-oriented
// format (JAXB with an allowlist, Jackson with a fixed target type, JSON schema)."""

FIX_PULL = """XmlPullParserFactory f = XmlPullParserFactory.newInstance();
XmlPullParser p = f.newPullParser();
p.setFeature(XmlPullParser.FEATURE_PROCESS_DOCDECL, false);"""

FIX_SOAP = """// SAAJ/JAX-WS: enforce XML hardening on the underlying parser,
// e.g. system property javax.xml.accessExternalDTD="" plus a custom
// SOAPMessage handler that rejects DOCTYPE declarations."""

RULES: List[Rule] = [
    Rule("XXE-DOM", "DocumentBuilderFactory (DOM)",
         re.compile(r"\bDocumentBuilderFactory\s*\.\s*newInstance\s*\(|"
                    r"\bDocumentBuilderFactory\s+\w+\s*="),
         "HIGH",
         [["DISALLOW_DOCTYPE"],
          ["EXT_GENERAL_ENTITIES", "EXT_PARAM_ENTITIES", "LOAD_EXTERNAL_DTD"]],
         ["EXT_GENERAL_ENTITIES", "EXT_PARAM_ENTITIES", "LOAD_EXTERNAL_DTD",
          "ENTITY_RESOLVER", "SECURE_PROCESSING", "EXPAND_ENTITY_REF"],
         "DOM parsing reads external entities by default (file leak, SSRF, billion laughs).",
         fix=FIX_JAXP),
    Rule("XXE-SAX", "SAXParserFactory / XMLReader",
         re.compile(r"\bSAXParserFactory\s*\.\s*newInstance\s*\(|"
                    r"\bXMLReaderFactory\s*\.\s*createXMLReader\s*\(|"
                    r"\bSAXParserFactory\s+\w+\s*="),
         "HIGH",
         [["DISALLOW_DOCTYPE"],
          ["EXT_GENERAL_ENTITIES", "EXT_PARAM_ENTITIES", "LOAD_EXTERNAL_DTD"]],
         ["EXT_GENERAL_ENTITIES", "EXT_PARAM_ENTITIES", "LOAD_EXTERNAL_DTD",
          "ENTITY_RESOLVER", "SECURE_PROCESSING"],
         "SAX parsing reads external entities by default.",
         fix=FIX_SAX),
    Rule("XXE-STAX", "XMLInputFactory (StAX)",
         re.compile(r"\bXMLInputFactory\s*\.\s*(?:newInstance|newFactory)\s*\(|"
                    r"\bXMLInputFactory\s+\w+\s*="),
         "HIGH",
         [["STAX_SUPPORT_DTD"], ["STAX_EXT_ENTITIES", "ACCESS_EXTERNAL_DTD"]],
         ["STAX_EXT_ENTITIES", "ACCESS_EXTERNAL_DTD", "SECURE_PROCESSING"],
         "StAX supports DTDs by default (exception: individually hardened runtimes).",
         fix=FIX_STAX),
    Rule("XXE-TRANSFORMER", "TransformerFactory / XSLT",
         re.compile(r"\b(?:SAX)?TransformerFactory\s*\.\s*newInstance\s*\(|"
                    r"\bTransformerFactory\s+\w+\s*="),
         "HIGH",
         [["ACCESS_EXTERNAL_DTD", "ACCESS_EXTERNAL_STYLESHEET"]],
         ["SECURE_PROCESSING", "ACCESS_EXTERNAL_DTD", "ACCESS_EXTERNAL_STYLESHEET"],
         "XSLT can load external resources via document(), xsl:import and xsl:include.",
         fix=FIX_TRANSFORMER),
    Rule("XXE-SCHEMA", "SchemaFactory / Validator",
         re.compile(r"\bSchemaFactory\s*\.\s*newInstance\s*\(|\.\s*newValidator\s*\("),
         "MEDIUM",
         [["ACCESS_EXTERNAL_DTD", "ACCESS_EXTERNAL_SCHEMA"]],
         ["SECURE_PROCESSING", "ACCESS_EXTERNAL_DTD", "ACCESS_EXTERNAL_SCHEMA"],
         "Validation can fetch external schemas and DTDs.",
         fix=FIX_SCHEMA),
    Rule("XXE-XPATH", "XPathFactory",
         re.compile(r"\bXPathFactory\s*\.\s*newInstance\s*\("),
         "LOW", [["SECURE_PROCESSING"]], [],
         "Only relevant if the evaluated document was parsed without hardening.",
         fix="XPathFactory xpf = XPathFactory.newInstance();\n"
             "xpf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);"),
    Rule("XXE-DOM4J", "dom4j SAXReader",
         re.compile(r"\bnew\s+SAXReader\s*\(|\bDocumentHelper\s*\.\s*parseText\s*\("),
         "HIGH",
         [["DISALLOW_DOCTYPE"],
          ["EXT_GENERAL_ENTITIES", "EXT_PARAM_ENTITIES", "LOAD_EXTERNAL_DTD"]],
         ["ENTITY_RESOLVER", "VALIDATION_OFF"],
         "dom4j before 2.1.3 is vulnerable by default; DocumentHelper.parseText cannot be hardened at all.",
         fix=FIX_DOM4J),
    Rule("XXE-JDOM", "JDOM SAXBuilder",
         re.compile(r"\bnew\s+SAXBuilder\s*\("),
         "HIGH",
         [["DISALLOW_DOCTYPE"],
          ["EXT_GENERAL_ENTITIES", "EXT_PARAM_ENTITIES", "LOAD_EXTERNAL_DTD"]],
         ["ENTITY_RESOLVER", "EXPAND_ENTITY_REF"],
         "SAXBuilder needs explicit features or XMLReaders.NONVALIDATING.",
         fix=FIX_JDOM),
    Rule("XXE-JAXB", "JAXB Unmarshaller",
         re.compile(r"\bcreateUnmarshaller\s*\(\s*\)|\bJAXB\s*\.\s*unmarshal\s*\("),
         "MEDIUM", [], [], always_report=True,
         note="unmarshal(File/InputStream/Source) parses without hardening internally. "
              "Safe only via unmarshal(SAXSource) with a hardened XMLReader.",
         fix=FIX_JAXB),
    Rule("XXE-SPRING-OXM", "Spring OXM Jaxb2Marshaller",
         re.compile(r"\bnew\s+Jaxb2Marshaller\s*\(|\bJaxb2Marshaller\s+\w+\s*="),
         "HIGH",
         [["SPRING_SUPPORT_DTD"], ["SPRING_EXT_ENTITIES"]],
         ["SPRING_EXT_ENTITIES", "SPRING_SUPPORT_DTD"],
         "Jaxb2Marshaller allows DTDs once setSupportDtd(true) is set, or by default "
         "in older Spring versions.",
         fix=FIX_SPRING),
    Rule("XXE-JACKSON-XML", "Jackson XmlMapper / XmlFactory",
         re.compile(r"\bnew\s+XmlMapper\s*\(|\bnew\s+XmlFactory\s*\("),
         "MEDIUM", [["STAX_SUPPORT_DTD"], ["STAX_EXT_ENTITIES"]],
         ["STAX_EXT_ENTITIES", "SECURE_PROCESSING"],
         "XmlMapper internally uses an XMLInputFactory (Woodstox/StAX) - harden it "
         "and pass it via the constructor.",
         fix="XMLInputFactory xif = XMLInputFactory.newFactory();\n"
             "xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);\n"
             "xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);\n"
             "XmlMapper mapper = new XmlMapper(new XmlFactory(xif));"),
    Rule("XXE-SOAP", "SAAJ / SOAP MessageFactory",
         re.compile(r"\bMessageFactory\s*\.\s*newInstance\s*\(|\bSOAPMessage\s+\w+\s*="),
         "MEDIUM", [], [], always_report=True,
         note="SOAP endpoints parse XML before your own code runs. Hardening is only "
              "possible via parser configuration or system properties.",
         fix=FIX_SOAP),
    Rule("XXE-PULLPARSER", "XmlPullParser (Android/kXML)",
         re.compile(r"\bXmlPullParserFactory\s*\.\s*newInstance\s*\(|\bnewPullParser\s*\("),
         "MEDIUM", [["PULL_NO_DOCDECL"]], [],
         "FEATURE_PROCESS_DOCDECL must be explicitly set to false.",
         fix=FIX_PULL),
    Rule("XXE-XERCES-DIRECT", "Xerces DOMParser/SAXParser used directly",
         re.compile(r"\bnew\s+(?:org\.apache\.xerces\.parsers\.)?(?:DOMParser|SAXParser)\s*\("),
         "HIGH",
         [["DISALLOW_DOCTYPE"],
          ["EXT_GENERAL_ENTITIES", "EXT_PARAM_ENTITIES", "LOAD_EXTERNAL_DTD"]],
         ["ENTITY_RESOLVER"],
         "Direct Xerces parsers bypass any JAXP hardening.",
         fix=FIX_JAXP),
    Rule("XXE-DIGESTER", "Apache Commons Digester",
         re.compile(r"\bnew\s+Digester\s*\("),
         "MEDIUM",
         [["DISALLOW_DOCTYPE"], ["EXT_GENERAL_ENTITIES", "EXT_PARAM_ENTITIES"]],
         ["ENTITY_RESOLVER", "VALIDATION_OFF"],
         "Digester uses a SAX parser internally.",
         fix=FIX_SAX),
    Rule("DESER-XMLDECODER", "java.beans.XMLDecoder",
         re.compile(r"\bnew\s+XMLDecoder\s*\("),
         "CRITICAL", [], [], always_report=True,
         note="Not XXE but insecure deserialization with a direct RCE path. "
              "Never apply to untrusted data.",
         fix=FIX_XMLDECODER),
    Rule("DESER-XSTREAM", "XStream fromXML",
         re.compile(r"\bnew\s+XStream\s*\(|\.\s*fromXML\s*\("),
         "HIGH", [["XSTREAM_ALLOWLIST"]], ["XSTREAM_ALLOWLIST"],
         "XStream without a type allowlist leads to RCE (gadget chains).",
         fix=FIX_XSTREAM),
]

RULE_BY_ID = {r.rid: r for r in RULES}

# ---- Anti-patterns: values that are actively set to something insecure ---

_T = r"(?:true|Boolean\s*\.\s*TRUE)"
_F = r"(?:false|Boolean\s*\.\s*FALSE)"

RULES += [
    Rule("ANTI-DOCTYPE-ON", "disallow-doctype-decl explicitly set to false",
         re.compile(r"disallow-doctype-decl\s*\"\s*,\s*" + _F, re.I),
         "HIGH", [], [],
         "DTD processing is explicitly re-enabled.",
         always_report=True, kind="antipattern",
         fix='setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'),
    Rule("ANTI-STAX-DTD-ON", "StAX SUPPORT_DTD set to true",
         re.compile(r"(?:SUPPORT_DTD|supportDTD\s*\")\s*,\s*" + _T, re.I),
         "HIGH", [], [], "DTDs are enabled in the StAX parser.",
         always_report=True, kind="antipattern",
         fix="xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);"),
    Rule("ANTI-EXT-ENTITIES-ON", "external entities explicitly enabled",
         re.compile(r"external-(?:general|parameter)-entities\s*\"\s*,\s*" + _T +
                    r"|IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*" + _T +
                    r"|setProcessExternalEntities\s*\(\s*" + _T, re.I),
         "HIGH", [], [], "External entities are explicitly allowed.",
         always_report=True, kind="antipattern"),
    Rule("ANTI-SPRING-DTD-ON", "Jaxb2Marshaller setSupportDtd(true)",
         re.compile(r"setSupportDtd\s*\(\s*" + _T + r"\s*\)", re.I),
         "HIGH", [], [], "The Spring marshaller allows DTDs.",
         always_report=True, kind="antipattern",
         fix="marshaller.setSupportDtd(false);\nmarshaller.setProcessExternalEntities(false);"),
    Rule("ANTI-ACCESS-ALL", 'ACCESS_EXTERNAL_* set to "all"',
         re.compile(r"ACCESS_EXTERNAL_(?:DTD|SCHEMA|STYLESHEET)\s*,\s*\"\s*all\s*\"", re.I),
         "HIGH", [], [], "Completely lifts the JAXP 1.5 restriction.",
         always_report=True, kind="antipattern"),
    Rule("ANTI-XINCLUDE-ON", "setXIncludeAware(true)",
         re.compile(r"setXIncludeAware\s*\(\s*" + _T + r"\s*\)", re.I),
         "MEDIUM", [], [],
         "XInclude embeds local files - works even when DOCTYPE is blocked.",
         always_report=True, kind="antipattern",
         fix="dbf.setXIncludeAware(false);"),
    Rule("ANTI-EXPAND-ENTITIES-ON", "setExpandEntityReferences/setExpandEntities(true)",
         re.compile(r"setExpand(?:EntityReferences|Entities)\s*\(\s*" + _T + r"\s*\)", re.I),
         "MEDIUM", [], [], "Entity references are deliberately expanded.",
         always_report=True, kind="antipattern"),
]


# ==========================================================================
# Spring Security rule family
# ==========================================================================

# --- Guards ----------------------------------------------------------------
SPRING_GUARD_PATTERNS: dict = {
    # CSRF
    "CSRF_ENABLED":          re.compile(r"\.csrf\(\s*(?:Customizer\.withDefaults|c\s*->|csrf\s*->)(?!\s*c\.disable|\s*csrf\.disable)", re.I),
    "CSRF_REPO":             re.compile(r"setCsrfTokenRepository\s*\(|csrfTokenRepository\s*\(", re.I),
    "CSRF_MATCHER":          re.compile(r"requireCsrfProtectionMatcher\s*\(", re.I),
    # Auth
    "AUTH_REQUIRED":         re.compile(r"\.authenticated\(\)|\.hasRole\s*\(|\.hasAuthority\s*\(|\.hasAnyRole\s*\(|\.hasAnyAuthority\s*\(|\.access\s*\(", re.I),
    "METHOD_SECURITY_ENABLED": re.compile(r"@Enable(?:Global)?MethodSecurity\b"),
    "FORM_LOGIN_SECURED":    re.compile(r"\.formLogin\s*\((?!.*disable)", re.I),
    "HTTP_BASIC_SECURED":    re.compile(r"\.httpBasic\s*\((?!.*disable)", re.I),
    "OAUTH2_SECURED":        re.compile(r"\.oauth2Login\s*\(|\.oauth2ResourceServer\s*\(", re.I),
    # Session
    "SESSION_FIXATION":      re.compile(r"\.sessionFixation\s*\(\s*\)\s*\.\s*(?:newSession|migrateSession|changeSessionId)", re.I),
    "SESSION_STATELESS":     re.compile(r"SessionCreationPolicy\s*\.\s*STATELESS", re.I),
    "SESSION_TIMEOUT":       re.compile(r"setMaxInactiveInterval\s*\(|session-timeout|invalidSessionUrl\s*\(", re.I),
    # Header
    "HSTS":                  re.compile(r"\.headers\s*\(.*?\.hsts\s*\(|http\.headers\s*\(\s*\)", re.I),
    "CSP":                   re.compile(r"contentSecurityPolicy\s*\(|\.defaultSrc\s*\(", re.I),
    "FRAME_OPTIONS":         re.compile(r"\.frameOptions\s*\(\s*\)\s*\.\s*(?:deny|sameOrigin)", re.I),
    "HTTPS_REDIRECT":        re.compile(r"requiresSecure\s*\(|requiresChannel\s*\(.*?https|portMapper\s*\(", re.I),
    # CORS
    "CORS_EXPLICIT":         re.compile(r"\.cors\s*\(\s*c\s*->|CorsConfigurationSource|corsConfiguration\s*\.", re.I),
    "CORS_CREDENTIALS_OFF":  re.compile(r"setAllowCredentials\s*\(\s*false\s*\)", re.I),
    "CORS_ORIGINS_SPECIFIC": re.compile(r"setAllowedOrigins\s*\(\s*(?!.*\"\s*\*\s*\")", re.I),
    # Password
    "BCRYPT":                re.compile(r"BCryptPasswordEncoder\s*\(|PasswordEncoderFactories\.createDelegatingPasswordEncoder", re.I),
    "ARGON2":                re.compile(r"Argon2PasswordEncoder", re.I),
    "PBKDF2":                re.compile(r"Pbkdf2PasswordEncoder", re.I),
    # Actuator
    "ACTUATOR_SECURED":      re.compile(r"EndpointRequest\.to\s*\(|EndpointRequest\.toAnyEndpoint\s*\(\s*\)\s*\.\s*(?:authenticated|hasRole|hasAuthority)", re.I),
    # Remember-Me
    "REMEMBERME_KEY":        re.compile(r"\.rememberMe\s*\(\s*\)\s*\.\s*key\s*\(|rememberMeServices\s*\(", re.I),
    "REMEMBERME_LIMIT":      re.compile(r"tokenValiditySeconds\s*\(\s*\d+\s*\)", re.I),
    # JWT / OAuth2
    "JWT_VALIDATION":        re.compile(r"JwtDecoder|NimbusJwtDecoder|jwtDecoder\s*\(|JwtAuthenticationConverter", re.I),
    "OPAQUE_TOKEN":          re.compile(r"opaqueToken\s*\(|introspect\s*\(", re.I),
}
GUARD_PATTERNS.update(SPRING_GUARD_PATTERNS)

SPRING_GUARD_HINTS: dict = {
    "CSRF_ENABLED":          ".csrf(Customizer.withDefaults()) - do not disable csrf",
    "CSRF_REPO":             ".csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))",
    "CSRF_MATCHER":          ".csrf(c -> c.requireCsrfProtectionMatcher(new AntPathRequestMatcher(...)))",
    "AUTH_REQUIRED":         ".authorizeHttpRequests(a -> a.anyRequest().authenticated())",
    "SESSION_FIXATION":      ".sessionManagement(s -> s.sessionFixation().newSession())",
    "SESSION_TIMEOUT":       "set server.servlet.session.timeout in application.properties",
    "HSTS":                  ".headers(h -> h.httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000)))",
    "CSP":                   ".headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives(\"default-src 'self'\")))",
    "FRAME_OPTIONS":         ".headers(h -> h.frameOptions(fo -> fo.deny()))",
    "HTTPS_REDIRECT":        ".requiresChannel(c -> c.anyRequest().requiresSecure())",
    "CORS_EXPLICIT":         "register a CorsConfigurationSource bean with explicit allowed origins",
    "CORS_CREDENTIALS_OFF":  "config.setAllowCredentials(false), or specific origins instead of a wildcard",
    "CORS_ORIGINS_SPECIFIC": "config.setAllowedOrigins(List.of(\"https://myapp.example.com\"))",
    "BCRYPT":                "new BCryptPasswordEncoder(12)  // cost >= 12",
    "ACTUATOR_SECURED":      ".authorizeHttpRequests(a -> a.requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole(\"ADMIN\"))",
    "REMEMBERME_KEY":        ".rememberMe(r -> r.key(env.getRequiredProperty(\"app.remember-me-key\")))",
    "REMEMBERME_LIMIT":      ".rememberMe(r -> r.tokenValiditySeconds(86400))  // max. 24h",
    "JWT_VALIDATION":        "NimbusJwtDecoder.withJwkSetUri(jwksUri).build()",
}
GUARD_HINTS.update(SPRING_GUARD_HINTS)

# --- Fix snippets ----------------------------------------------------------
FIX_CSRF = """\
// Spring Security >= 6 (lambda DSL)
http.csrf(Customizer.withDefaults());
// or with a cookie repo for a SPA:
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler()));"""

FIX_AUTH = """\
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .anyRequest().authenticated()
);"""

FIX_SESSION = """\
http.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    .sessionFixation().newSession()
    .maximumSessions(1).expiredUrl("/session-expired")
);"""

FIX_HEADERS = """\
http.headers(h -> h
    .httpStrictTransportSecurity(hsts -> hsts
        .includeSubDomains(true).maxAgeInSeconds(31_536_000))
    .frameOptions(fo -> fo.deny())
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'; script-src 'self'"))
    .referrerPolicy(rp -> rp
        .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN))
    .permissionsPolicy(pp -> pp.policy("camera=(), microphone=()"))
);"""

FIX_CORS = """\
@Bean
CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration cfg = new CorsConfiguration();
    cfg.setAllowedOrigins(List.of("https://app.example.com"));
    cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    cfg.setAllowCredentials(false);  // true only with specific origins
    cfg.setMaxAge(3600L);
    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
    src.registerCorsConfiguration("/**", cfg);
    return src;
}"""

FIX_PASSWORD = """\
// BCrypt with an explicit cost factor
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}
// Recommended: DelegatingPasswordEncoder allows migration
@Bean
PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}"""

FIX_ACTUATOR = """\
// In SecurityFilterChain:
http.authorizeHttpRequests(auth -> auth
    .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("ADMIN")
    .anyRequest().authenticated()
);
// In application.properties:
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=when-authorized"""

FIX_REMEMBERME = """\
http.rememberMe(r -> r
    .key(env.getRequiredProperty("app.remember-me-key"))  // from config, not hardcoded
    .tokenValiditySeconds(86400)                           // max. 24h
    .useSecureCookie(true)
    .rememberMeCookieName("remember-me")
);"""

FIX_JWT = """\
@Bean
JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withJwkSetUri(jwksUri)
        .jwsAlgorithm(SignatureAlgorithm.RS256)
        .build();
}
http.oauth2ResourceServer(oauth2 -> oauth2
    .jwt(jwt -> jwt.decoder(jwtDecoder()))
);"""

FIX_NOOPENCODER = """\
// Do NOT use NoOpPasswordEncoder / a plaintext encoder in production.
// Migration to BCrypt:
// 1) use a DelegatingPasswordEncoder as a temporary bridge
// 2) rehash passwords on the next login (BCrypt)
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}"""

# --- Spring Security rules -------------------------------------------------

FIX_JWT_FULL = """// NimbusJwtDecoder with issuer and audience validation
@Bean
JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
        .jwsAlgorithm(SignatureAlgorithm.RS256)   // explicit - never accept 'none'
        .build();
    OAuth2TokenValidator<Jwt> validators = new DelegatingOAuth2TokenValidator<>(
        JwtValidators.createDefaultWithIssuer("https://auth.example.com"),
        new JwtClaimValidator<List<String>>("aud", a -> a.contains("my-api")),
        new JwtTimestampValidator(Duration.ofSeconds(30))
    );
    decoder.setJwtValidator(validators);
    return decoder;
}"""

FIX_JOSE_REMOTE_KEYS = """// Never trust jku/x5u URLs supplied by the token itself.
// Configure a fixed HTTPS JWKS URI (or a pinned local key registry) and let the
// trusted decoder select only a known kid from that configured key set.
NimbusJwtDecoder decoder = NimbusJwtDecoder
    .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
    .build();"""

FIX_PKCE_S256 = """// Public OAuth2 clients must use PKCE S256, never plain.
authorizationRequest.additionalParameters(params -> {
    params.put("code_challenge", base64Url(sha256(codeVerifier)));
    params.put("code_challenge_method", "S256");
});"""

FIX_CSRF_JWT_COOKIE = """// A browser sends authentication cookies automatically, so keep CSRF enabled.
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
// Alternatively, use an Authorization: Bearer header instead of an auth cookie."""

FIX_IDOR_AUTHZ = """// Scope the lookup to the authenticated owner/tenant instead of a bare ID.
@PreAuthorize("#owner == authentication.name")
public Order getOrder(Long id, String owner) {
    return repository.findByIdAndOwnerId(id, owner).orElseThrow();
}"""

FIX_COVERAGE_CONTROLS = """// Make required controls explicit at the boundary and service layer.
@PreAuthorize("hasAuthority('orders:write') and @orderAccess.canUpdate(#id, authentication)")
public Order updateOrder(Long id, @Valid UpdateOrderRequest request) {
    Order order = repository.findByIdAndTenantId(id, currentTenantId()).orElseThrow();
    Order updated = applyValidatedUpdate(order, request);
    auditService.recordOrderUpdate(authentication.getName(), id);
    return repository.save(updated);
}
// Apply throttling to authentication, token, and password-reset entry points."""

FIX_EMBEDDED_JOSE_KEY = """// Do not trust jwk/x5c key material supplied by the token.
// Resolve only a validated kid against a server-configured, pinned key set.
NimbusJwtDecoder decoder = NimbusJwtDecoder
    .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
    .build();"""

FIX_AUTHZ_ORDER = """// Put specific rules before broad fallbacks.
auth.requestMatchers("/admin/**").hasRole("ADMIN")
    .requestMatchers("/public/**").permitAll()
    .anyRequest().authenticated();"""

FIX_REDIRECT_EXACT = """// Normalize and compare the complete pre-registered redirect URI.
URI requested = URI.create(redirectUri).normalize();
if (!registeredRedirectUris.contains(requested.toString())) {
    throw new IllegalArgumentException("Unregistered redirect_uri");
}"""

FIX_TLS_MODERN = """SSLContext context = SSLContext.getInstance("TLSv1.3");
// Permit only deployment-approved TLS 1.2/1.3 cipher suites and use the default
// trust manager/hostname verifier. Enable certificate revocation checking."""

FIX_TOKEN_PURPOSE = """// Validate token purpose before constructing Authentication.
String type = jwt.getClaimAsString("token_use");
if (!"access".equals(type)) throw new BadCredentialsException("wrong token type");
// For OIDC ID tokens also validate azp when aud contains multiple entries."""

FIX_REFRESH_LIFECYCLE = """// Rotate refresh tokens atomically and revoke the consumed token.
RefreshToken replacement = refreshTokens.rotateAndRevoke(oldRefreshToken);
// On logout, revoke/delete every refresh-token family for the authenticated session."""

FIX_FILTER_CHAINS = """// Put specific filter chains first and keep an explicit fallback chain.
@Bean @Order(1)
SecurityFilterChain api(HttpSecurity http) { return http.securityMatcher("/api/**").build(); }
@Bean @Order(99)
SecurityFilterChain fallback(HttpSecurity http) {
    return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();
}"""

FIX_TENANT_AUTHZ = """// Derive tenant scope from the authenticated principal, never from request data alone.
String tenant = ((TenantPrincipal) authentication.getPrincipal()).tenantId();
return repository.findByIdAndTenantId(id, tenant).orElseThrow();"""

FIX_NESTED_JWT = """// After decrypting a nested JWT, parse and verify the inner signed JWT.
SignedJWT inner = payload.toSignedJWT();
if (inner == null || !inner.verify(trustedVerifier)) throw new BadJOSEException("invalid inner JWS");
// Then validate issuer, audience, type and timestamps."""

FIX_DPOP = """// Validate every DPoP proof component and reject replay.
validateHtmAndHtu(proof, request);
validateIat(proof, Duration.ofMinutes(5));
replayCache.putIfAbsent(proof.getJWTID(), proof.getIssueTime());
validateAth(proof, accessToken);
validateNonceWhenRequired(proof, expectedNonce);"""

FIX_PASSWORD_RESET = """// Generate a random, one-time, short-lived reset token.
byte[] value = new byte[32];
new SecureRandom().nextBytes(value);
resetTokens.save(hash(value), Instant.now().plus(Duration.ofMinutes(15)), false);
// Atomically mark/delete it when the password is changed."""

FIX_METHOD_SEC = """// enable on a config class
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig { }

// secure methods
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long id) { ... }

@Secured("ROLE_USER")
public UserDto getProfile(Long id) { ... }"""

FIX_INMEMORY = """// Do NOT use InMemoryUserDetailsManager in production.
// Production-ready alternative:
@Bean
UserDetailsService userDetailsService(DataSource ds) {
    JdbcUserDetailsManager mgr = new JdbcUserDetailsManager(ds);
    // schema: load spring-security-schema.sql
    return mgr;
}
// Or: a custom UserDetailsService implementation with JPA"""

FIX_EXCEPTION = """http.exceptionHandling(ex -> ex
    .accessDeniedHandler((req, res, exc) -> {
        res.sendError(HttpServletResponse.SC_FORBIDDEN);
        // NO stack trace in the response
    })
    .authenticationEntryPoint((req, res, exc) -> {
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    })
);"""

FIX_CROSS_ORIGIN = """// @CrossOrigin at method/class level does NOT override the global CORS config,
// it adds to it - and can undermine global restrictions.
// Recommendation: remove @CrossOrigin and configure globally instead:
@Bean
CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration cfg = new CorsConfiguration();
    cfg.setAllowedOrigins(List.of("https://app.example.com"));
    cfg.setAllowedMethods(List.of("GET","POST"));
    cfg.setAllowCredentials(false);
    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
    src.registerCorsConfiguration("/**", cfg);
    return src;
}"""

SS_T = r"(?:true|Boolean\s*\.\s*TRUE)"
SS_F = r"(?:false|Boolean\s*\.\s*FALSE)"

SS_RULES: List[Rule] = [
    # ---- CSRF ----
    Rule("SpringSecurityCheck-CSRF-DISABLED", "CSRF protection disabled",
         re.compile(r"\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|"
                    r"\.csrf\s*\(\s*(?:(?:c|csrf)\s*->\s*(?:c|csrf)\s*\.\s*disable\s*\(\s*\)|"
                    r"AbstractHttpConfigurer\s*::\s*disable)\s*\)", re.I),
         "HIGH", [], [],
         "CSRF is completely disabled. REST APIs can be stateless + JWT - then it is "
         "legitimate, but must be documented explicitly.",
         always_report=True, kind="antipattern", fix=FIX_CSRF),
    Rule("SpringSecurityCheck-CSRF-IGNORE-PATH", "CSRF exceptions for broad path patterns",
         re.compile(r"ignoringRequestMatchers\s*\(\s*[\"'][^\"']*\*\*[^\"']*[\"']|"
                    r"ignoringAntMatchers\s*\(\s*[\"'][^\"']*\*\*[^\"']*[\"']", re.I),
         "MEDIUM", [], [],
         "Wildcard exceptions can weaken CSRF protection for more endpoints than intended.",
         always_report=True, kind="antipattern", fix=FIX_CSRF),

    # ---- Authentication / Authorization ----
    Rule("SpringSecurityCheck-PERMIT-ALL-BROAD", "permitAll() on /api/** or /admin/**",
         re.compile(r"requestMatchers\s*\([\"']/(?:api|admin|manage|actuator|internal)"
                    r"[^\"']*[\"']\s*\)\s*\.\s*permitAll\s*\(\s*\)|"
                    r"antMatchers\s*\([\"']/(?:api|admin|manage|actuator|internal)"
                    r"[^\"']*[\"']\s*\)\s*\.\s*permitAll\s*\(\s*\)", re.I),
         "HIGH", [], [],
         "Sensitive paths (API, admin, actuator) are reachable without authentication.",
         always_report=True, kind="antipattern", fix=FIX_AUTH),
    Rule("SpringSecurityCheck-ANY-REQUEST-PERMIT", "anyRequest().permitAll()",
         re.compile(r"anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)", re.I),
         "CRITICAL", [], [],
         "All endpoints are reachable without authentication - effectively no access control.",
         always_report=True, kind="antipattern", fix=FIX_AUTH),
    Rule("SpringSecurityCheck-ANONYMOUS-ACCESS", "AnonymousAuthenticationFilter explicitly enabled",
         re.compile(r"\.anonymous\s*\(\s*\)\s*\.\s*(?:authorities|principal|key)\s*\(|"
                    r"AnonymousAuthenticationFilter\s*\(", re.I),
         "LOW", [], [],
         "Anonymous authentication is configured - check whether it is really needed.",
         always_report=True),
    Rule("SpringSecurityCheck-HTTP-BASIC-PROD", "HTTP Basic without enforced HTTPS",
         re.compile(r"\.httpBasic\s*\(\s*(?:Customizer\.withDefaults\s*\(\s*\)|"
                    r"c\s*->|b\s*->)", re.I),
         "MEDIUM", ["HTTPS_REDIRECT"], [],
         "HTTP Basic sends credentials as Base64-encoded plaintext - use only over TLS.",
         fix=FIX_HEADERS),

    # ---- Session ----
    Rule("SpringSecurityCheck-SESSION-FIXATION", "Session fixation not configured",
         re.compile(r"\.sessionManagement\s*\(", re.I),
         "MEDIUM", [["SESSION_FIXATION"], ["SESSION_STATELESS"]], [],
         "sessionManagement without a sessionFixation() configuration; the default varies by Spring version.",
         fix=FIX_SESSION),
    Rule("SpringSecurityCheck-SESSION-STATELESS-NO-JWT", "STATELESS without JWT/OAuth2 protection",
         re.compile(r"SessionCreationPolicy\s*\.\s*STATELESS", re.I),
         "LOW", [["JWT_VALIDATION"], ["OPAQUE_TOKEN"], ["OAUTH2_SECURED"]], [],
         "Stateless sessions require a secure token mechanism (JWT, OAuth2 opaque).",
         fix=FIX_JWT),

    # ---- Security Headers ----
    Rule("SpringSecurityCheck-HEADERS-DISABLED", "Security header configuration disabled",
         re.compile(r"\.frameOptions\s*\(\s*\w+\s*->\s*\w+\s*\.\s*disable\s*\(\s*\)"
                    r"|\.headers\s*\(\s*(?:\w+\s*->\s*\w+\s*\.\s*)?"
                    r"(?:frameOptions\s*\(\s*\w+\s*->\s*\w+\s*\.\s*disable\s*\(\s*\)\s*\)|"
                    r"disable\s*\(\s*\))\s*\)"
                    r"|\.headers\s*\(\s*\)\s*\.\s*frameOptions\s*\(\s*\)\s*\.\s*disable\s*\(", re.I),
         "MEDIUM", [], [],
         "Security-relevant HTTP headers are disabled.",
         always_report=True, kind="antipattern", fix=FIX_HEADERS),
    Rule("SpringSecurityCheck-NO-CSP", "Content Security Policy not set",
         re.compile(r"http\s*\.\s*headers\s*\(", re.I),
         "LOW", [["CSP"]], [],
         "No CSP header configured - increased XSS risk.",
         fix=FIX_HEADERS),
    Rule("SpringSecurityCheck-NO-HSTS", "HSTS not configured",
         re.compile(r"http\s*\.\s*headers\s*\(", re.I),
         "MEDIUM", [["HSTS"]], [],
         "No Strict-Transport-Security header - SSL stripping possible.",
         fix=FIX_HEADERS),
    Rule("SpringSecurityCheck-NO-HTTPS", "HTTPS not enforced",
         re.compile(r"http\s*\.\s*authorizeHttpRequests\s*\(|"
                    r"http\s*\.\s*authorizeRequests\s*\(", re.I),
         "MEDIUM", [["HTTPS_REDIRECT"]], [],
         "No requiresChannel/requiresSecure - HTTP traffic is not redirected to HTTPS.",
         fix=FIX_HEADERS),

    # ---- CORS ----
    Rule("SpringSecurityCheck-CORS-WILDCARD", "CORS AllowedOrigins = '*'",
         re.compile(r"setAllowedOrigins\s*\(\s*(?:List\.of\s*\(\s*|Arrays\.asList\s*\(\s*)?"
                    r"[\"']\s*\*\s*[\"']\s*\)", re.I),
         "HIGH", [], [],
         "A wildcard origin allows requests from any site. "
         "Together with setAllowCredentials(true) this is a critical flaw.",
         always_report=True, kind="antipattern", fix=FIX_CORS),
    Rule("SpringSecurityCheck-CORS-WILDCARD-CRED", "CORS wildcard origin + credentials",
         re.compile(r"setAllowedOrigins\s*\([^)]*\*[^)]*\).*?setAllowCredentials\s*\(\s*true|"
                    r"setAllowCredentials\s*\(\s*true[^}]{0,200}setAllowedOrigins\s*\([^)]*\*",
                    re.I | re.S),
         "CRITICAL", [], [],
         "Wildcard origin + credentials = CORS bypass possible. Browsers block it, "
         "but some configurations work around the check.",
         always_report=True, kind="antipattern", fix=FIX_CORS),
    Rule("SpringSecurityCheck-CORS-ALL-METHODS", "CORS allows all methods",
         re.compile(r"setAllowedMethods\s*\(\s*(?:List\.of\s*\(\s*|Arrays\.asList\s*\(\s*)?"
                    r"[\"']\s*\*\s*[\"']\s*\)|addAllowedMethod\s*\(\s*[\"']\*[\"']\s*\)", re.I),
         "MEDIUM", [], [],
         "All HTTP methods are allowed - DELETE, PATCH, etc. should be enabled explicitly.",
         always_report=True, kind="antipattern", fix=FIX_CORS),

    # ---- Password Encoding ----
    Rule("SpringSecurityCheck-NOOP-ENCODER", "NoOpPasswordEncoder / plaintext storage",
         re.compile(r"NoOpPasswordEncoder|PasswordEncoder\s*\(\s*\)\s*\{[^}]{0,200}"
                    r"return\s+password|"
                    r"new\s+(?:Md5|MD5)PasswordEncoder|"
                    r"new\s+(?:MessageDigest|SHAPasswordEncoder)\s*\(\s*[\"'](?:MD5|SHA-1)[\"']\s*\)|"
                    r"withDefaultPasswordEncoder\s*\(\s*\)", re.I),
         "CRITICAL", [], [],
         "Passwords are stored in plaintext or with an insecure hash. "
         "Use BCrypt (cost >= 12) or Argon2.",
         always_report=True, kind="antipattern", fix=FIX_NOOPENCODER),
    Rule("SpringSecurityCheck-WEAK-ENCODER", "Outdated/insecure password encoder",
         re.compile(r"new\s+(?:LdapSha|ShaPasswordEncoder|StandardPasswordEncoder|"
                    r"Md4PasswordEncoder)\s*\(", re.I),
         "HIGH", [], [],
         "Outdated encoder without salting or with a weak algorithm.",
         always_report=True, kind="antipattern", fix=FIX_NOOPENCODER),
    Rule("SpringSecurityCheck-BCRYPT-LOW-COST", "BCrypt with a low cost factor",
         re.compile(r"new\s+BCryptPasswordEncoder\s*\(\s*([1-9])\s*\)", re.I),
         "MEDIUM", [], [],
         "BCryptPasswordEncoder with a cost factor < 10 is too fast for passwords. "
         "Recommendation: >= 12.",
         always_report=True, kind="antipattern", fix=FIX_PASSWORD),

    # ---- Actuator ----
    Rule("SpringSecurityCheck-ACTUATOR-EXPOSED", "Actuator endpoints exposed without protection",
         re.compile(r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*[\"']?\s*\*|"
                    r"web\.exposure\.include\s*=\s*\*", re.I),
         "HIGH", [["ACTUATOR_SECURED"]], [],
         "All actuator endpoints are exposed - /actuator/env, /actuator/dump, etc. "
         "contain sensitive information.",
         fix=FIX_ACTUATOR),
    Rule("SpringSecurityCheck-ACTUATOR-SHUTDOWN", "Actuator shutdown endpoint enabled",
         re.compile(r"management\.endpoint\.shutdown\.enabled\s*[=:]\s*true", re.I),
         "CRITICAL", [], [],
         "/actuator/shutdown allows shutting down the application without further protection.",
         always_report=True, kind="antipattern", fix=FIX_ACTUATOR),

    # ---- Remember-Me ----
    Rule("SpringSecurityCheck-REMEMBERME-NO-KEY", "Remember-me without a fixed key",
         re.compile(r"\.rememberMe\s*\(\s*\)(?!\s*\.\s*key\s*\()|"
                    r"\.rememberMe\s*\(\s*r\s*->\s*\)(?!\s*\.\s*key\s*\()", re.I),
         "MEDIUM", [["REMEMBERME_KEY"]], [],
         "Without a key a random key is generated at startup - all tokens become invalid "
         "after a restart. Also, weak keys enable token forgery.",
         fix=FIX_REMEMBERME),
    Rule("SpringSecurityCheck-REMEMBERME-LONG", "Remember-me token validity > 30 days",
         re.compile(r"tokenValiditySeconds\s*\(\s*(\d+)\s*\)", re.I),
         "LOW", [], [],
         "Token lifetimes > 30 days (2,592,000 s) are an extended attack window "
         "for stolen cookies.",
         always_report=True),

    # ---- JWT / Token ----
    Rule("SpringSecurityCheck-JWT-ALG-NONE", "JWT algorithm=none accepted",
         re.compile(r"(?:Algorithm|SignatureAlgorithm)\s*\.\s*NONE|"
                    r"[\"']none[\"']\s*,\s*[\"'](?:HS|RS|ES|PS)\d+[\"']|"
                    r"allowedAlgorithm[^(]*NONE|"
                    r"ignoreExpiration\s*\(\s*" + SS_T, re.I),
         "CRITICAL", [], [],
         "algorithm=none disables signature verification entirely - token forgery is trivial.",
         always_report=True, kind="antipattern", fix=FIX_JWT_FULL),

    Rule("SpringSecurityCheck-JWT-ALG-CONFUSION", "JWT algorithm confusion: HMAC instead of expected RSA",
         re.compile(r"Jwts\s*\.\s*(?:parser|parserBuilder)\s*\(\s*\)"
                    r"(?:(?!\.\s*(?:setSigningKey|verifyWith|requireIssuer))[^;]){0,300}"
                    r"\.\s*(?:setSigningKeyResolver|setSigningKey)\s*\([^)]{0,200}"
                    r"(?:PublicKey|RSAPublicKey|ECPublicKey)", re.I | re.S),
         "HIGH", [], [],
         "RSA/EC key with HMAC validation: an attacker can use the public key as the HMAC secret.",
         always_report=True, kind="antipattern", fix=FIX_JWT_FULL),

    Rule("SpringSecurityCheck-JWT-NO-ISSUER", "JWT issuer validation missing",
         re.compile(r"NimbusJwtDecoder|Jwts\s*\.\s*(?:parser|parserBuilder)\s*\(\s*\)", re.I),
         "MEDIUM", [["JWT_VALIDATION"]], [],
         "Without issuer checking, tokens from other issuers can be accepted. "
         "Set .requireIssuer() / JwtValidators.createDefaultWithIssuer().",
         fix=FIX_JWT_FULL),

    Rule("SpringSecurityCheck-JWT-LONG-EXPIRY", "JWT with no or a very long lifetime",
         re.compile(r"\.expiration\s*\(\s*new\s+Date\s*\(\s*System\s*\.\s*currentTimeMillis\s*\(\s*\)"
                    r"\s*\+\s*(\d+)\s*\*\s*(?:1000\s*\*\s*60\s*\*\s*60\s*\*\s*24|86400000)", re.I),
         "LOW", [], [],
         "A JWT lifetime >= 24h is an extended attack window for stolen tokens. "
         "Prefer short access tokens + refresh-token rotation.",
         always_report=True),

    # ---- OAuth2 ----
    Rule("SpringSecurityCheck-OAUTH2-REDIRECT-WILDCARD", "OAuth2 redirect_uri as a wildcard",
         re.compile(r"registeredRedirectUri\s*\([^)]*\*|"
                    r"redirectUri\s*\(\"[^\"]*\{baseUrl\}[^\"]*\"\)|"
                    r"setRegisteredRedirectUri\s*\([^)]*\*", re.I),
         "HIGH", [], [],
         "A wildcard redirect_uri allows open redirect and authorization-code hijacking.",
         always_report=True, kind="antipattern"),

    Rule("SpringSecurityCheck-OAUTH2-NO-PKCE", "OAuth2 without PKCE for public clients",
         re.compile(r"ClientAuthenticationMethod\s*\.\s*NONE|"
                    r"setClientAuthenticationMethod\s*\([^)]*NONE", re.I),
         "MEDIUM", [], [],
         "Public clients without PKCE are vulnerable to authorization-code interception.",
         always_report=True, kind="antipattern"),

    Rule("OAUTH2-PKCE-PLAIN", "OAuth2 PKCE uses the plain challenge method",
         re.compile(
             r"(?:code[_-]?challenge[_-]?method|CODE_CHALLENGE_METHOD)"
             r"[^;\n]{0,120}?[\x22\x27]plain[\x22\x27]|"
             r"\.codeChallengeMethod\s*\(\s*(?:[\x22\x27]plain[\x22\x27]|"
             r"(?:CodeChallengeMethod|PkceMethod)\s*\.\s*PLAIN)\s*\)|"
             r"(?:CodeChallengeMethod|PkceMethod)\s*\.\s*PLAIN",
             re.I),
         "HIGH", [], [],
         "PKCE plain sends a challenge equivalent to the verifier and does not protect "
         "against authorization-code interception. RFC 7636 clients should use S256.",
         always_report=True, kind="antipattern", fix=FIX_PKCE_S256),

    Rule("OAUTH2-REDIRECT-PREFIX-MATCH", "OAuth2 redirect URI validated by prefix/substring",
         re.compile(
             r"\b(?:redirectUri|redirect_uri|callbackUri|callbackUrl|returnUrl|registeredRedirect\w*)"
             r"\s*\.\s*(?:startsWith|contains)\s*\(",
             re.I),
         "HIGH", [], [],
         "Prefix or substring matching can accept attacker-controlled hosts such as "
         "trusted.example.evil.example. Compare a normalized URI against an exact allowlist.",
         always_report=True, kind="antipattern", fix=FIX_REDIRECT_EXACT),

    Rule("OAUTH2-TOKEN-QUERY-PARAM", "OAuth2 access token placed in a URL query parameter",
         re.compile(
             r"(?:queryParam|addQueryParameter|addParameter)\s*\(\s*"
             r"(?:OAuth2ParameterNames\s*\.\s*ACCESS_TOKEN|[\x22\x27]access_token[\x22\x27])|"
             r"[?&]access_token\s*=|access_token\s*=\s*[\x22\x27]\s*\+",
             re.I),
         "HIGH", [], [],
         "Access tokens in URLs leak through browser history, referrers, proxies, and access logs.",
         always_report=True, kind="antipattern",
         fix="Send the access token in the Authorization: Bearer header, never in the URL."),

    Rule("OAUTH2-CLIENT-SECRET-URL", "OAuth2 client secret placed in a URL query parameter",
         re.compile(
             r"(?:queryParam|addQueryParameter|addParameter)\s*\(\s*"
             r"(?:OAuth2ParameterNames\s*\.\s*CLIENT_SECRET|[\x22\x27]client_secret[\x22\x27])|"
             r"[?&]client_secret\s*=|client_secret\s*=\s*[\x22\x27]\s*\+",
             re.I),
         "CRITICAL", [], [],
         "OAuth2 client secrets in URLs are exposed to logs, monitoring, caches, and referrers.",
         always_report=True, kind="antipattern",
         fix="Use the token endpoint's authenticated POST mechanism; never put client_secret in a URL."),

    Rule("OAUTH2-STATE-MISSING", "OAuth2 authorization flow without CSRF state parameter",
         # Fires when an authorization request builder is called without .state(...)
         re.compile(
             r"OAuth2AuthorizationRequest\s*\.\s*(?:authorizationCode|implicit)\s*\(\s*\)"
             r"(?:(?!\.state\s*\().){0,400}"
             r"\.(?:build|authorizationRequestUri)\s*\(",
             re.I | re.S),
         "HIGH", [], [],
         "An OAuth2 authorization request is built without a state parameter. "
         "The state parameter is required to prevent CSRF attacks against the "
         "authorization callback endpoint.",
         always_report=True, kind="antipattern",
         fix="Set a cryptographically random state on every authorization request: "
             ".state(UUID.randomUUID().toString()) and verify it in the callback."),

    Rule("OAUTH2-TOKEN-LOGGING", "OAuth2 Bearer token written to a logger",
         # Flags logger calls that include a variable or expression matching common
         # token/bearer naming conventions - the token ends up in log files.
         re.compile(
             r"(?:log|logger|LOG|LOGGER)\s*\.\s*(?:debug|info|warn|error|trace)\s*\("
             r"[^;\n]{0,200}"
             r"(?:accessToken|bearerToken|idToken|jwtToken|token|Authorization)",
             re.I),
         "HIGH", [], [],
         "A Bearer or access token is written to a logger. Log files are often "
         "shipped to monitoring systems and retained for extended periods, "
         "turning every log consumer into a token store for attackers.",
         always_report=True, kind="sink",
         fix="Never log token values. Log only non-sensitive metadata (token type, "
             "subject claim, expiry timestamp). If debugging is required, mask the "
             "token: token.substring(0, 8) + \"...\"."),

    Rule("OAUTH2-INTROSPECTION-HTTP", "Token introspection endpoint uses plain HTTP",
         re.compile(
             r"(?:introspectionUri|setIntrospectionUri|introspection-uri)"
             r"\s*[=(]\s*[\x22\x27]http://",
             re.I),
         "HIGH", [], [],
         "The token introspection endpoint is configured over unencrypted HTTP. "
         "An on-path attacker can intercept tokens and responses, "
         "enabling token forgery and information disclosure.",
         always_report=True, kind="antipattern",
         fix="Use HTTPS with a valid certificate for the introspection endpoint. "
             "Set spring.security.oauth2.resourceserver.opaque-token.introspection-uri "
             "to an https:// URL."),

    Rule("OAUTH2-SCOPE-HARDCODED", "OAuth2 scope list hardcoded in source",
         # .scopes("openid","profile","email") or .scope("read") baked into Java/Kotlin
         re.compile(
             r"\.scopes?\s*\(\s*[\x22\x27](?:openid|profile|email|read|write|admin|"
             r"offline.?access|https://)[\x22\x27]",
             re.I),
         "LOW", [], [],
         "OAuth2 scopes are hardcoded in source rather than externalized to configuration. "
         "Scope changes require a code change and redeployment instead of a config update.",
         always_report=True, kind="antipattern",
         fix="Externalize scope configuration to application.properties/yaml: "
             "spring.security.oauth2.client.registration.<id>.scope=openid,profile"),

    Rule("OIDC-NONCE-MISSING", "OIDC ID token nonce not validated",
         # OidcIdTokenValidator or nonce check missing from the token validator chain
         re.compile(
             r"OidcUserService|OidcAuthorizationCodeAuthenticationProvider"
             r"(?:(?!nonce|OidcIdTokenValidator).){0,600}"
             r"\.setJwtDecoderFactory",
             re.I | re.S),
         "MEDIUM", [], [],
         "The OIDC authentication flow does not appear to validate the nonce claim "
         "in the ID token. Without nonce validation, replay attacks against the "
         "authorization code flow are possible.",
         always_report=True, kind="sink",
         fix="Ensure OidcIdTokenValidator is included in the token validator chain "
             "and that the nonce is generated per-request and stored in the session."),

    # These four rules are emitted by method/module-aware analyzers below.  The
    # impossible pattern keeps them in --list-rules and include/exclude filters
    # without creating a second regex-only finding.
    Rule("JWT-JKU-INJECTION", "JWT jku header controls remote key loading",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "An attacker-controlled jku header reaches a URL/JWKS loader.",
         always_report=True, kind="antipattern", fix=FIX_JOSE_REMOTE_KEYS),
    Rule("JWT-X5U-INJECTION", "JWT x5u header controls certificate loading",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "An attacker-controlled x5u header reaches a URL/certificate loader.",
         always_report=True, kind="antipattern", fix=FIX_JOSE_REMOTE_KEYS),
    Rule("SpringSecurityCheck-CSRF-DISABLED-JWT-COOKIE",
         "CSRF disabled while JWT authentication uses cookies",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "Cookie-based authentication is sent automatically by browsers; disabling CSRF "
         "therefore enables cross-site authenticated requests.",
         always_report=True, kind="antipattern", fix=FIX_CSRF_JWT_COOKIE),
    Rule("AUTHZ-IDOR-DATAFLOW", "Request identifier reaches repository without visible authorization",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A request path identifier reaches a repository ID lookup without visible owner, "
         "tenant, principal, or method-security enforcement.",
         always_report=True, kind="antipattern", fix=FIX_IDOR_AUTHZ),
    Rule("JWT-EMBEDDED-JWK-TRUST", "JWT embedded jwk header trusted as verification key",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "Attacker-controlled jwk key material reaches signature verification.",
         always_report=True, kind="antipattern", fix=FIX_EMBEDDED_JOSE_KEY),
    Rule("JWT-X5C-TRUST", "JWT embedded x5c certificate chain trusted without a pinned root",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "Attacker-controlled x5c certificate material reaches signature verification.",
         always_report=True, kind="antipattern", fix=FIX_EMBEDDED_JOSE_KEY),
    Rule("AUTHZ-MATCHER-ORDER", "Broad permitAll matcher precedes a restrictive matcher",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "Spring Security uses first-match-wins semantics; an earlier broad permitAll can shadow a later rule.",
         always_report=True, kind="antipattern", fix=FIX_AUTHZ_ORDER),
    Rule("AUTHZ-PREAUTHORIZE-WITHOUT-METHODSECURITY",
         "@PreAuthorize used without enabled method security",
         re.compile(r"(?!)"), "HIGH", [], [],
         "@PreAuthorize/@PostAuthorize annotations are ineffective unless method security is enabled.",
         always_report=True, kind="antipattern", fix=FIX_METHOD_SEC),
    Rule("OIDC-IDTOKEN-AS-ACCESS-TOKEN", "OIDC ID token used as an API Bearer token",
         re.compile(r"(?!)"), "HIGH", [], [],
         "An ID token authenticates a client session; it must not be used as an API access token.",
         always_report=True, kind="antipattern", fix=FIX_TOKEN_PURPOSE),
    Rule("OIDC-AZP-NOT-VALIDATED", "OIDC authorized party claim not validated",
         re.compile(r"(?!)"), "MEDIUM", [], [],
         "Custom OIDC audience validation does not visibly validate azp for multi-audience ID tokens.",
         always_report=True, kind="antipattern", fix=FIX_TOKEN_PURPOSE),
    Rule("JWT-TOKEN-TYPE-CONFUSION", "JWT accepted for authentication without purpose validation",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A parsed JWT is converted to Authentication without checking typ/token_use or equivalent purpose.",
         always_report=True, kind="antipattern", fix=FIX_TOKEN_PURPOSE),
    Rule("REFRESH-TOKEN-NO-ROTATION", "Refresh-token flow without visible rotation",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A refresh flow issues a new access token without visibly rotating and revoking the refresh token.",
         always_report=True, kind="antipattern", fix=FIX_REFRESH_LIFECYCLE),
    Rule("REFRESH-TOKEN-NO-REVOKE-ON-LOGOUT", "Logout does not visibly revoke refresh tokens",
         re.compile(r"(?!)"), "HIGH", [], [],
         "Refresh tokens appear in the module, but logout has no visible revocation/deletion step.",
         always_report=True, kind="antipattern", fix=FIX_REFRESH_LIFECYCLE),
    Rule("AUTHZ-SECURITYFILTERCHAIN-ORDER", "SecurityFilterChain order shadows a specific chain",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "An earlier broad SecurityFilterChain can consume requests before a later specific chain.",
         always_report=True, kind="antipattern", fix=FIX_FILTER_CHAINS),
    Rule("AUTHZ-FILTERCHAIN-NO-FALLBACK", "Scoped SecurityFilterChain set has no fallback chain",
         re.compile(r"(?!)"), "HIGH", [], [],
         "User-defined scoped filter chains have no catch-all fallback for unmatched requests.",
         always_report=True, kind="antipattern", fix=FIX_FILTER_CHAINS),
    Rule("AUTHZ-TENANT-DATAFLOW", "Request tenant scope reaches or is dropped before repository access",
         re.compile(r"(?!)"), "HIGH", [], [],
         "Request-controlled tenant context crosses service calls without binding to the authenticated tenant.",
         always_report=True, kind="antipattern", fix=FIX_TENANT_AUTHZ),
    Rule("SECURITY-CONTROL-COVERAGE-GAP", "Required security-control coverage is missing or unresolved",
         re.compile(r"(?!)"), "MEDIUM", [], [],
         "At least one required security control is missing or unresolved on an externally reachable processing path.",
         always_report=True, kind="antipattern", fix=FIX_COVERAGE_CONTROLS),
    Rule("AUTHZ-SENSITIVE-SINK-UNCOVERED", "Sensitive processing path lacks authorization",
         re.compile(r"(?!)"), "HIGH", [], [],
         "An externally reachable path can reach a sensitive repository or state-changing operation "
         "without a proven authorization decision.",
         always_report=True, kind="antipattern", fix=FIX_COVERAGE_CONTROLS),
    Rule("AUTHZ-PARTIALLY-PROTECTED-SERVICE", "Service is reachable from mixed authorization contexts",
         re.compile(r"(?!)"), "HIGH", [], [],
         "The same service method is reachable from both authorized and unauthorized entry points.",
         always_report=True, kind="antipattern", fix=FIX_COVERAGE_CONTROLS),
    Rule("TENANT-CONTEXT-LOST", "Tenant context is not bound on a sensitive path",
         re.compile(r"(?!)"), "HIGH", [], [],
         "Tenant-scoped input reaches sensitive processing without a proven authenticated-tenant binding.",
         always_report=True, kind="antipattern", fix=FIX_TENANT_AUTHZ),
    Rule("VALIDATION-COVERAGE-GAP", "External input reaches processing without proven validation",
         re.compile(r"(?!)"), "MEDIUM", [], [],
         "Request or message payload data reaches application processing without visible validation.",
         always_report=True, kind="antipattern", fix=FIX_COVERAGE_CONTROLS),
    Rule("RATE-LIMIT-COVERAGE-GAP", "Abuse-sensitive entry point lacks throttling",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A login, token, MFA, or password-reset entry point has no visible rate limit or lockout control.",
         always_report=True, kind="antipattern", fix=FIX_COVERAGE_CONTROLS),
    Rule("AUDIT-COVERAGE-GAP", "Sensitive state change lacks security audit evidence",
         re.compile(r"(?!)"), "MEDIUM", [], [],
         "A sensitive state-changing path has no visible structured security audit event.",
         always_report=True, kind="antipattern", fix=FIX_COVERAGE_CONTROLS),
    Rule("OAUTH2-ISSUER-MIXUP", "Multi-issuer OAuth callback lacks issuer binding",
         re.compile(r"(?!)"), "HIGH", [], [],
         "Multiple authorization issuers are configured without visible request-to-callback issuer binding.",
         always_report=True, kind="antipattern", fix=FIX_TOKEN_PURPOSE),
    Rule("JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED", "Nested JWT inner signature not validated",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "A decrypted nested JWT is consumed without visible inner JWS signature verification.",
         always_report=True, kind="antipattern", fix=FIX_NESTED_JWT),
    Rule("JWE-ZIP-ENABLED", "JWE compression enabled before encryption",
         re.compile(r"(?:setCompressionAlgorithm|compressionAlgorithm)\s*\([^;\n]{0,120}"
                    r"(?:CompressionAlgorithmIdentifiers\s*\.\s*DEF|[\x22\x27]DEF[\x22\x27])|"
                    r"customParam\s*\(\s*[\x22\x27]zip[\x22\x27]\s*,\s*[\x22\x27]DEF[\x22\x27]\s*\)|"
                    r"[\x22\x27]zip[\x22\x27]\s*[,=:]\s*[\x22\x27]DEF[\x22\x27]", re.I),
         "MEDIUM", [], [],
         "Compression before encryption can expose plaintext-length relationships and should be avoided.",
         always_report=True, kind="antipattern",
         fix="Do not set the JWE zip header; encrypt the uncompressed payload."),
    Rule("JWT-KEY-ISSUER-NOT-BOUND", "JWT verification key selection not bound to issuer",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A custom kid/key resolver has no visible binding between trusted issuer and key set.",
         always_report=True, kind="antipattern", fix=FIX_EMBEDDED_JOSE_KEY),
    Rule("JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES", "Same signing key used for multiple JWT types",
         re.compile(r"(?!)"), "HIGH", [], [],
         "Access, ID, and refresh tokens share signing material, weakening token-type separation.",
         always_report=True, kind="antipattern", fix=FIX_TOKEN_PURPOSE),
    Rule("CERT-PRIVATE-KEY-COMMITTED", "Private key material committed in source",
         re.compile(r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH)\s+)?PRIVATE KEY-----", re.I),
         "CRITICAL", [], [],
         "Private key material is present in a scanned source/configuration file.",
         always_report=True, kind="antipattern",
         fix="Remove and rotate the key immediately; load replacement material from a secret manager."),
    Rule("CERT-EMPTY-PKCS12-PASSWORD", "PKCS12 keystore loaded with an empty password",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A PKCS12 keystore appears to be loaded or written with null/empty password protection.",
         always_report=True, kind="antipattern",
         fix="Protect PKCS12 files with a strong runtime secret and restrict filesystem permissions."),
    Rule("PASSWORD-RESET-NO-EXPIRY", "Password-reset token has no visible expiry",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A password-reset token is generated or stored without a visible expiry/TTL.",
         always_report=True, kind="antipattern", fix=FIX_PASSWORD_RESET),
    Rule("PASSWORD-RESET-TOKEN-REUSE", "Password-reset token is not consumed atomically",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A password-reset flow changes a password without deleting or marking the token used.",
         always_report=True, kind="antipattern", fix=FIX_PASSWORD_RESET),
    Rule("PASSWORD-RESET-PREDICTABLE-TOKEN", "Predictable password-reset token generation",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "Password-reset token material comes from a predictable timestamp or non-cryptographic RNG.",
         always_report=True, kind="antipattern", fix=FIX_PASSWORD_RESET),
    Rule("AUTH-LOGIN-NO-RATE-LIMIT", "Login endpoint has no visible throttling or lockout",
         re.compile(r"(?!)"), "MEDIUM", [], [],
         "A custom login/authentication endpoint has no visible rate limit, delay, or account lockout.",
         always_report=True, kind="antipattern",
         fix="Apply per-account and per-origin throttling and temporary lockout outside credential comparison."),
    Rule("MFA-FAIL-OPEN", "MFA verification fails open on errors",
         re.compile(r"(?!)"), "CRITICAL", [], [],
         "An exception or unavailable MFA service appears to allow authentication to continue.",
         always_report=True, kind="antipattern",
         fix="Fail closed: deny authentication whenever MFA verification cannot complete successfully."),
    Rule("DPOP-JTI-NOT-REPLAY-CHECKED", "DPoP jti not checked for replay",
         re.compile(r"(?!)"), "HIGH", [], [],
         "DPoP validation lacks a visible jti replay cache/uniqueness check.",
         always_report=True, kind="antipattern", fix=FIX_DPOP),
    Rule("DPOP-HTM-HTU-NOT-VALIDATED", "DPoP HTTP method/URI not fully validated",
         re.compile(r"(?!)"), "HIGH", [], [],
         "DPoP proof validation does not visibly bind both htm and htu to the request.",
         always_report=True, kind="antipattern", fix=FIX_DPOP),
    Rule("DPOP-IAT-WINDOW-TOO-LARGE", "DPoP proof acceptance window exceeds five minutes",
         re.compile(r"(?!)"), "MEDIUM", [], [],
         "The configured DPoP iat acceptance window is larger than five minutes.",
         always_report=True, kind="antipattern", fix=FIX_DPOP),
    Rule("DPOP-ATH-NOT-VALIDATED", "DPoP access-token hash not validated",
         re.compile(r"(?!)"), "HIGH", [], [],
         "A DPoP-bound access-token flow lacks visible ath validation.",
         always_report=True, kind="antipattern", fix=FIX_DPOP),
    Rule("DPOP-NONCE-NOT-VALIDATED", "Configured DPoP nonce not validated",
         re.compile(r"(?!)"), "HIGH", [], [],
         "DPoP nonce support is configured or emitted without visible proof nonce validation.",
         always_report=True, kind="antipattern", fix=FIX_DPOP),

    # ---- Method Security ----
    Rule("SpringSecurityCheck-NO-METHOD-SECURITY", "@EnableMethodSecurity missing",
         re.compile(r"@EnableWebSecurity", re.I),
         "LOW", [["METHOD_SECURITY_ENABLED"]], [],
         "@EnableMethodSecurity not found - fine-grained method security "
         "(@PreAuthorize, @Secured) is not active.",
         fix=FIX_METHOD_SEC),

    Rule("SpringSecurityCheck-CROSS-ORIGIN-BROAD", "@CrossOrigin without explicit origins",
         re.compile(r"@CrossOrigin\s*(?:\(\s*\)|\(\s*origins\s*=\s*\"\*\"\)|"
                    r"\((?![^)]*\borigins\s*=)[^)]*\ballowCredentials\s*=\s*(?:true|\"true\")\s*[^)]*\))", re.I),
         "HIGH", [], [],
         "@CrossOrigin without explicit origins allows requests from any site. "
         "Use a global CORS configuration instead of the annotation.",
         always_report=True, kind="antipattern", fix=FIX_CROSS_ORIGIN),

    Rule("SpringSecurityCheck-IGNORE-REQUEST-MATCHER", "WebSecurityCustomizer ignores too many paths",
         re.compile(r"\.ignoring\s*\(\s*\)\s*\.\s*(?:requestMatchers|antMatchers)\s*\("
                    r'[^)]*["\'/][^)]*', re.I),
         "HIGH", [], [],
         "ignoringRequestMatchers() turns off the security filters entirely - "
         "CSRF, authentication and header protection no longer apply.",
         always_report=True, kind="antipattern"),

    # ---- UserDetails / Authentication ----
    Rule("SpringSecurityCheck-INMEMORY-USERS", "InMemoryUserDetailsManager in production code",
         re.compile(r"new\s+InMemoryUserDetailsManager\s*\(|"
                    r"User\s*\.\s*withDefaultPasswordEncoder\s*\(", re.I),
         "HIGH", [], [],
         "InMemoryUserDetailsManager stores credentials in the heap - no audit, no locking, "
         "no persistence. Suitable for tests only.",
         always_report=True, kind="antipattern", fix=FIX_INMEMORY),

    Rule("SpringSecurityCheck-NULL-USERDETAILS", "loadUserByUsername returns null",
         re.compile(r"loadUserByUsername[^{]{0,100}\{[^}]{0,500}return\s+null", re.I | re.S),
         "MEDIUM", [], [],
         "Per the Spring contract, loadUserByUsername must throw UsernameNotFoundException, "
         "never return null - otherwise it leads to an NPE or auth bypass.",
         always_report=True, kind="antipattern"),

    Rule("SpringSecurityCheck-EMPTY-PASSWORD-AUTH", "AuthenticationProvider allows empty passwords",
         re.compile(r"setHideUserNotFoundExceptions\s*\(\s*" + SS_F + r"\s*\)|"
                    r"setPasswordEncoder\s*\(\s*NoOpPasswordEncoder", re.I),
         "HIGH", [], [],
         "setHideUserNotFoundExceptions(false) reveals whether a username exists (user "
         "enumeration). NoOpPasswordEncoder as the provider encoder: plaintext comparison.",
         always_report=True, kind="antipattern", fix=FIX_PASSWORD),

    # ---- Exception Handling / Info-Leak ----
    Rule("SpringSecurityCheck-NO-ACCESS-DENIED-HANDLER", "No AccessDeniedHandler configured",
         re.compile(r"http\s*\.\s*exceptionHandling\s*\(", re.I),
         "LOW", [["AUTH_REQUIRED"]], [],
         "Without an AccessDeniedHandler, Spring Security sends the default error with a "
         "stack trace. Register a custom handler.",
         fix=FIX_EXCEPTION),

    Rule("SpringSecurityCheck-ANTI-STACKTRACE", "server.error.include-stacktrace=always",
         re.compile(r"server\.error\.include-(?:stacktrace|message)\s*[=:]\s*always", re.I),
         "MEDIUM", [], [],
         "Stack traces in the HTTP response leak implementation details.",
         always_report=True, kind="antipattern"),

    # ---- SAML ----
    Rule("SpringSecurityCheck-SAML-NO-SIGN", "SAML assertion signature disabled",
         re.compile(r"wantAssertionsSigned\s*\(\s*" + SS_F + r"\s*\)|"
                    r"setWantAssertionsSigned\s*\(\s*" + SS_F + r"\s*\)|"
                    r"authnRequestsSigned\s*\(\s*" + SS_F + r"\s*\)", re.I),
         "CRITICAL", [], [],
         "SAML assertions without signature verification enable SAML response forgery and auth bypass.",
         always_report=True, kind="antipattern"),

    # ---- SecurityContext ----
    Rule("SpringSecurityCheck-NO-CTX-CLEAR", "SecurityContextHolder.clearContext() missing in logout",
         re.compile(r"\.logout\s*\([^)]*\)", re.I),
         "LOW", [["AUTH_REQUIRED"]], [],
         "Check whether the logout handler calls SecurityContextHolder.clearContext() "
         "and invalidates the session.",
         fix=FIX_AUTH),

    Rule("SpringSecurityCheck-NO-FAILURE-HANDLER", "No AuthenticationFailureHandler",
         re.compile(r"\.formLogin\s*\(", re.I),
         "LOW", [["AUTH_REQUIRED"]], [],
         "Without a custom FailureHandler, Spring Security passes the failure reason in the "
         "redirect (e.g. ?error=BadCredentials) - potential information disclosure.",
         fix=FIX_AUTH),

    # ---- Anti-patterns: explicitly insecure configurations ----
    Rule("TLS-OLD-PROTOCOL", "Obsolete SSL/TLS protocol explicitly enabled",
         re.compile(
             r"SSLContext\s*\.\s*getInstance\s*\(\s*[\x22\x27](?:SSLv?2|SSLv3|TLSv1(?:\.0|\.1)?)[\x22\x27]\s*\)|"
             r"(?:setEnabledProtocols|setProtocols|protocols?)\s*\([^;\n]{0,200}"
             r"[\x22\x27](?:SSLv?2|SSLv3|TLSv1(?:\.0|\.1)?)[\x22\x27]",
             re.I),
         "HIGH", [], [],
         "SSLv2/SSLv3/TLS 1.0/TLS 1.1 are obsolete and must not be explicitly enabled.",
         always_report=True, kind="antipattern", fix=FIX_TLS_MODERN),
    Rule("TLS-WEAK-CIPHER", "Weak TLS cipher suite explicitly enabled",
         re.compile(
             r"[\x22\x27](?:SSL|TLS)_[A-Z0-9_]*(?:RC4|3DES|DES_EDE|_DES_|NULL|EXPORT|ANON|anon)[A-Z0-9_]*[\x22\x27]",
             re.I),
         "HIGH", [], [],
         "RC4, DES/3DES, NULL, EXPORT, and anonymous TLS suites do not provide modern transport security.",
         always_report=True, kind="antipattern", fix=FIX_TLS_MODERN),
    Rule("TLS-TRUST-SELF-SIGNED", "Self-signed certificates trusted without pinning",
         re.compile(r"\bTrustSelfSignedStrategy\b|"
                    r"loadTrustMaterial\s*\([^;\n]{0,200}(?:isSelfSigned|selfSigned)", re.I),
         "HIGH", [], [],
         "Trusting arbitrary self-signed certificates removes public/private CA identity guarantees.",
         always_report=True, kind="antipattern", fix=FIX_TLS_MODERN),
    Rule("TLS-REVOCATION-DISABLED", "Certificate revocation checking explicitly disabled",
         re.compile(r"setRevocationEnabled\s*\(\s*false\s*\)|"
                    r"(?:com\.sun\.net\.ssl\.checkRevocation|ocsp\.enable)\s*[\x22\x27]?\s*[,=:]\s*[\x22\x27]?false", re.I),
         "HIGH", [], [],
         "Certificate revocation checking is explicitly disabled; revoked credentials may remain trusted.",
         always_report=True, kind="antipattern", fix=FIX_TLS_MODERN),
    Rule("TLS-MTLS-WANT-INSTEAD-OF-NEED", "mTLS client certificate is optional instead of required",
         re.compile(r"setWantClientAuth\s*\(\s*true\s*\)|"
                    r"setNeedClientAuth\s*\(\s*false\s*\)|"
                    r"ClientAuth\s*\.\s*(?:OPTIONAL|WANT)\b", re.I),
         "HIGH", [], [],
         "Optional client authentication permits connections without a client certificate.",
         always_report=True, kind="antipattern",
         fix="For mTLS-only endpoints require client certificates with setNeedClientAuth(true) or ClientAuth.REQUIRE."),
    Rule("TLS-KEYSTORE-PASSWORD-HARDCODED", "Hardcoded TLS keystore password",
         re.compile(
             r"(?:keyStorePassword|keystorePassword|setKeyStorePassword)\s*(?:=|\()\s*"
             r"[\x22\x27][^\x22\x27${}]{3,}[\x22\x27]|"
             r"[\x22\x27]javax\.net\.ssl\.keyStorePassword[\x22\x27]\s*,\s*"
             r"[\x22\x27][^\x22\x27${}]{3,}[\x22\x27]",
             re.I),
         "HIGH", [], [],
         "A keystore password is embedded in source code and cannot be rotated safely.",
         always_report=True, kind="antipattern",
         fix="Load the keystore password from a secret manager or protected runtime secret."),
    Rule("TLS-TRUSTSTORE-PASSWORD-HARDCODED", "Hardcoded TLS truststore password",
         re.compile(
             r"(?:trustStorePassword|truststorePassword|setTrustStorePassword)\s*(?:=|\()\s*"
             r"[\x22\x27][^\x22\x27${}]{3,}[\x22\x27]|"
             r"[\x22\x27]javax\.net\.ssl\.trustStorePassword[\x22\x27]\s*,\s*"
             r"[\x22\x27][^\x22\x27${}]{3,}[\x22\x27]",
             re.I),
         "MEDIUM", [], [],
         "A truststore password is embedded in source code and should be externalized.",
         always_report=True, kind="antipattern",
         fix="Load the truststore password from a secret manager or protected runtime secret."),
    Rule("SpringSecurityCheck-ANTI-TRUST-ALL-CERTS", "SSL certificate validation disabled",
         re.compile(r"setSSLSocketFactory\s*\(.*?TrustAll|"
                    r"TrustAllStrategy|TRUST_ALL_HOSTNAME|"
                    r"NoopHostnameVerifier|AllowAllHostname|"
                    r"setHostnameVerifier\s*\(\s*(?:SSLConnectionSocketFactory\s*\.\s*)?ALLOW_ALL|"
                    r"X509TrustManager[^{]{0,100}checkServerTrusted[^{]{0,100}\{\s*\}", re.I | re.S),
         "CRITICAL", [], [],
         "TLS/SSL certificate verification disabled - man-in-the-middle is trivially possible.",
         always_report=True, kind="antipattern"),
    Rule("SpringSecurityCheck-ANTI-DISABLE-SEC", "@EnableWebSecurity without HTTPS/header hardening",
         re.compile(r"@EnableWebSecurity\b", re.I),
         "INFO", [["HTTPS_REDIRECT"], ["HSTS"], ["CSP"]], [],
         "Spring Security enabled - check whether HTTPS, HSTS and CSP are configured.",
         fix=FIX_HEADERS),
    Rule("SpringSecurityCheck-HARDCODED-SECRET", "Hardcoded JWT secret / API key / password",
         re.compile(r"(?:jwt(?:Secret|Key|SignKey)|secret|password|apiKey|api_key)"
                    r"\s*[=:]\s*[\"'][A-Za-z0-9+/=_\-]{3,}[\"']", re.I),
         "HIGH", [], [],
         "Credentials in source code: rotate immediately and move to a secrets store "
         "(Vault, K8s secrets, env var). Even a short/trivial-looking value (e.g. \"123456\") "
         "is a real hardcoded secret and often the easiest one to brute-force.",
         always_report=True, kind="antipattern"),
    Rule("SpringSecurityCheck-HARDCODED-BCRYPT-COST-0", "BCryptPasswordEncoder(0) disables hashing",
         re.compile(r"new\s+BCryptPasswordEncoder\s*\(\s*0\s*\)", re.I),
         "CRITICAL", [], [],
         "A cost factor of 0 makes BCrypt trivially reversible.",
         always_report=True, kind="antipattern", fix=FIX_PASSWORD),
]

RULES.extend(SS_RULES)
RULE_BY_ID.update({r.rid: r for r in SS_RULES})

# Also check properties files (application.properties / .yml)
PROP_RULES: List[Tuple[str, re.Pattern, str, str, str]] = [
    # (rule_id, pattern, severity, note, fix)
    ("SpringSecurityCheck-PROP-DEBUG", re.compile(r"spring\.security\.debug\s*[=:]\s*true", re.I),
     "MEDIUM", "Spring Security debug logging enabled in production - leaks internal details.", ""),
    ("SpringSecurityCheck-PROP-ACTUATOR-ALL", re.compile(r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*\*", re.I),
     "HIGH", "All actuator endpoints exposed.", FIX_ACTUATOR),
    ("SpringSecurityCheck-PROP-SHUTDOWN", re.compile(r"management\.endpoint\.shutdown\.enabled\s*[=:]\s*true", re.I),
     "CRITICAL", "Shutdown actuator enabled.", FIX_ACTUATOR),
    ("SpringSecurityCheck-PROP-DEVTOOLS", re.compile(
        r"spring\.devtools\.(?:restart|remote\.restart)\.enabled\s*[=:]\s*true", re.I),
     "MEDIUM", "Spring DevTools restart support enabled; verify it is disabled in production.", ""),
    ("SpringSecurityCheck-PROP-WEAK-JWT-SECRET", re.compile(r"(?:jwt\.secret|jwt-secret|app\.secret)\s*[=:]\s*\S{1,20}$", re.I | re.M),
     "HIGH", "JWT secret shorter than 20 characters - too weak for HMAC signatures.", FIX_JWT),
    ("SpringSecurityCheck-PROP-PLAIN-PASSWORD", re.compile(r"(?:spring\.datasource\.password|"
                                           r"spring\.security\.user\.password)\s*[=:]\s*"
                                           r"(?!\s*(?:\$\{|#\{|ENC\(|\s*$))\S+", re.I),
     "LOW", "Database password in a configuration file - better read it from a secrets store. "
            "Placeholders such as ${DB_PASSWORD} are not flagged.", ""),
    ("SpringSecurityCheck-PROP-SSL-DISABLED", re.compile(r"server\.ssl\.enabled\s*[=:]\s*false", re.I),
     "HIGH", "TLS/HTTPS explicitly disabled - all data is transmitted unencrypted.", ""),
    ("TLS-OLD-PROTOCOL", re.compile(
        r"(?:server\.ssl\.(?:enabled-)?protocols|https\.protocols|jdk\.tls\.client\.protocols)"
        r"\s*[=:][^\n]*(?:SSLv?2|SSLv3|TLSv1(?:\.0|\.1)?)(?:[,\s]|$)", re.I),
     "HIGH", "Obsolete SSL/TLS protocol explicitly enabled in configuration.", FIX_TLS_MODERN),
    ("TLS-WEAK-CIPHER", re.compile(
        r"(?:server\.ssl\.ciphers|https\.cipherSuites)\s*[=:][^\n]*"
        r"(?:RC4|3DES|DES_EDE|_DES_|NULL|EXPORT|anon)", re.I),
     "HIGH", "Weak TLS cipher suite explicitly enabled in configuration.", FIX_TLS_MODERN),
    ("TLS-REVOCATION-DISABLED", re.compile(
        r"(?:com\.sun\.net\.ssl\.checkRevocation|ocsp\.enable)\s*[=:]\s*false", re.I),
     "HIGH", "Certificate revocation checking explicitly disabled.", FIX_TLS_MODERN),
    ("TLS-MTLS-WANT-INSTEAD-OF-NEED", re.compile(
        r"server\.ssl\.client-auth\s*[=:]\s*(?:want|optional)", re.I),
     "HIGH", "Client certificates are optional although mTLS appears configured.",
     "Use server.ssl.client-auth=need for mTLS-only endpoints."),
    ("TLS-KEYSTORE-PASSWORD-HARDCODED", re.compile(
        r"(?:server\.ssl\.key-store-password|javax\.net\.ssl\.keyStorePassword)\s*[=:]\s*"
        r"(?!\s*(?:\$\{|#\{|ENC\(|\s*$))\S+", re.I),
     "HIGH", "Hardcoded TLS keystore password in configuration.",
     "Use a runtime secret placeholder or secret manager."),
    ("TLS-TRUSTSTORE-PASSWORD-HARDCODED", re.compile(
        r"(?:server\.ssl\.trust-store-password|javax\.net\.ssl\.trustStorePassword)\s*[=:]\s*"
        r"(?!\s*(?:\$\{|#\{|ENC\(|\s*$))\S+", re.I),
     "MEDIUM", "Hardcoded TLS truststore password in configuration.",
     "Use a runtime secret placeholder or secret manager."),
    ("CERT-PRIVATE-KEY-COMMITTED", re.compile(
        r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH)\s+)?PRIVATE KEY-----", re.I),
     "CRITICAL", "Private key material embedded in application configuration.",
     "Remove and rotate the key; load it from a secret manager."),
    ("SpringSecurityCheck-PROP-MGMT-SEC-OFF", re.compile(r"management\.security\.enabled\s*[=:]\s*false", re.I),
     "CRITICAL", "Spring Boot 1.x: actuator security completely turned off.", FIX_ACTUATOR),
    ("SpringSecurityCheck-PROP-STACKTRACE", re.compile(r"server\.error\.include-(?:stacktrace|message)\s*[=:]\s*always", re.I),
     "MEDIUM", "Stack traces/error messages in HTTP responses leak implementation details.", ""),
    ("SpringSecurityCheck-PROP-DB-URL-CREDS", re.compile(r"spring\.datasource\.url\s*[=:][^\n]*(?:password=|user=)[^\n]+", re.I),
     "HIGH", "Credentials embedded directly in the JDBC URL - rotation is very difficult.", ""),
    ("SpringSecurityCheck-PROP-NO-JWT-URI", re.compile(r"spring\.security\.oauth2\.resourceserver\.jwt\.public-key-location"
                                       r"|spring\.security\.oauth2\.resourceserver\.jwt\s*:", re.I),
     "LOW", "JWT configuration found - check whether jwk-set-uri is set and HTTPS is used.", ""),
    ("SpringSecurityCheck-PROP-H2-CONSOLE", re.compile(r"spring\.h2\.console\.enabled\s*[=:]\s*true", re.I),
     "HIGH", "H2 web console enabled - direct database access without app auth if misconfigured.", ""),
    ("SpringSecurityCheck-PROP-TRACE", re.compile(r"management\.endpoint\.httptrace\.enabled\s*[=:]\s*true|"
                                  r"management\.endpoint\.logfile\.enabled\s*[=:]\s*true", re.I),
     "MEDIUM", "HTTP trace/logfile endpoint enabled - could leak sensitive headers/tokens.", ""),
]
PROP_EXTS = (".properties", ".yml", ".yaml")

RULE_BY_ID.update({r.rid: r for r in RULES})


# --------------------------------------------------------------------------
# Dependency check
# --------------------------------------------------------------------------


@dataclass
class DepRule:
    artifact: str
    fixed: Optional[str]
    severity: str
    note: str
    groups: Sequence[str] = ()


DEP_RULES: List[DepRule] = [
    DepRule('dom4j', '2.1.3', 'HIGH', 'Legacy minimum-version review hint (2.1.3); not a verified CVE range or universal safe version.'),
    DepRule('xstream', '1.4.21', 'CRITICAL', 'Legacy minimum-version review hint (1.4.21); not a verified CVE range or universal safe version.'),
    DepRule('jdom', '2.0.6.1', 'HIGH', 'Legacy minimum-version review hint (2.0.6.1); not a verified CVE range or universal safe version.'),
    DepRule('jdom2', '2.0.6.1', 'HIGH', 'Legacy minimum-version review hint (2.0.6.1); not a verified CVE range or universal safe version.'),
    DepRule('woodstox-core', '6.4.0', 'MEDIUM', 'Legacy minimum-version review hint (6.4.0); not a verified CVE range or universal safe version.'),
    DepRule('xercesImpl', None, 'MEDIUM', 'Dependency configuration review; package presence alone does not prove a vulnerability.'),
    DepRule('commons-digester', None, 'LOW', 'Dependency configuration review; package presence alone does not prove a vulnerability.'),
    DepRule('spring-oxm', None, 'LOW', 'Dependency configuration review; package presence alone does not prove a vulnerability.'),
    DepRule('castor-xml', None, 'MEDIUM', 'Dependency configuration review; package presence alone does not prove a vulnerability.'),
    # Spring Security / Boot
    DepRule('spring-security-core', '5.8.0', 'HIGH', 'Legacy minimum-version review hint (5.8.0); not a verified CVE range or universal safe version.'),
    DepRule('spring-security-web', '5.8.0', 'HIGH', 'Legacy minimum-version review hint (5.8.0); not a verified CVE range or universal safe version.'),
    DepRule('spring-security-config', '5.8.0', 'HIGH', 'Legacy minimum-version review hint (5.8.0); not a verified CVE range or universal safe version.'),
    DepRule('spring-boot-starter-security', '3.0.0', 'MEDIUM', 'Legacy minimum-version review hint (3.0.0); not a verified CVE range or universal safe version.'),
    DepRule('spring-boot-autoconfigure', '2.7.0', 'MEDIUM', 'Legacy minimum-version review hint (2.7.0); not a verified CVE range or universal safe version.'),
    DepRule('spring-webmvc', '5.3.20', 'MEDIUM', 'Legacy minimum-version review hint (5.3.20); not a verified CVE range or universal safe version.'),
    DepRule('nimbus-jose-jwt', '9.31', 'HIGH', 'Legacy minimum-version review hint (9.31); not a verified CVE range or universal safe version.'),
    DepRule('jjwt', '0.12.0', 'MEDIUM', 'Legacy minimum-version review hint (0.12.0); not a verified CVE range or universal safe version.'),
    DepRule('jjwt-api', '0.12.0', 'MEDIUM', 'Legacy minimum-version review hint (0.12.0); not a verified CVE range or universal safe version.'),
    DepRule('java-jwt', '4.3.0', 'MEDIUM', 'Legacy minimum-version review hint (4.3.0); not a verified CVE range or universal safe version.'),
    # Critical ecosystem CVEs
    DepRule("log4j-core", "2.17.1", "CRITICAL",
            "Log4Shell CVE-2021-44228: JNDI RCE via log input."),
    DepRule('spring-cloud-gateway', '3.1.1', 'CRITICAL', 'Legacy minimum-version review hint (3.1.1); not a verified CVE range or universal safe version.'),
    DepRule("spring-data-mongodb", "3.4.1", "CRITICAL",
            "CVE-2022-22980: conditional SpEL injection in Spring Data MongoDB; branch-aware version assessment."),
    DepRule('snakeyaml', '2.0', 'HIGH', 'Legacy minimum-version review hint (2.0); not a verified CVE range or universal safe version.'),
    DepRule('jackson-databind', '2.14.0', 'HIGH', 'Legacy minimum-version review hint (2.14.0); not a verified CVE range or universal safe version.'),
    DepRule('commons-text', '1.10.0', 'HIGH', 'Legacy minimum-version review hint (1.10.0); not a verified CVE range or universal safe version.'),
    DepRule('h2', '2.1.210', 'CRITICAL', 'Legacy minimum-version review hint (2.1.210); not a verified CVE range or universal safe version.'),
    DepRule('logback-classic', '1.2.11', 'HIGH', 'Legacy minimum-version review hint (1.2.11); not a verified CVE range or universal safe version.'),
    DepRule('logback-core', '1.2.11', 'HIGH', 'Legacy minimum-version review hint (1.2.11); not a verified CVE range or universal safe version.'),
    DepRule('tomcat-embed-core', '10.1.5', 'HIGH', 'Legacy minimum-version review hint (10.1.5); not a verified CVE range or universal safe version.'),
    DepRule('spring-cloud-netflix-eureka-client', None, 'MEDIUM', 'Dependency configuration review; package presence alone does not prove a vulnerability.'),
    DepRule('spring-data-rest-core', '3.7.0', 'HIGH', 'Legacy minimum-version review hint (3.7.0); not a verified CVE range or universal safe version.'),
    DepRule('commons-collections', '3.2.2', 'CRITICAL', 'Legacy minimum-version review hint (3.2.2); not a verified CVE range or universal safe version.'),
    DepRule('commons-collections4', '4.1', 'CRITICAL', 'Legacy minimum-version review hint (4.1); not a verified CVE range or universal safe version.'),
]

MAVEN_DEP = re.compile(
    r"<artifactId>\s*([\w.\-]+)\s*</artifactId>\s*(?:<[^>]+>\s*)*?<version>\s*([^<\s]+)\s*</version>",
    re.S)
MAVEN_ARTIFACT_ONLY = re.compile(r"<artifactId>\s*([\w.\-]+)\s*</artifactId>")
MAVEN_PROPERTY = re.compile(r"<([\w.\-]+)>\s*([\d][\d.\-_a-zA-Z]+)\s*</\1>")
MAVEN_PROPERTY_REF = re.compile(r"\$\{([\w.\-]+)\}")

# --- Maven: parent chain + <dependencyManagement> resolution --------------
# A large share of real poms declare no <version> on a dependency at all: the
# version comes from <dependencyManagement>, either in the same pom or in a
# parent pom of a multi-module build. Without resolving those, such entries
# have no version to check and are simply skipped - i.e. silently unscanned.
_MAVEN_PARENT_BLOCK = re.compile(r"<parent>(.*?)</parent>", re.S | re.I)
_MAVEN_RELPATH = re.compile(r"<relativePath>\s*([^<]*?)\s*</relativePath>", re.I)
_MAVEN_DEPMGMT_BLOCK = re.compile(r"<dependencyManagement>(.*?)</dependencyManagement>", re.S | re.I)
_MAVEN_DEP_ENTRY = re.compile(r"<dependency>(.*?)</dependency>", re.S | re.I)
_MAVEN_TAG_GROUP = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>", re.I)
_MAVEN_TAG_ARTIFACT = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", re.I)
_MAVEN_TAG_VERSION = re.compile(r"<version>\s*([^<\s]+)\s*</version>", re.I)





GRADLE_DEP = re.compile(r"[\'\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)[\'\"]")
GRADLE_VERSION_BLOCK = re.compile(
    r"[\'\"]([\w.\-]+):([\w.\-]+)[\'\"]\)?\s*\{[^}]*?version\s*\{[^}]*?"
    r"(?:strictly|require|prefer)\s*\(\s*[\'\"]([\w.\-]+)[\'\"]",
    re.S)
TOML_LIB = re.compile(
    r"^([\w\-]+)\s*=\s*\{[^}]*?module\s*=\s*[\'\"]([\w.\-]+):([\w.\-]+)[\'\"]"
    r"[^}]*?version(?:\.ref)?\s*=\s*[\'\"]([\w.\-]+)[\'\"]",
    re.M | re.S)
TOML_VERSION = re.compile(r"^([\w\-]+)\s*=\s*[\'\"]([\d][\w.\-]*)[\'\"]", re.M)
GRADLE_CONSTRAINT = re.compile(
    r"constraints\s*\{[^}]*?(?:implementation|api|runtimeOnly)\s*"
    r"[\'\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)[\'\"]",
    re.S)
SPRING_BOOT_VER = re.compile(
    r"spring[\-_]boot[\-_]starter[\-_]parent.*?<version>\s*([\d.]+)\s*</version>|"
    r"id\s*[\'\"]org\.springframework\.boot[\'\"]\s*version\s*[\'\"]([\d.]+)[\'\"]",
    re.S | re.I)


def version_tuple(ver: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", ver)
    return tuple(int(p) for p in parts[:5]) or (0,)




# --------------------------------------------------------------------------
# Taint hints
# --------------------------------------------------------------------------

TAINT_PATTERNS = [
    (re.compile(r"HttpServletRequest|getInputStream\s*\(|getReader\s*\(|getParameter\s*\("), "HTTP request"),
    (re.compile(r"MultipartFile|@RequestBody|@RequestParam|FileUpload|getPart\s*\("), "upload/controller"),
    (re.compile(r"@WebService|@SOAPBinding|SOAPMessage|javax\.jws|jakarta\.jws"), "SOAP endpoint"),
    (re.compile(r"@Consumes\s*\(|MediaType\.APPLICATION_XML|text/xml|application/xml"), "XML REST endpoint"),
    (re.compile(r"KafkaListener|JmsListener|onMessage\s*\(|@RabbitListener"), "message queue"),
    (re.compile(r"URLConnection|HttpClient|RestTemplate|WebClient|okhttp"), "outbound HTTP call"),
    (re.compile(r"@Controller|@RestController|@Path\s*\(|extends\s+HttpServlet"), "web endpoint"),
]

TEST_PATH = re.compile(r"(?:^|[/\\])(?:test|tests|androidTest|src[/\\]test)(?:[/\\]|$)", re.I)

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    rule_name: str
    severity: str
    status: str            # VULNERABLE | PARTIAL | REVIEW | HARDENED
    code: str
    variable: Optional[str] = None
    method: Optional[str] = None
    guards_found: List[str] = field(default_factory=list)
    guards_missing: List[str] = field(default_factory=list)
    taint: List[str] = field(default_factory=list)
    note: str = ""
    is_test: bool = False
    fingerprint: str = ""
    fix: str = ""
    flow: List[str] = field(default_factory=list)
    # Surrounding source lines as (line_number, text) pairs, so a finding can
    # be judged in context instead of from a single line torn out of it.
    # Deliberately NOT part of the fingerprint: reformatting a neighbouring
    # line must not invalidate an existing baseline or triage decision.
    context: List[Tuple[int, str]] = field(default_factory=list)


@dataclass
class CoverageEntry:
    """Security-control coverage for one externally reachable entry point."""
    entrypoint: str
    kind: str
    file: str
    line: int
    method: str
    http_method: str = ""
    route: str = ""
    controls: Dict[str, str] = field(default_factory=dict)
    evidence: Dict[str, List[str]] = field(default_factory=dict)
    flow: List[str] = field(default_factory=list)
    sensitive_sinks: List[str] = field(default_factory=list)
    unresolved_calls: List[str] = field(default_factory=list)
    semantic_facts: Dict[str, object] = field(default_factory=dict)
    flow_steps: List[dict] = field(default_factory=list)
    sinks: List[dict] = field(default_factory=list)
    route_policy: str = "unknown"
    policy_evidence: List[str] = field(default_factory=list)
    reference_flow: bool = False
    policy_sources: List[dict] = field(default_factory=list)
    control_sources: Dict[str, List[dict]] = field(default_factory=dict)
    control_explanations: Dict[str, dict] = field(default_factory=dict)
    required_permissions: List[str] = field(default_factory=list)
    activation_conditions: List[str] = field(default_factory=list)
    policy_conditions: List[str] = field(default_factory=list)
    configuration_profiles: List[str] = field(default_factory=list)


@dataclass
class Method:
    name: str
    ret: str
    start: int   # 1-based, inclusive
    end: int     # 1-based, inclusive


# --------------------------------------------------------------------------
# Lexer helpers
# --------------------------------------------------------------------------

def strip_comments(src: str) -> str:
    out = []
    i, n = 0, len(src)
    state = "code"
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if src.startswith('"""', i):
                state = "text_block"
                out.append('"""')
                i += 3
                continue
            if c == '"':
                state = "string"
            elif c == "'":
                state = "char"
            out.append(c)
            i += 1
            continue
        if state == "line_comment":
            if c == "\n":
                state = "code"
                out.append(c)
            i += 1
            continue
        if state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if state == "text_block":
            if src.startswith('"""', i):
                state = "code"
                out.append('"""')
                i += 3
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        if c == "\\" and nxt:
            out.append(nxt)
            i += 2
            continue
        if (state == "string" and c == '"') or (state == "char" and c == "'"):
            state = "code"
        i += 1
    return "".join(out)


STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"')
CHAR_LITERAL = re.compile(r"'(?:\\.|[^'\\])'")


def blank_literals(line: str) -> str:
    return CHAR_LITERAL.sub("''", STRING_LITERAL.sub('""', line))


METHOD_DECL = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|native|default|"
    r"strictfp|suspend|open|override|fun)\s+)+"
    r"(?:<[^>]{0,80}>\s*)?"
    r"([\w<>\[\],.?\s]*?)\s*\b(\w+)\s*\([^;{]*\)\s*(?:throws\s+[\w.,\s<>]+)?\{?\s*$")


def parse_methods(lines: List[str]) -> List[Method]:
    """Finds method blocks by brace depth (a heuristic, but good enough)."""
    blanked = [blank_literals(ln) for ln in lines]
    depths: List[int] = []
    d = 0
    for ln in blanked:
        d += ln.count("{") - ln.count("}")
        depths.append(d)

    methods: List[Method] = []
    for i, ln in enumerate(blanked):
        m = METHOD_DECL.match(ln)
        if not m:
            continue
        ret = (m.group(1) or "").strip()
        name = m.group(2)
        if name in {"if", "for", "while", "switch", "catch", "synchronized", "return", "new"}:
            continue
        before = depths[i - 1] if i > 0 else 0
        # signature without "{" -> the body starts on the next line
        end = len(lines)
        for j in range(i + 1, len(lines)):
            if depths[j] <= before:
                end = j + 1
                break
        methods.append(Method(name=name, ret=ret, start=i + 1, end=end))
    return methods


def enclosing_method(methods: List[Method], line_no: int) -> Optional[Method]:
    best: Optional[Method] = None
    for m in methods:
        if m.start <= line_no <= m.end:
            if best is None or (m.end - m.start) < (best.end - best.start):
                best = m
    return best


VAR_ASSIGN = re.compile(r"(?:^|[^\w.])(?:final\s+|val\s+|var\s+)?(?:\w[\w<>,\[\]\s.]*?\s+)?(\w+)\s*=\s*[^=]")
RHS_CALL = re.compile(r"=\s*(?:new\s+)?(?:([\w.]+)\s*\.\s*)?(\w+)\s*\(")

FACTORY_RETURN_HINT = re.compile(r"Factory|Reader|Builder|Marshaller|Parser|Mapper|XStream", re.I)


def collect_guards(lines: Sequence[str], var: Optional[str]) -> Set[str]:
    found: Set[str] = set()
    var_re = re.compile(r"\b" + re.escape(var) + r"\s*\.") if var else None
    for line in lines:
        if var_re is not None and not var_re.search(line):
            continue
        found.update(gid for gid, pat in GUARD_PATTERNS.items() if pat.search(line))
    return found


def build_helper_index(files_data: Dict[str, Tuple[List[str], List[Method]]]) -> Dict[str, Set[str]]:
    """Method name -> guards it sets, for factory helpers across the whole project."""
    index: Dict[str, Set[str]] = {}
    for path, (lines, methods) in files_data.items():
        for m in methods:
            if not FACTORY_RETURN_HINT.search(m.ret or ""):
                continue
            body = lines[m.start - 1:m.end]
            guards = _helper_xml_guards(body)
            if m.name in index:
                index[m.name].intersection_update(guards)
            else:
                index[m.name] = guards
    return index


def taint_hints(text: str) -> List[str]:
    return [label for pat, label in TAINT_PATTERNS if pat.search(text)]


def evaluate(rule: Rule, guards: Set[str]) -> Tuple[str, List[str]]:
    if rule.kind == "hardening":
        # Standalone positive-practice rules: the pattern match itself IS the
        # good practice, independent of any nearby risky construct or guard
        # collection - so it is always reported as HARDENED (same status/
        # filtering path as a properly-guarded sink), never VULNERABLE/REVIEW.
        return "HARDENED", []
    if rule.kind == "antipattern":
        return "ANTIPATTERN", []
    if rule.always_report:
        return "REVIEW", []
    for group in rule.sufficient:
        if all(g in guards for g in group):
            return "HARDENED", []
    if any(g in guards for g in rule.partial):
        best = min(rule.sufficient, key=lambda g: len([x for x in g if x not in guards])) \
            if rule.sufficient else []
        return "PARTIAL", [g for g in best if g not in guards]
    return "VULNERABLE", list(rule.sufficient[0]) if rule.sufficient else []


def bump(severity: str, steps: int) -> str:
    idx = max(0, min(len(SEVERITY_LIST) - 1, SEVERITY_LIST.index(severity) + steps))
    return SEVERITY_LIST[idx]


CONTEXT_RADIUS = 999_999  # 0 = nur Treffer-Zeile; grosser Wert = ganze Datei


def context_lines(raw_lines: Sequence[str], line_no: int,
                  radius: int = CONTEXT_RADIUS) -> List[Tuple[int, str]]:
    """Returns (line_number, text) pairs around a 1-based line number.

    A single matched line is often not enough to judge a finding - whether a
    parser is hardened two lines further down, or what a concatenated SQL
    string actually contains, only shows in context.

    radius <= 0  → matched line only (use --context 0 to select this)
    radius large → entire file (default; all lines visible, finding highlighted)
    """
    if not raw_lines:
        return []
    if radius <= 0:
        # radius 0: nur die Treffer-Zeile zurückgeben
        if 1 <= line_no <= len(raw_lines):
            return [(line_no, raw_lines[line_no - 1].rstrip("\n"))]
        return []
    start = max(1, line_no - radius)
    end = min(len(raw_lines), line_no + radius)
    return [(n, raw_lines[n - 1].rstrip("\n")) for n in range(start, end + 1)]


def finding_context_text(f: Finding) -> str:
    if not f.context:
        return f.code
    width = len(str(f.context[-1][0]))
    return "\n".join(f"{'>' if n == f.line else ' '} {n:>{width}} | {line}"
                     for n, line in f.context)


def enrich_context(findings: List[Finding], root: str, radius: int = 3, raw_cache: Optional[Dict[str, List[str]]] = None) -> None:
    """Load original source once per file, including dependency and OSV findings."""
    cache: Dict[str, List[str]] = dict(raw_cache or {})
    for f in findings:
        path = os.path.join(root, f.file) if root else f.file
        if path not in cache:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    cache[path] = fh.read().splitlines()
            except OSError:
                cache[path] = []
        lines = cache[path]
        if 1 <= f.line <= len(lines):
            start, end = max(1, f.line - radius), min(len(lines), f.line + radius)
            f.context = [(n, lines[n - 1]) for n in range(start, end + 1)]


def load_codeql_sarif(paths: Sequence[str], root: str) -> List[Finding]:
    """Import CodeQL CLI/Action SARIF without bundling CodeQL or its queries."""
    imported: List[Finding] = []
    for sarif_path in paths:
        try:
            with open(sarif_path, encoding="utf-8") as fh:
                document = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ValueError(f"cannot read CodeQL SARIF {sarif_path}: {exc}") from exc
        for run in document.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            rule_names = {str(r.get("id")): r.get("name", "")
                          for r in driver.get("rules", [])}
            for result in run.get("results", []):
                rid = str(result.get("ruleId") or result.get("rule", "CODEQL"))
                location = (result.get("locations") or [{}])[0]
                physical = location.get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {}
                uri = urllib.parse.unquote(str(artifact.get("uri") or "<unknown>"))
                if uri.startswith("file://"):
                    uri = uri[7:]
                if os.path.isabs(uri) and root:
                    rel = os.path.relpath(uri, root)
                else:
                    rel = os.path.normpath(uri)
                region = physical.get("region") or {}
                line = int(region.get("startLine") or 1)
                message = (result.get("message") or {}).get("text", "CodeQL finding")
                severity = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(
                    str(result.get("level") or "warning").lower(), "MEDIUM")
                flow: List[str] = []
                for code_flow in result.get("codeFlows", []):
                    for thread in code_flow.get("threadFlows", []):
                        for step in thread.get("locations", []):
                            step_loc = step.get("location", {}).get("physicalLocation", {})
                            step_uri = (step_loc.get("artifactLocation") or {}).get("uri", uri)
                            step_line = (step_loc.get("region") or {}).get("startLine", "?")
                            flow.append(f"{step_uri}:{step_line}")
                code = str(region.get("snippet", {}).get("text") or message)
                external_id = f"CODEQL-{rid}"
                imported.append(Finding(
                    file=rel, line=line, rule_id=external_id,
                    rule_name=rule_names.get(rid) or rid, severity=severity,
                    status="VULNERABLE", code=code[:200], note=message,
                    fingerprint=fingerprint(rel, external_id, f"{line}:{code}"), flow=flow))
    return imported


def fingerprint(rel_path: str, rule_id: str, code: str) -> str:
    norm = re.sub(r"\s+", " ", code).strip()
    return hashlib.sha1(f"{rel_path}|{rule_id}|{norm}".encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------
# Analyzing a single file
# --------------------------------------------------------------------------

def load_file(path: str) -> Optional[Tuple[str, List[str], List[str], List[Method]]]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"[!] Cannot read {path}: {exc}", file=sys.stderr)
        return None
    code = strip_comments(raw)
    lines = code.splitlines()
    return raw, raw.splitlines(), lines, parse_methods(lines)



def _candidate_rules(lines: Sequence[str], rules: Sequence[Rule]) -> List[Rule]:
    """Skip only rules whose mandatory literals are absent from the whole file.

    The actual regex still determines every match. Match metadata is bound to
    compiled patterns, so new or changed rules automatically use the slow path.
    Non-ASCII input bypasses case-insensitive prefilters to preserve Python's
    Unicode IGNORECASE semantics (including dotted/dotless I and long S).
    """
    source = "\n".join(lines)
    ascii_source = source.isascii()
    folded = source.lower() if ascii_source else ""
    candidates = []
    for rule in rules:
        literals = _RULE_PREFILTERS.get(rule.pattern)
        if not literals or (rule.pattern.flags & re.I and not ascii_source):
            candidates.append(rule)
            continue
        haystack = folded if rule.pattern.flags & re.I else source
        if any(literal in haystack for literal in literals):
            candidates.append(rule)
    return candidates



def _source_matches(lines, rules):
    """Preserve line matches and add cross-line matches at original offsets."""
    from bisect import bisect_right
    text = "\n".join(lines)
    starts = [0]
    starts.extend(m.end() for m in re.finditer("\n", text))
    matches = {}
    for rule in rules:
        for index, line in enumerate(lines):
            match = rule.pattern.search(line)
            if match:
                matches[(index + 1, rule.rid)] = (
                    rule, match, starts[index] + match.start(), line)
        for match in rule.pattern.finditer(text):
            if "\n" not in match.group():
                continue
            index = bisect_right(starts, match.start()) - 1
            # Include a split assignment preceding the matched constructor.
            begin = max(text.rfind(c, 0, match.start()) for c in ";{}") + 1
            snippet = text[begin:match.end()]
            matches.setdefault((index + 1, rule.rid),
                               (rule, match, match.start(), snippet))
    by_line = {}
    order = {id(rule): i for i, rule in enumerate(rules)}
    for (line, _), value in matches.items():
        by_line.setdefault(line, []).append(value)
    for values in by_line.values():
        values.sort(key=lambda value: order[id(value[0])])
    masked = _structure_mask(text)
    seen_assignments = set()
    for line_number in sorted(by_line):
        normalized = []
        for rule, match, position, snippet in by_line[line_number]:
            begin = max(masked.rfind(c, 0, position) for c in ";{}") + 1
            end = masked.find(";", position)
            statement = text[begin:end if end >= 0 else len(text)]
            assignment = VAR_ASSIGN.search(statement)
            if assignment and begin + assignment.start() <= position + len(match.group()):
                key = (begin, rule.rid)
                if key in seen_assignments:
                    continue
                seen_assignments.add(key)
                snippet = statement
            normalized.append((rule, match, position, snippet))
        by_line[line_number] = normalized
    return text, by_line


def _xml_guard_evidence(text, masked, bounds, position, variable, initial=()):
    """Trust only direct, unconditional configuration before first object use.

    This is deliberately conservative, not a control-flow proof. Branches,
    reassignment, unknown setters and unsupported statements invalidate proof.
    The caller may still report an explicit feature setting as REVIEW.
    """
    if not variable:
        return set(), []
    enclosing = [b for b in bounds if b[3] < position < b[4]]
    if not enclosing:
        return set(), []
    boundary = min(enclosing, key=lambda b: b[4] - b[3])[4]
    declaration_end = masked.find(";", position, boundary)
    if declaration_end < 0:
        return set(), []
    guards = set(initial)
    evidence = []
    begin = declaration_end + 1
    receiver = re.compile(r"^\s*" + re.escape(variable) + r"\s*\.\s*(\w+)\s*\(")
    mention = re.compile(r"\b" + re.escape(variable) + r"\b")
    tail_start = begin
    for terminator in re.finditer(";", masked[tail_start:boundary]):
        end = tail_start + terminator.start()
        statement = text[begin:end]
        structure = masked[begin:end]
        if re.search(r"[{}]|\b(?:if|else|for|while|switch|try|catch|finally|do)\b|->|\?", structure):
            return set(), []
        if not mention.search(structure):
            begin = end + 1
            continue
        call = receiver.match(structure)
        if not call:
            if re.match(r"\s*return\s+" + re.escape(variable) + r"\s*$", structure):
                return guards, evidence
            return set(), []
        opening = call.end() - 1
        closing = _closing(structure, opening)
        # Nested expressions can execute arbitrary mutations; do not certify.
        if closing < 0:
            return set(), []
        name = call.group(1)
        if name.startswith(('set', 'allow')):
            if structure[closing + 1:].strip() or re.search(r"[\w$]\s*\(", structure[opening + 1:closing]):
                return set(), []
            hits = {key for key, pattern in GUARD_PATTERNS.items()
                    if pattern.search(statement)}
            if not hits:
                # Unknown or reversing configuration cannot establish safety.
                return set(), []
            guards.update(hits)
            evidence.append((begin, end))
            begin = end + 1
            continue
        # Only known consumption operations preserve the established proof.
        # An unknown call could mutate the object before its eventual use.
        if name in {"newDocumentBuilder", "newSAXParser", "createXMLStreamReader",
                    "createXMLEventReader", "newTransformer", "newTemplates",
                    "newSchema", "newValidator", "newPullParser", "parse",
                    "build", "read", "unmarshal", "fromXML", "evaluate", "compile"}:
            return guards, evidence
        return set(), []
    return guards, evidence


def _helper_xml_guards(body):
    """Only certify a simple factory returning the very object it configured."""
    text = "class Helper { public Object factory() {\n" + "\n".join(body[1:-1]) + "\n} }"
    masked = _structure_mask(text)
    bounds = list(_web_methods(text))
    returns = list(re.finditer(r"\breturn\s+(\w+)\s*;", masked))
    if len(returns) != 1:
        return set()
    variable = returns[0].group(1)
    assignment = re.search(r"\b" + re.escape(variable) + r"\s*=\s*", masked)
    if not assignment:
        return set()
    guards, _ = _xml_guard_evidence(text, masked, bounds, assignment.start(), variable)
    return guards



def _check_kid_injection(path: str, lines: list, raw_lines: list,
                         methods: list, context_radius: int) -> list:
    """Cross-line taint check: kid JWT header claim flows into a dangerous sink.

    Sources:  getHeader("kid"), claims.get("kid"), JwtHeader.getKeyId(),
              Jwt.getHeaders().get("kid"), NimbusJwt/SignedJWT.getHeader().getKeyID()
    Sinks:    DB (query/prepareStatement/nativeQuery/execute/prepareCall/NamedQuery),
              File (new File / Paths.get / FileReader / FileInputStream / readAllBytes),
              OS cmd (Runtime.exec / ProcessBuilder),
              JNDI (lookup), LDAP (search/bind), SSRF (RestTemplate/WebClient/URL/URI),
              Crypto key load (MessageDigest.getInstance / Cipher.getInstance / KeyFactory),
              JDBC URL (DriverManager.getConnection)
    Passes:   3 passes - (1) source→same-line sink, (2) source→var, var→sink,
              (3) kid var passed through a helper/builder method that then hits a sink.

    CVE-2018-0114 class: https://github.com/ticarpi/jwt_tool (KID injection playbook)
    """
    import re as _re
    findings_out = []

    # ── Sources ──────────────────────────────────────────────────────────────
    KID_SOURCE = _re.compile(
        # jjwt: claims.get("kid") / getClaims().get("kid") / getHeader("kid")
        r"(?:getHeader|header\s*\(\s*)[\x22\x27]kid[\x22\x27]|"
        r"\.getClaims\(\)[^;\n]{0,100}\.get\s*\(\s*[\x22\x27]kid[\x22\x27]|"
        r"claims\s*\.\s*get\s*\(\s*[\x22\x27]kid[\x22\x27]|"
        # Spring Security OAuth2 JWT: jwt.getHeaders().get("kid") / Jwt.getHeader("kid")
        r"\.getHeaders\s*\(\s*\)[^;\n]{0,80}\.get\s*\(\s*[\x22\x27]kid[\x22\x27]|"
        r"\.getHeader\s*\(\s*[\x22\x27]kid[\x22\x27]|"
        # Nimbus: SignedJWT.getHeader().getKeyID() / JWSHeader.getKeyID()
        r"\.getKeyID\s*\(\s*\)|"
        r"JWSHeader[^;\n]{0,60}\.getKeyID\s*\(\s*\)",
        _re.I)

    # ── Sinks ─────────────────────────────────────────────────────────────────
    KID_SINK = _re.compile(
        # DB
        r"\.(?:query|nativeQuery|execute|prepareStatement|prepareCall|"
        r"createNativeQuery|createQuery|find|findById)\s*\(|"
        r"\.(?:createNamedQuery|createSQLQuery)\s*\(|"
        # File
        r"new\s+(?:java\.io\.)?File\s*\(|(?:java\.nio\.file\.)?Paths\s*\.\s*get\s*\(|"
        r"new\s+(?:java\.io\.)?FileReader\s*\(|new\s+(?:java\.io\.)?FileInputStream\s*\(|"
        r"\.readAllBytes\s*\(|Files\s*\.\s*(?:read|newInput)\s*\(|"
        # OS
        r"Runtime\s*\.\s*exec\s*\(|ProcessBuilder\s*\(|"
        # JNDI / LDAP
        r"\.lookup\s*\(|ctx\s*\.\s*search\s*\(|ctx\s*\.\s*bind\s*\(|"
        r"new\s+InitialDirContext\s*\(|new\s+InitialLdapContext\s*\(|"
        # SSRF
        r"new\s+URL\s*\(|URI\s*\.\s*create\s*\(|"
        r"restTemplate\s*\.\s*(?:getFor|postFor|exchange|execute)|"
        r"webClient\s*\.\s*(?:get|post|put|delete)\s*\(|"
        # Crypto key load (key confusion)
        r"MessageDigest\s*\.\s*getInstance\s*\(|"
        r"Cipher\s*\.\s*getInstance\s*\(|"
        r"KeyFactory\s*\.\s*getInstance\s*\(|"
        # JDBC
        r"DriverManager\s*\.\s*getConnection\s*\(",
        _re.I)

    # ── Taint tracking ────────────────────────────────────────────────────────
    kid_vars: set = set()         # variables assigned from a kid source
    kid_taint_vars: set = set()   # variables that receive a kid_var as argument

    def _make_finding(line_idx: int, rule_name: str, note: str) -> "Finding":
        code = raw_lines[line_idx].strip()[:200] if line_idx < len(raw_lines) else ""
        return Finding(
            file=path, line=line_idx + 1,
            rule_id="JWT-KID-INJECTION",
            rule_name=rule_name,
            severity="HIGH", status="VULNERABLE",
            code=code,
            note=note,
            fingerprint=fingerprint(path, "JWT-KID-INJECTION", code),
            context=context_lines(raw_lines, line_idx + 1, context_radius),
            fix="Never use the kid claim value directly in a DB query, file path, "
                "OS command, JNDI lookup, SSRF call, or crypto-algorithm selector. "
                "Maintain a fixed key registry (a validated Map<String,Key>) and "
                "look up keys by a safe internal identifier, not by the raw kid string.",
        )

    # Pass 1: source on the same line as a sink → immediate finding
    # Pass 1 also: collect variables assigned from kid sources
    for i, line in enumerate(lines):
        m = KID_SOURCE.search(line)
        if m:
            assign = re.search(r"(?:String|Object|var|Key|byte\[\])\s+(\w+)\s*=", line)
            if assign:
                kid_vars.add(assign.group(1))
            if KID_SINK.search(line):
                findings_out.append(_make_finding(
                    i, "JWT kid claim used directly in a sink",
                    "The kid JWT header field is attacker-controlled and flows directly "
                    "into a dangerous sink on the same line (SQLi, path traversal, RCE, "
                    "JNDI/LDAP injection, SSRF, or key confusion). CVE-2018-0114 class."))

    # Pass 2: kid variable flows into a sink (possibly many lines later)
    if kid_vars:
        var_re = re.compile(r"\b(" + "|".join(re.escape(v) for v in kid_vars) + r")\b")
        for i, line in enumerate(lines):
            if var_re.search(line):
                # Track variables that receive a kid var as argument
                passthrough = re.search(
                    r"(?:String|Object|var|Key|byte\[\])\s+(\w+)\s*=[^;\n]{0,200}\b("
                    + "|".join(re.escape(v) for v in kid_vars) + r")\b", line)
                if passthrough:
                    kid_taint_vars.add(passthrough.group(1))
                if KID_SINK.search(line):
                    findings_out.append(_make_finding(
                        i, "JWT kid claim flows into a sink (cross-line)",
                        "A variable derived from the kid JWT header field reaches a "
                        "dangerous sink. The kid value is attacker-controlled. "
                        "CVE-2018-0114 class."))

    # Pass 3: tainted passthrough variable reaches a sink
    if kid_taint_vars:
        taint_re = re.compile(
            r"\b(" + "|".join(re.escape(v) for v in kid_taint_vars) + r")\b")
        for i, line in enumerate(lines):
            if taint_re.search(line) and KID_SINK.search(line):
                findings_out.append(_make_finding(
                    i, "JWT kid claim flows into a sink (tainted passthrough)",
                    "A variable that received a kid-tainted value as an argument "
                    "reaches a dangerous sink. The original kid value is attacker-controlled. "
                    "CVE-2018-0114 class."))

    return findings_out


def analyze_file(path: str, raw_lines: List[str], lines: List[str], methods: List[Method],
                 helper_index: Dict[str, Set[str]], root: str,
                 show_hardened: bool,
                 active_rules: Optional[Sequence[Rule]] = None, context_radius: int = CONTEXT_RADIUS) -> List[Finding]:
    is_test = bool(TEST_PATH.search(path)) or path.endswith(("Test.java", "Tests.java", "IT.java"))
    rel = os.path.relpath(path, root) if root else path

    findings: List[Finding] = []
    # Per-file caches: a method's source and guards are immutable during analysis.
    scope_cache = {}
    guard_cache = {}
    candidate_rules = _candidate_rules(lines, active_rules if active_rules is not None else RULES)
    source_text, source_matches = _source_matches(lines, candidate_rules)
    source_mask = _structure_mask(source_text)
    source_bounds = list(_web_methods(source_text))
    verified_xml_settings = []
    for idx, line in enumerate(lines, start=1):
        raw_line = raw_lines[idx - 1] if idx - 1 < len(raw_lines) else ""
        # Imports mention vulnerable APIs but do not execute them. Rules that
        # intentionally inspect dependencies operate on build files instead.
        if line.lstrip().startswith(("import ", "package ")):
            continue
        # A marker may sit immediately above a method declaration while the
        # vulnerable API occurs a line or two into its body.  Inspect the
        # short declaration window before falling back to rule evaluation.
        sup_match = None
        for candidate in reversed(raw_lines[max(0, idx - 3):idx]):
            sup_match = SUPPRESS_MARKER.search(candidate)
            if sup_match:
                break
        suppressed_rules = None
        if sup_match:
            if sup_match.group(1):
                suppressed_rules = {r.strip().upper() for r in sup_match.group(1).split(",") if r.strip()}
            else:
                continue

        meth = enclosing_method(methods, idx)
        method_marker_found = False
        method_suppressed_rules: Optional[Set[str]] = set()
        if meth:
            # A marker immediately above a method applies to the method body,
            # including intervening annotations and the declaration itself.
            for candidate in raw_lines[max(0, meth.start - 4):meth.start]:
                marker = SUPPRESS_MARKER.search(candidate)
                if marker:
                    method_marker_found = True
                    method_suppressed_rules = ({r.strip().upper()
                                                for r in marker.group(1).split(",") if r.strip()}
                                               if marker.group(1) else None)

        # Rule include/exclude filters are resolved once by the CLI. Avoid
        # running regexes for disabled rules on every source line.
        for rule, rule_match, match_position, match_source in source_matches.get(idx, ()):
            # Cross-line matches use the same suppression and report handling.
            if suppressed_rules is not None and rule.rid.upper() in suppressed_rules:
                continue
            if method_marker_found and (method_suppressed_rules is None or
                                        rule.rid.upper() in method_suppressed_rules):
                continue

            var = None
            m = VAR_ASSIGN.search(match_source)
            if m:
                var = m.group(1)

            scope_key = (meth.start, meth.end) if meth else None
            if scope_key not in scope_cache:
                scope_lines = lines[meth.start - 1:meth.end] if meth else lines
                scope_cache[scope_key] = (
                    scope_lines, taint_hints("\n".join(scope_lines)) if meth else [])
            scope_lines, finding_taint = scope_cache[scope_key]
            # Only use taint as a confidence/severity signal when it occurs in
            # the same method as the sink. File-wide taint made unrelated
            # class annotations and sibling methods look one level worse.
            if var:
                guard_key = (scope_key, var)
                if guard_key not in guard_cache:
                    guard_cache[guard_key] = collect_guards(scope_lines, var)
                guards = guard_cache[guard_key].copy()
            elif rule.rid.startswith("SpringSecurityCheck-"):
                # Spring Security is configured as a builder chain
                # (http.csrf(...).sessionManagement(...)), so the hardening
                # calls are not bound to a variable the way a parser factory
                # is. Restricting guard collection to a variable would leave
                # guards permanently empty here and report every such rule
                # even on correctly hardened configurations.
                guard_key = (scope_key, None)
                if guard_key not in guard_cache:
                    guard_cache[guard_key] = collect_guards(scope_lines, None)
                guards = guard_cache[guard_key].copy()
            else:
                guards = set()

            # Resolve a helper factory: dbf = XmlUtils.secureFactory();
            via_helper = None
            rhs = RHS_CALL.search(match_source)
            if rhs:
                callee = rhs.group(2)
                if callee not in ("newInstance", "newFactory") and callee in helper_index:
                    guards |= helper_index[callee]
                    via_helper = callee

            if rule.rid.startswith("XXE-") or rule.rid == "DESER-XSTREAM":
                initial = helper_index.get(via_helper, set()) if via_helper else set()
                guards, evidence = _xml_guard_evidence(
                    source_text, source_mask, source_bounds, match_position, var, initial)
                verified_xml_settings.extend(evidence)
            status, missing = evaluate(rule, guards)
            if rule.rid == "HARDEN-XXE-DISALLOW-DOCTYPE" and not any(
                    start <= match_position < end for start, end in verified_xml_settings):
                status = "REVIEW"

            note = rule.note
            if rule.rid == "HARDEN-XXE-DISALLOW-DOCTYPE" and status == "REVIEW":
                note += " Explicit setting only: unconditional protection before parser use was not proven."
            if rule.rid.startswith("XXE-") and status not in ("HARDENED",):
                note += " Effective protection before first use was not proven; review ordering and control flow."
            matched_text = rule_match.group(0).strip()
            if matched_text and matched_text not in note:
                note += f" Matched construct: `{matched_text}`."
            if status != "HARDENED" and not var and not rule.always_report and rule.kind == "sink":
                note += " Used inline without a variable - hardening cannot be detected."
            if via_helper:
                note += f" Configuration comes from helper method {via_helper}()."

            if status == "HARDENED" and not show_hardened:
                continue

            severity = rule.severity
            if status == "PARTIAL":
                severity = bump(severity, -1)
            elif status == "HARDENED":
                severity = "INFO"
            if status in ("VULNERABLE", "REVIEW", "ANTIPATTERN") and finding_taint and not is_test:
                severity = bump(severity, 1)
            if is_test:
                severity = bump(severity, -1)

            snippet = raw_line.strip()[:200]
            findings.append(Finding(
                file=rel, line=idx, rule_id=rule.rid, rule_name=rule.name,
                severity=severity, status=status, code=snippet, variable=var,
                method=meth.name if meth else None,
                guards_found=sorted(guards), guards_missing=missing,
                taint=finding_taint, note=note.strip(), is_test=is_test,
                fingerprint=fingerprint(rel, rule.rid, snippet),
                context=context_lines(raw_lines, idx, context_radius),
            ))
    return findings


# --------------------------------------------------------------------------
# Dependency analysis
# --------------------------------------------------------------------------

_MAVEN_DEPENDENCY_BLOCK_RE = re.compile(r"<dependency>.*?</dependency>", re.S)


def _find_maven_dep_block(content: str, artifact: str) -> Optional[Tuple[str, int]]:
    """Returns (full <dependency>...</dependency> XML block, start offset) for
    the block whose <artifactId> matches, or None if not found."""
    art_re = re.compile(rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>")
    for m in _MAVEN_DEPENDENCY_BLOCK_RE.finditer(content):
        if art_re.search(m.group(0)):
            return m.group(0), m.start()
    return None


def _find_gradle_dep_line(raw_lines: List[str], artifact: str, version: Optional[str]) -> Optional[Tuple[str, int]]:
    """Returns (raw line text, 1-based line number) of the first line mentioning
    both the artifact and its version, for Gradle/TOML build files."""
    for i, ln in enumerate(raw_lines, start=1):
        if artifact in ln and (not version or version in ln):
            return ln.strip(), i
    for i, ln in enumerate(raw_lines, start=1):
        if artifact in ln:
            return ln.strip(), i
    return None




# --------------------------------------------------------------------------
# OSV.dev dependency check (opt-in via --check-osv)
# --------------------------------------------------------------------------
# The DEP_RULES list above is a static, hand-maintained snapshot and goes
# stale as new CVEs appear. --check-osv instead queries osv.dev (Google's
# free, open vulnerability database; no API key) live for the exact
# groupId:artifactId@version pairs found in the project's build files.
#
# For air-gapped machines, the check also supports a two-step cache workflow:
#   1) on an internet-connected machine:
#        python3 jspringguard.py . --check-osv --osv-cache-write osv-cache.json
#      (queries osv.dev live and saves every raw response to osv-cache.json)
#   2) copy osv-cache.json to the air-gapped machine, then:
#        python3 jspringguard.py . --check-osv --osv-cache-read osv-cache.json
#      (looks packages up ONLY in the local file - makes no network call at all)

OSV_API_QUERY_URL = "https://api.osv.dev/v1/query"
# Deliberately conservative: osv.dev is a free public service, and hammering it
# with many parallel requests is the quickest way to get rate limited.
OSV_MAX_CONCURRENCY = 4

_MAVEN_GROUP_RE = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>")
_MAVEN_ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")
_MAVEN_VERSION_RE = re.compile(r"<version>\s*([^<\s]+)\s*</version>")




_MAVEN_VERSION_QUALIFIER_RE = re.compile(r"\.(RELEASE|Final|GA|RC\d*|SP\d*)$", re.I)




@dataclass(frozen=True)
class ResolvedDependency:
    build_file: str
    group: str
    artifact: str
    version: str
    resolver: str


def parse_maven_dependency_output(output: str, build_file: str) -> List[ResolvedDependency]:
    """Parse `maven-dependency-plugin:dependency:list` console coordinates."""
    found: Set[Tuple[str, str, str]] = set()
    for raw in output.splitlines():
        line = re.sub(r"^\s*\[[A-Z]+\]\s*", "", raw).strip()
        for token in line.split():
            value = token.strip("(),")
            parts = value.split(":")
            if len(parts) not in (5, 6):
                continue
            group, artifact = parts[0], parts[1]
            version, scope = parts[-2], parts[-1]
            if (scope not in {"compile", "runtime", "provided", "system"}
                    or not re.fullmatch(r"[\w.-]+", group)
                    or not re.fullmatch(r"[\w.+-]+", version)):
                continue
            found.add((group, artifact, version))
    return [ResolvedDependency(build_file, g, a, v, "maven")
            for g, a, v in sorted(found)]


def parse_gradle_dependency_output(output: str, build_file: str) -> List[ResolvedDependency]:
    """Parse Gradle's plain `dependencies --configuration runtimeClasspath` tree."""
    found: Set[Tuple[str, str, str]] = set()
    coordinate = re.compile(
        r"(?:^|\s)([\w.-]+):([\w.-]+):([^\s()]+)(?:\s+->\s+([^\s()]+))?")
    for raw in output.splitlines():
        if re.search(r"\bFAILED\b|\(n\)", raw):
            continue
        match = coordinate.search(raw)
        if not match or match.group(1) == "project":
            continue
        version = match.group(4) or match.group(3)
        if version in {"FAILED", "unspecified"} or version.startswith("{"):
            continue
        if ":" in version:
            replacement = version.split(":")
            if len(replacement) == 3:
                found.add(tuple(replacement))
            continue
        found.add((match.group(1), match.group(2), version))
    return [ResolvedDependency(build_file, g, a, v, "gradle")
            for g, a, v in sorted(found)]


def _wrapper_or_tool(module_dir: str, kind: str,
                     boundary: Optional[str] = None) -> Optional[str]:
    names = (("mvnw.cmd", "mvnw") if kind == "maven" else
             ("gradlew.bat", "gradlew"))
    current = os.path.abspath(module_dir)
    stop = os.path.abspath(boundary) if boundary else current
    while True:
        for name in names:
            candidate = os.path.join(current, name)
            if os.path.isfile(candidate):
                return candidate
        parent = os.path.dirname(current)
        if parent == current or current == stop:
            break
        current = parent
    return shutil.which("mvn" if kind == "maven" else "gradle")


def _executable_command(executable: str, args: Sequence[str]) -> List[str]:
    if os.name == "nt" and executable.lower().endswith((".cmd", ".bat")):
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c",
                subprocess.list2cmdline([executable] + list(args))]
    if os.name != "nt" and not os.access(executable, os.X_OK):
        return ["sh", executable] + list(args)
    return [executable] + list(args)


def resolve_project_dependencies(build_files: Sequence[str], root: str,
                                 timeout: int = 180) -> Tuple[List[ResolvedDependency], List[str]]:
    """Ask Maven/Gradle for the effective runtime graph.

    This is deliberately opt-in: wrappers and build scripts are executable
    project code and may access configured repositories. The normal static
    scan never invokes them.
    """
    selected: Dict[str, Tuple[str, str]] = {}
    for path in build_files:
        name = os.path.basename(path)
        module = os.path.abspath(os.path.dirname(path))
        if name == "pom.xml":
            selected[module] = (path, "maven")
        elif name in {"build.gradle", "build.gradle.kts"} and module not in selected:
            selected[module] = (path, "gradle")
    dependencies: List[ResolvedDependency] = []
    errors: List[str] = []
    resolver_root = os.path.abspath(root) if root and os.path.isdir(root) else ""
    for module, (build_file, kind) in sorted(selected.items()):
        executable = _wrapper_or_tool(module, kind, resolver_root or module)
        rel = os.path.relpath(build_file, root) if root else build_file
        if not executable:
            errors.append(f"{rel}: no {kind} wrapper or executable found")
            continue
        args = (["--batch-mode", "--no-transfer-progress", "dependency:list",
                 "-DincludeScope=runtime", "-DexcludeTransitive=false"] if kind == "maven" else
                ["dependencies", "--configuration", "runtimeClasspath", "--console=plain"])
        try:
            proc = subprocess.run(_executable_command(executable, args), cwd=module,
                                  capture_output=True, text=True, errors="replace",
                                  timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{rel}: {kind} resolver failed: {exc}")
            continue
        combined = proc.stdout + "\n" + proc.stderr
        if proc.returncode != 0:
            tail = " ".join(combined.splitlines()[-3:])[:500]
            errors.append(f"{rel}: {kind} exited {proc.returncode}: {tail}")
            continue
        if kind == "gradle" and re.search(r"\bFAILED\b|\(n\)", combined):
            errors.append(f"{rel}: Gradle dependency graph is incomplete (unresolved entries)")
            continue
        parsed = (parse_maven_dependency_output(combined, build_file) if kind == "maven"
                  else parse_gradle_dependency_output(combined, build_file))
        if not parsed:
            errors.append(f"{rel}: {kind} returned no parseable runtime dependencies")
            continue
        dependencies.extend(parsed)
    unique = {(d.build_file, d.group, d.artifact, d.version): d for d in dependencies}
    return list(unique.values()), errors




RESOLVED_COMBINATION_RULES = {
    "BOOT-ACTUATOR-WITHOUT-HEALTH", "BOOT-ACTUATOR-WITHOUT-SECURITY",
    "BOOT-DEVTOOLS-PRESENT", "BOOT-WEB-WITHOUT-SECURITY",
    "COMBO-DATA-REST-WITHOUT-SECURITY",
}


def analyze_resolved_combinations(dependencies: Sequence[ResolvedDependency], root: str,
                                  module_evidence: Dict[str, str]) -> List[Finding]:
    """Evaluate Spring combinations against each effective runtime graph."""
    grouped: Dict[str, List[ResolvedDependency]] = {}
    for item in dependencies:
        grouped.setdefault(os.path.abspath(item.build_file), []).append(item)
    out: List[Finding] = []
    for build_file, items in grouped.items():
        by_artifact = {item.artifact: item for item in items}
        artifacts = set(by_artifact)
        security = bool(artifacts & {"spring-boot-starter-security",
                                     "spring-security-web", "spring-security-config"})
        evidence = module_evidence.get(build_file, "")
        clean_source = _structure_mask(strip_comments(evidence))
        rel = os.path.relpath(build_file, root) if root else build_file

        def add(rid: str, item: ResolvedDependency, severity: str, note: str, fix: str) -> None:
            identity = f"{item.group}:{item.artifact}:{item.version}"
            out.append(Finding(
                file=rel, line=1, rule_id=rid, rule_name=rid,
                severity=severity, status="REVIEW", code=identity,
                note="Effective runtime graph: " + note,
                fix=fix, fingerprint=fingerprint(rel, rid, identity)))

        actuator = (by_artifact.get("spring-boot-actuator-autoconfigure") or
                    by_artifact.get("spring-boot-starter-actuator"))
        auto = by_artifact.get("spring-boot-actuator-autoconfigure")
        if auto and "spring-boot-health" not in artifacts:
            match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:\.RELEASE)?", auto.version)
            affected = bool(match and (4, 0, 0) <= tuple(map(int, match.groups())) <= (4, 0, 5))
            if affected:
                add("BOOT-ACTUATOR-WITHOUT-HEALTH", auto, "HIGH",
                    "Spring Boot 4.0.0-4.0.5 actuator-autoconfigure without spring-boot-health. "
                    "Servlet/default-chain prerequisites still require source/runtime review.",
                    "Upgrade Spring Boot to 4.0.6 or later and verify the SecurityFilterChain.")
        devtools = by_artifact.get("spring-boot-devtools")
        if devtools:
            add("BOOT-DEVTOOLS-PRESENT", devtools, "MEDIUM",
                "DevTools is present in the resolved runtime graph.",
                "Exclude DevTools from the production runtime/archive.")
        if actuator and not security:
            add("BOOT-ACTUATOR-WITHOUT-SECURITY", actuator, "MEDIUM",
                "Actuator is present without Spring Security web/config in the resolved graph.",
                "Authenticate management endpoints and restrict their exposure.")
        data_rest = next((by_artifact[name] for name in
                          ("spring-boot-starter-data-rest", "spring-data-rest-webmvc",
                           "spring-data-rest-core") if name in by_artifact), None)
        if data_rest and not security:
            repository = bool(
                re.search(r"@RepositoryRestResource\b(?!\s*\([^)]*\bexported\s*=\s*false)",
                          clean_source, re.I)
                or re.search(r"\b(?:extends|:)\s*(?:[\w.]+\.)?"
                             r"(?:CrudRepository|JpaRepository|PagingAndSortingRepository|"
                             r"Repository)\s*<", clean_source))
            add("COMBO-DATA-REST-WITHOUT-SECURITY", data_rest,
                "HIGH" if repository else "MEDIUM",
                "Spring Data REST is present without Spring Security web/config. " +
                ("An export-capable repository was recognized." if repository else
                 "No export-capable repository was recognized."),
                "Restrict repository export and authorize Data REST endpoints.")
        web = next((by_artifact[name] for name in
                    ("spring-boot-starter-web", "spring-boot-starter-webmvc",
                     "spring-boot-starter-webflux", "spring-webmvc", "spring-webflux")
                    if name in by_artifact), None)
        if (web and not security and not actuator and not data_rest
                and re.search(r"@(?:RestController|EnableWebSecurity)\b", clean_source)):
            add("BOOT-WEB-WITHOUT-SECURITY", web, "MEDIUM",
                "Web runtime plus controller/security annotation without Spring Security web/config. "
                "Gateway or external authentication may still be intentional.",
                "Verify the effective authentication and authorization design.")
    return out




_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_base_score(vector: str) -> Optional[float]:
    """Computes the CVSS v3.0/3.1 base score from a vector string, per the
    official FIRST specification. Returns None if the vector is not a
    parseable CVSS v3 vector.

    This matters because OSV/GHSA advisories almost always carry the vector
    but not a numeric score. Without this, every such advisory collapses to
    one blanket severity, which makes the report far less useful for
    prioritising - a 'low' and a 'critical' would look identical."""
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None
    parts = dict()
    for chunk in vector.split("/")[1:]:
        if ":" in chunk:
            k, _, v = chunk.partition(":")
            parts[k.upper()] = v.upper()
    try:
        av = _CVSS3_AV[parts["AV"]]
        ac = _CVSS3_AC[parts["AC"]]
        ui = _CVSS3_UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_CVSS3_PR_C if scope_changed else _CVSS3_PR_U)[parts["PR"]]
        c = _CVSS3_CIA[parts["C"]]
        i = _CVSS3_CIA[parts["I"]]
        a = _CVSS3_CIA[parts["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)

    # CVSS 3.1 "roundup": smallest number to one decimal >= the value, done in
    # integer arithmetic to avoid float artefacts (as the spec prescribes).
    scaled = int(round(raw * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (int(scaled / 10000) + 1) / 10.0


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _osv_severity(vuln: dict) -> str:
    """Maps an OSV vulnerability record to our severity scale.

    Order of preference: the advisory's own normalized severity, then a bare
    numeric CVSS score, then a base score computed from the CVSS vector.
    Falls back to MEDIUM only when none of those are present, rather than
    over- or under-stating an unknown risk."""
    db_sev = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    mapping = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
              "MEDIUM": "MEDIUM", "LOW": "LOW"}
    if db_sev in mapping:
        return mapping[db_sev]
    for sev in vuln.get("severity") or []:
        score_field = str(sev.get("score", "")).strip()
        if re.fullmatch(r"\d+(?:\.\d+)?", score_field):
            return _score_to_severity(float(score_field))
        computed = cvss3_base_score(score_field)
        if computed is not None:
            return _score_to_severity(computed)
    return "MEDIUM"


def osv_check_build_files(build_files: List[str], root: str,
                          cache_read: Optional[Dict[str, dict]],
                          cache_write: Optional[Dict[str, dict]],
                          jobs: int = 8,
                          resolved: Sequence[ResolvedDependency] = (),
                          diagnostics: Optional[dict] = None,
                          offline_db=None) -> Tuple[List["Finding"], int, int, int, Optional[str]]:
    """Runs the OSV check across the given build files.

    cache_read (if not None): look packages up ONLY here - no network call is
    ever made, safe for air-gapped machines.
    cache_write (if not None): every live query's raw response is stored here
    under "group:artifact@version", so the caller can persist it to disk for
    later offline use.

    Live queries are deduplicated (a "group:artifact@version" seen in several
    build files - e.g. a multi-module Maven project's several pom.xml files -
    is only queried once) and, when there is more than one unique package to
    query, run in parallel via a thread pool - each request is independent
    I/O, so this is a straightforward, safe speed-up.

    Returns (findings, occurrences_checked, unique_packages_checked,
    packages_failed, first_error). Only attempted lookups count as failures.
    Optional diagnostics separately records skipped unresolved declarations and
    whether coverage is incomplete. packages_failed/first_error let the caller
    distinguish "OSV genuinely found nothing" from "every query failed" (no
    real internet access, a proxy/firewall, or osv.dev being unreachable) -
    both look identical from the finding count alone otherwise.
    """
    # Pass 1: collect every (file, group, artifact, version) occurrence.
    occurrences: List[Tuple[str, str, str, str]] = []
    unresolved = []
    build_contents: Dict[str, Tuple[str, List[str]]] = {}
    resolved_files = {os.path.abspath(d.build_file) for d in resolved}
    for bf in build_files:
        try:
            with open(bf, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(bf, root) if root else bf
        build_contents[rel] = (content, content.splitlines())
        if os.path.abspath(bf) not in resolved_files:
            unresolved.extend(f"{rel}: {row.group}:{row.artifact}" for row in _dependency_declarations(bf, content)
                              if not _coordinate_known(row.group, row.artifact) or row.reason or not _osv_version_is_concrete(row.version))
            for group, artifact, version in _osv_ecosystem_triples(bf, content):
                occurrences.append((rel, group, artifact, version))
    for item in resolved:
        rel = os.path.relpath(item.build_file, root) if root else item.build_file
        if not _osv_version_is_concrete(item.version):
            unresolved.append(f"{rel}: {item.group}:{item.artifact}")
            continue
        occurrences.append((rel, item.group, item.artifact, item.version))
    occurrences = list(dict.fromkeys(occurrences))

    # Pass 2: reduce to the unique packages that actually need a lookup.
    unique: Dict[str, Tuple[str, str, str]] = {}
    for _rel, group, artifact, version in occurrences:
        key = f"{group}:{artifact}@{version}"
        unique.setdefault(key, (group, artifact, version))

    results: Dict[str, Optional[dict]] = {}
    unresolved = list(dict.fromkeys(unresolved))
    failed = 0
    first_error: Optional[str] = None

    lookup_errors = {}
    if offline_db is not None:
        for key, (group, artifact, version) in unique.items():
            data, err = offline_db.query(group, artifact, version)
            results[key] = data
            if err is not None:
                failed += 1
                lookup_errors[key] = err
                if first_error is None:
                    first_error = f"{key}: {err}"
    elif cache_read is not None:
        for key in unique:
            cached = cache_read.get(key)
            if (isinstance(cached, dict) and not cached.get("next_page_token")
                    and isinstance(cached.get("vulns", []), list)
                    and all(isinstance(v, dict) for v in cached.get("vulns", []))):
                results[key] = cached
            else:
                results[key] = None
                failed += 1
                if first_error is None:
                    reason = "missing from" if key not in cache_read else "invalid entry in"
                    first_error = f"{key}: {reason} offline cache"
    else:
        def _fetch(item: Tuple[str, Tuple[str, str, str]]):
            key, (group, artifact, version) = item
            data, err = osv_query_online(group, artifact, _normalize_maven_version_for_osv(version))
            return key, data, err

        items = list(unique.items())
        if jobs > 1 and len(items) > 1:
            # Cap concurrency for OSV regardless of --jobs: --jobs is meant for
            # local file reading, where a high value is harmless. Pointing the
            # same number at a free public API is not - too many simultaneous
            # requests is what triggers rate limiting in the first place.
            osv_workers = min(jobs, len(items), OSV_MAX_CONCURRENCY)
            with concurrent.futures.ThreadPoolExecutor(max_workers=osv_workers) as pool:
                fetched = list(pool.map(_fetch, items))
        else:
            fetched = [_fetch(it) for it in items]

        for key, data, err in fetched:
            results[key] = data
            if err is not None:
                failed += 1
                if first_error is None:
                    first_error = f"{key}: {err}"
            if cache_write is not None:
                if err is None and data is not None:
                    cache_write[key] = data
                else:
                    # A failed refresh must not leave a stale success behind.
                    cache_write.pop(key, None)

    # Pass 3: expand the (deduplicated) results back out to every occurrence,
    # so each build file still gets its own finding for a shared dependency.
    out: List[Finding] = []
    for rel, group, artifact, version in occurrences:
        lookup_key = f"{group}:{artifact}@{version}"
        if lookup_key in lookup_errors:
            out.append(Finding(file=rel, line=1, rule_id="OSV-OFFLINE-UNRESOLVED",
                               rule_name="Offline advisory assessment incomplete", severity="MEDIUM",
                               status="REVIEW", code=lookup_key, note=lookup_errors[lookup_key],
                               fix="Review the listed advisory ranges; no safe-version conclusion was reached.",
                               fingerprint=fingerprint(rel, "OSV-OFFLINE-UNRESOLVED", lookup_key)))
        data = results.get(lookup_key)
        if not data:
            continue
        # OSV frequently returns several records describing the SAME issue -
        # typically a GHSA advisory plus the CVE it aliases. Reporting both
        # would double-count the same vulnerability for the same package, so
        # keep the first record of each alias group.
        seen_ids: Set[str] = set()
        for v in data.get("vulns") or []:
            vid = v.get("id", "UNKNOWN")
            # A withdrawn advisory is one the database itself retracted - it is
            # not a finding and must not be reported.
            if v.get("withdrawn"):
                continue
            id_group = {vid} | {str(a) for a in (v.get("aliases") or [])}
            if seen_ids & id_group:
                continue
            seen_ids |= id_group
            summary = (v.get("summary") or (v.get("details") or "")[:200]).strip()
            snippet = f"{group}:{artifact}:{version}"
            line_no = 1
            code = snippet
            content, raw_lines = build_contents.get(rel, ("", []))
            if rel.endswith(".xml"):
                block = _find_maven_dep_block(content, artifact)
                if block:
                    block_text, offset = block
                    artifact_offset = block_text.find(artifact)
                    position = offset + max(0, artifact_offset)
                    line_no = content.count("\n", 0, position) + 1
                    if 1 <= line_no <= len(raw_lines):
                        code = raw_lines[line_no - 1].strip()
            elif rel.endswith((".gradle", ".kts", ".toml")):
                declaration = _find_gradle_dep_line(raw_lines, artifact, version)
                if declaration:
                    code, line_no = declaration
            aliases = [a for a in (v.get("aliases") or []) if a != vid]
            note = summary or f"See https://osv.dev/vulnerability/{vid}"
            if offline_db is not None:
                note += " Offline Maven snapshot: " + offline_db.metadata.get("created_utc", "unknown") + "."
            if aliases:
                note += f" (also known as {', '.join(aliases[:3])})"
            out.append(Finding(
                file=rel, line=line_no, rule_id=f"OSV-{vid}",
                rule_name=f"OSV advisory {vid} for {group}:{artifact}",
                severity=_osv_severity(v), status="VULNERABLE", code=code,
                note=note,
                fix=f"Check {vid} at https://osv.dev/vulnerability/{vid} for the fixed version(s).",
                fingerprint=fingerprint(rel, f"OSV-{vid}", snippet)))
    if diagnostics is not None:
        diagnostics.update(unresolved=unresolved, successful=len(unique) - failed,
                           failed=failed, attempted=len(unique),
                           incomplete=bool(failed or unresolved))
    return out, len(occurrences), len(unique), failed, first_error





def analyze_props_file(path: str, root: str) -> List[Finding]:
    """Scans properties/YAML files for insecure Spring Boot configurations."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"[!] Cannot read {path}: {exc}", file=sys.stderr)
        return []
    rel = os.path.relpath(path, root) if root else path
    findings = []
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.lstrip()
        if stripped.startswith(("#", "!")):
            continue
        if SUPPRESS_MARKER.search(raw):
            continue
        for rid, pat, severity, note, fix in PROP_RULES:
            if not pat.search(raw):
                continue
            fp = hashlib.sha1(f"{rel}|{rid}|{raw.strip()}".encode("utf-8", "replace")).hexdigest()[:16]
            findings.append(Finding(
                file=rel, line=idx, rule_id=rid, rule_name=rid,
                severity=severity, status="ANTIPATTERN", code=raw.strip()[:200],
                note=note, fingerprint=fp, fix=fix,
                context=context_lines([l.rstrip("\n") for l in lines], idx),
            ))
    content = "".join(lines)
    if re.search(r"server\.ssl\.key-store-type\s*[=:]\s*PKCS12\b", content, re.I):
        empty = re.search(r"^\s*server\.ssl\.key-store-password\s*[=:]\s*(?:#.*)?$",
                          content, re.I | re.M)
        if empty:
            idx = content.count("\n", 0, empty.start()) + 1
            raw = lines[idx - 1].strip() if 1 <= idx <= len(lines) else "server.ssl.key-store-password="
            rid = "CERT-EMPTY-PKCS12-PASSWORD"
            findings.append(Finding(
                file=rel, line=idx, rule_id=rid, rule_name=rid,
                severity="HIGH", status="ANTIPATTERN", code=raw[:200],
                note="PKCS12 keystore is configured with an empty password.",
                fix=RULE_BY_ID[rid].fix, fingerprint=fingerprint(rel, rid, raw),
                context=context_lines([line.rstrip("\n") for line in lines], idx)))
    return findings


def walk_props(paths: Iterable[str], exclude: Set[str]) -> List[str]:
    files: List[str] = []
    for root_path in paths:
        if os.path.isfile(root_path):
            if root_path.endswith(PROP_EXTS):
                files.append(root_path)
            continue
        for root, dirs, names in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in exclude]
            for name in names:
                if name.endswith(PROP_EXTS) and any(
                        k in name for k in ("application", "security", "bootstrap",
                                            "management", "actuator")):
                    files.append(os.path.join(root, name))
    return sorted(files)


def walk(paths: Iterable[str], exts: Tuple[str, ...], exclude: Set[str],
         skip_tests: bool, want_builds: bool) -> Tuple[List[str], List[str]]:
    src: List[str] = []
    builds: List[str] = []
    for root_path in paths:
        if os.path.isfile(root_path):
            (builds if os.path.basename(root_path) in BUILD_FILES else src).append(root_path)
            continue
        for root, dirs, names in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in exclude]
            for name in names:
                full = os.path.join(root, name)
                if want_builds and name in BUILD_FILES:
                    builds.append(full)
                    continue
                if not name.endswith(exts):
                    continue
                if skip_tests and TEST_PATH.search(full):
                    continue
                src.append(full)
    return sorted(src), sorted(builds)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

COLORS = {
    # Pure black & white: no ANSI color codes, only text attributes, so it
    # looks the same regardless of the terminal's own color scheme.
    "CRITICAL": "\033[1;7m", "HIGH": "\033[1m", "MEDIUM": "\033[4m",
    "LOW": "\033[2m", "INFO": "\033[0m", "RESET": "\033[0m", "DIM": "\033[2m",
}


def colorize(text: str, key: str, enabled: bool) -> str:
    return f"{COLORS.get(key, '')}{text}{COLORS['RESET']}" if enabled else text


_VULN_CATEGORY_RULES: List[Tuple[str, str]] = [
    ("JWT-", "JWT"),
    ("JWE-", "JWT"),
    ("HARDEN-JWT-", "JWT"),          # keep JWT badge for hardening sub-group too
    ("OAUTH2-", "OAuth2/OIDC"), ("OIDC-", "OAuth2/OIDC"),
    ("DPOP-", "OAuth2/OIDC"), ("REFRESH-TOKEN-", "OAuth2/OIDC"),
    ("AUTHZ-", "Spring Security"), ("AUTH-", "Spring Security"),
    ("SECURITY-CONTROL-", "Security Coverage"),
    ("TENANT-CONTEXT-", "Security Coverage"),
    ("VALIDATION-COVERAGE-", "Security Coverage"),
    ("RATE-LIMIT-COVERAGE-", "Security Coverage"),
    ("AUDIT-COVERAGE-", "Security Coverage"),
    ("PASSWORD-", "Spring Security"), ("MFA-", "Spring Security"),
    ("TLS-", "TLS/Certificates"), ("CERT-", "TLS/Certificates"),
    ("HARDEN-", "Hardening"),
    ("XXE-", "XXE"), ("ANTI-", "XXE"),
    ("DESER-", "Deserialization"), ("SRC-DESER", "Deserialization"),
    ("SRC-FASTJSON", "Deserialization"),
    ("SRC-CRYPTO", "Weak crypto"),
    ("SRC-SPEL", "Injection"), ("SRC-CMD-EXEC", "Injection"), ("SRC-JNDI", "Injection"),
    ("SRC-SQLI", "Injection"), ("SRC-SSRF", "Injection"), ("SRC-PATH-TRAVERSAL", "Injection"),
    ("SRC-OPEN-REDIRECT", "Injection"), ("SRC-LDAP-INJECTION", "Injection"),
    ("SRC-CRLF", "Injection"), ("SRC-LOG-INJECTION", "Injection"),
    ("SRC-CORS-ORIGIN-REFLECTION", "Spring Security"),
    ("SRC-CROSSORIGIN", "Spring Security"),
    ("SpringSecurityCheck-", "Spring Security"),
    ("DEP-", "Dependency"),
    ("OSV-", "Dependency"),
    ("BUILD-", "Build hygiene"),
    ("SRC-", "Injection"),  # catch-all: any other SRC-* rule is an injection-class sink
]


def categorize_rule(rule_id: str) -> str:
    """Buckets a rule_id into a broad vulnerability-type category, used for the
    HTML report's type filter. Order matters: more specific prefixes first."""
    if "PROP" in rule_id:
        return "Configuration"
    for prefix, cat in _VULN_CATEGORY_RULES:
        if rule_id.startswith(prefix):
            return cat
    return "Other"


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))


def summary_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


_COVERAGE_COLUMNS = (
    ("authentication", "AuthN"), ("authorization", "AuthZ"),
    ("tenant", "Tenant"), ("validation", "Validation"),
    ("rate_limit", "Rate limit"), ("audit", "Audit"), ("path_resolution", "Path"))
_COVERAGE_MARK = {
    "COVERED": "OK", "MISSING": "MISSING", "UNKNOWN": "UNKNOWN",
    "NOT_REQUIRED": "N/A"}


def coverage_summary(entries: Sequence[CoverageEntry]) -> Dict[str, int]:
    counts = {"COVERED": 0, "MISSING": 0, "UNKNOWN": 0, "NOT_REQUIRED": 0}
    for entry in entries:
        for status in entry.controls.values():
            counts[status] = counts.get(status, 0) + 1
    return counts


def coverage_payload(entries: Sequence[CoverageEntry]) -> dict:
    return {
        "summary": coverage_summary(entries),
        "legend": {
            "COVERED": "Static control evidence is present on the recognized path; runtime enforcement requires review.",
            "MISSING": "A required control is not visible on the reachable path.",
            "UNKNOWN": "Static analysis cannot prove the control because configuration is dynamic or external.",
            "NOT_REQUIRED": "The control is not required for the identified processing path.",
        },
        "entries": [asdict(entry) for entry in entries],
        "attack_paths": coverage_attack_paths(entries),
    }


def print_coverage_text(entries: Sequence[CoverageEntry], output_format: str = "table") -> None:
    print("\nSecurity control coverage")
    print("=========================")
    if not entries:
        print("No supported HTTP, listener, or scheduled entry points were found.")
        return
    if output_format == "json":
        print(json.dumps(coverage_payload(entries), indent=2, ensure_ascii=False))
        return
    headers = ["Entry point"] + [label for _, label in _COVERAGE_COLUMNS]
    rows = []
    for entry in entries:
        rows.append([entry.entrypoint] + [
            _COVERAGE_MARK.get(entry.controls.get(key, "UNKNOWN"), "UNKNOWN")
            for key, _ in _COVERAGE_COLUMNS])
    widths = [min(64, max(len(headers[index]), *(len(row[index]) for row in rows)))
              for index in range(len(headers))]
    def render(row: Sequence[str]) -> str:
        cells = []
        for index, value in enumerate(row):
            clipped = value if len(value) <= widths[index] else value[:widths[index] - 1] + "…"
            cells.append(clipped.ljust(widths[index]))
        return " | ".join(cells)
    print(render(headers))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(render(row))
    counts = coverage_summary(entries)
    print("Coverage summary: " + "  ".join(
        f"{status}: {counts.get(status, 0)}"
        for status in ("COVERED", "MISSING", "UNKNOWN", "NOT_REQUIRED")))


def print_text(findings: List[Finding], scanned: int, builds: int, use_color: bool,
               show_fix: bool, coverage: Optional[Sequence[CoverageEntry]] = None,
               coverage_format: str = "table") -> None:
    print(f"JSpringGuard {VERSION} - {scanned} source file(s), {builds} build file(s), "
          f"{len(findings)} finding(s)\n")
    if not findings:
        print("No findings at the selected filters.")
        if coverage is not None:
            print_coverage_text(coverage, coverage_format)
        print(f"\nJSpringGuard v{VERSION} by {AUTHOR} - {REPO_URL}")
        return

    for f in sort_findings(findings):
        print(colorize(f"[{f.severity}] {f.rule_id} - {f.rule_name}  ({f.status})",
                       f.severity, use_color))
        loc = f"  {f.file}:{f.line}"
        if f.method:
            loc += f"  in {f.method}()"
        print(loc)
        for row in finding_context_text(f).splitlines():
            print(colorize("  " + row, "DIM", use_color))
        if f.variable:
            print(f"  Instance: {f.variable}")
        if f.guards_found:
            print(f"  Set: {', '.join(f.guards_found)}")
        if f.guards_missing:
            print("  Missing:")
            for g in f.guards_missing:
                print(f"    - {GUARD_HINTS.get(g, g)}")
        if f.taint:
            print(f"  External input in file: {', '.join(f.taint)}")
        if f.flow:
            print(f"  Flow: {' -> '.join(f.flow)}")
        if f.is_test:
            print("  (test code)")
        if f.note:
            print(f"  Note: {f.note}")
        print(f"  ID: {f.fingerprint}")
        if show_fix:
            fix_text = f.fix or (RULE_BY_ID[f.rule_id].fix if f.rule_id in RULE_BY_ID else "")
            if fix_text:
                print("  Fix:")
                for ln in fix_text.splitlines():
                    print(f"    {ln}")
        print()

    counts = summary_counts(findings)
    print("Summary: " + "  ".join(
        f"{k}: {counts[k]}" for k in reversed(SEVERITY_LIST) if k in counts))
    if coverage is not None:
        print_coverage_text(coverage, coverage_format)
    print(f"\nJSpringGuard v{VERSION} by {AUTHOR} - {REPO_URL}")


HTML_CSS = r"""

.context-hit{display:inline-block;min-width:100%;background:var(--warn-soft);font-weight:bold}
.source-context{white-space:pre;overflow-x:auto;max-height:420px;overflow-y:auto;border-radius:var(--r-sm)}
.report-menu{position:sticky;top:61px;z-index:30;display:flex;flex-wrap:wrap;gap:6px;margin:0 -2px 16px;padding:10px 2px;background:var(--bg);border-bottom:1px solid var(--line-soft)}
.report-menu-link{display:inline-flex;align-items:center;gap:7px;color:var(--dim);text-decoration:none;border:1px solid var(--line);background:var(--surface);border-radius:var(--r-md);padding:7px 12px;font-size:12px;font-weight:700;cursor:pointer}
.report-menu-link:hover{color:var(--text);background:var(--surface-2)}.report-menu-link.active{color:var(--accent);border-color:var(--accent-soft);background:var(--accent-soft)}
.report-menu-count{font:700 9.5px var(--mono);border:1px solid currentColor;border-radius:999px;padding:1px 6px;opacity:.8}
.report-menu-action{margin-left:auto;display:inline-flex;align-items:center;border:1px solid var(--accent-soft);background:var(--accent-soft);color:var(--accent);border-radius:var(--r-md);padding:7px 12px;font-size:11px;font-weight:800;cursor:pointer}.report-menu-action:hover{border-color:var(--accent);color:var(--text)}
body[data-report-view="findings"] .coverage-wrap{display:none}
body[data-report-view="flow"] .chips,body[data-report-view="flow"] .filter-row,body[data-report-view="flow"] .triage-bar,body[data-report-view="flow"] .flow-decision-findings,body[data-report-view="flow"] .card,body[data-report-view="flow"] .empty-note{display:none!important}
.coverage-wrap{margin:22px 0 28px;padding:18px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-lg)}
.coverage-title{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;margin-bottom:14px}
.coverage-wrap h2{margin:0 0 3px;font-size:17px}.coverage-subtitle{margin:0;color:var(--dim);font-size:12px}
.coverage-totals{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.coverage-total{font-size:10.5px;font-weight:700;border:1px solid var(--line);border-radius:999px;padding:3px 8px;white-space:nowrap}
.coverage-attack-section{margin:0 0 12px;border:1px solid var(--line);border-radius:var(--r-md);background:var(--bg);overflow:hidden}
.coverage-attack-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 12px;border-bottom:1px solid var(--line-soft)}
.coverage-attack-head h3{margin:0;font-size:12px;text-transform:uppercase;letter-spacing:.06em}.coverage-attack-head p{margin:2px 0 0;color:var(--faint);font-size:10.5px}
.coverage-attack-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;padding:10px}
.coverage-attack{border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:var(--r-sm);background:var(--surface);color:var(--text);padding:9px 10px;text-align:left;cursor:pointer;min-width:0}
.coverage-attack:hover{border-color:var(--accent)}.coverage-attack.CRITICAL{border-left-color:var(--critical)}.coverage-attack.HIGH{border-left-color:var(--danger)}.coverage-attack.MEDIUM{border-left-color:var(--warn)}
.coverage-attack-top{display:flex;align-items:center;gap:7px;margin-bottom:5px}.coverage-attack-score{font:800 10px var(--mono);border-radius:999px;padding:2px 6px;background:var(--surface-2)}
.coverage-attack-label{display:block;font:600 10.5px var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.coverage-attack-reason{display:block;color:var(--faint);font-size:9.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:3px}
.coverage-policy-tools{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin:0 0 12px;padding:9px 11px;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-md)}
.coverage-policy-tools-title{font-size:11px;color:var(--dim);margin-right:auto}.coverage-policy-action{border:1px solid var(--line);background:var(--surface);color:var(--accent);border-radius:var(--r-sm);padding:6px 9px;font-size:10.5px;font-weight:700;cursor:pointer}.coverage-policy-action:hover{border-color:var(--accent)}
.coverage-drift{display:none;margin:0 0 12px;border:1px solid var(--warn);border-radius:var(--r-md);background:var(--surface);overflow:hidden}.coverage-drift-head{display:flex;justify-content:space-between;gap:12px;padding:10px 12px;border-bottom:1px solid var(--line)}.coverage-drift-head h3{margin:0;font-size:12px;color:var(--warn)}.coverage-drift-summary{font:700 9.5px var(--mono);color:var(--warn)}.coverage-drift-list{display:flex;flex-direction:column;gap:7px;padding:10px}.coverage-drift-item{border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:var(--r-sm);padding:8px 10px;background:var(--surface-2)}.coverage-drift-item.degraded,.coverage-drift-item.removed{border-left-color:var(--danger)}.coverage-drift-item.improved,.coverage-drift-item.added{border-left-color:var(--keep)}.coverage-drift-entry{font:700 10.5px var(--mono)}.coverage-drift-change{display:block;color:var(--dim);font-size:10px;margin-top:3px}
.coverage-permission-section{margin:0 0 12px;border:1px solid var(--line);border-radius:var(--r-md);background:var(--surface);overflow:hidden}.coverage-permission-head{padding:10px 12px;border-bottom:1px solid var(--line)}.coverage-permission-head h3{margin:0;font-size:12px;text-transform:uppercase;letter-spacing:.06em}.coverage-permission-head p{margin:3px 0 0;color:var(--faint);font-size:10px}.coverage-permission-scroll{overflow:auto;max-height:310px}.coverage-permission-table{width:100%;border-collapse:collapse;min-width:620px}.coverage-permission-table th,.coverage-permission-table td{padding:7px 9px;border-bottom:1px solid var(--line-soft);font-size:10px;text-align:center;white-space:nowrap}.coverage-permission-table th:first-child,.coverage-permission-table td:first-child{text-align:left;position:sticky;left:0;background:var(--surface);z-index:1}.coverage-permission-yes{color:var(--keep);font-weight:800}.coverage-permission-no{color:var(--faint)}.coverage-permission-conditional{color:var(--warn);font-weight:800}
.flow-triage-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 12px;padding:9px 11px;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-md)}
.flow-triage-count{font-size:11px;color:var(--dim);margin-right:auto}.flow-triage-count b{color:var(--text)}
.flow-triage-action{border:1px solid var(--line);background:var(--surface);color:var(--dim);border-radius:var(--r-sm);padding:6px 9px;font-size:10.5px;font-weight:700;cursor:pointer}.flow-triage-action:hover{color:var(--text);border-color:var(--accent)}
.coverage-dashboard{display:grid;grid-template-columns:minmax(220px,28%) minmax(0,1fr);min-height:560px;border:1px solid var(--line);border-radius:var(--r-md);overflow:hidden;background:var(--bg)}
.coverage-sidebar{padding:12px;border-right:1px solid var(--line);background:var(--surface-2)}
.coverage-search,.coverage-flow-filter{width:100%;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-sm);color:var(--text);padding:8px 9px;font-size:12px;margin-bottom:8px}
.coverage-flow-filter{cursor:pointer}.coverage-filter-label{display:block;color:var(--faint);font-size:9.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;margin:2px 0 5px}
.coverage-entry-list{display:flex;flex-direction:column;gap:6px;max-height:510px;overflow:auto}
.coverage-entry{width:100%;border:1px solid transparent;background:transparent;color:var(--text);border-radius:var(--r-sm);padding:9px;text-align:left;cursor:pointer;display:grid;grid-template-columns:8px minmax(0,1fr);gap:8px;transition:background .12s,border-color .12s}
.coverage-entry:hover{background:var(--surface)}.coverage-entry.active{background:var(--surface);border-color:var(--accent-soft)}
.coverage-entry-dot{width:8px;height:8px;border-radius:50%;margin-top:5px;background:var(--faint)}
.coverage-entry-dot.GAP{background:var(--danger)}.coverage-entry-dot.REVIEW{background:var(--warn)}.coverage-entry-dot.COVERED{background:var(--keep)}
.coverage-entry-name{display:block;font:600 11.5px var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.coverage-entry-loc{display:block;color:var(--faint);font:10px var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:3px}
.coverage-entry-flow{display:inline-flex;margin-top:5px;border:1px solid var(--line);border-radius:999px;padding:1px 6px;color:var(--faint);font:800 8.5px var(--mono);letter-spacing:.04em}.coverage-entry-flow.HAS_FLOW{color:var(--accent);border-color:var(--accent-soft)}
.coverage-main{padding:16px;min-width:0}.coverage-overview{display:flex;align-items:flex-start;gap:10px;justify-content:space-between;margin-bottom:12px}
.coverage-overview h3{margin:0;font:700 14px var(--mono);overflow-wrap:anywhere}.coverage-overview p{margin:4px 0 0;color:var(--faint);font:10.5px var(--mono)}
.coverage-overview-actions{display:flex;align-items:center;gap:7px;flex-wrap:wrap;justify-content:flex-end}
.coverage-state{flex:none;font-size:10px;font-weight:800;letter-spacing:.04em;border-radius:999px;padding:4px 9px}
.coverage-state.GAP{background:var(--danger-soft);color:var(--danger)}.coverage-state.REVIEW{background:var(--warn-soft);color:var(--warn)}.coverage-state.COVERED{background:var(--keep-soft);color:var(--keep)}
.coverage-panel{border:1px solid var(--line);background:var(--surface);border-radius:var(--r-md);padding:12px;margin-bottom:10px;min-width:0}
.coverage-panel-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:9px}.coverage-panel-head h4{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--dim);margin:0}
.coverage-policy{display:grid;grid-template-columns:minmax(105px,.35fr) minmax(0,1fr);gap:8px 16px;font-size:11.5px}.coverage-policy dt{color:var(--faint)}.coverage-policy dd{margin:0;font-family:var(--mono);overflow-wrap:anywhere}
.coverage-flow{display:flex;align-items:stretch;gap:8px;overflow-x:auto;padding:3px 2px 9px}
.coverage-flow-node{flex:0 0 156px;min-height:83px;border:1px solid var(--line);border-top:3px solid var(--accent);border-radius:var(--r-sm);background:var(--surface-2);color:var(--text);padding:9px;text-align:left;cursor:pointer}
.coverage-flow-node:hover,.coverage-flow-node.active{border-color:var(--accent);background:var(--surface-3)}
.coverage-flow-node.SINK{border-top-color:var(--danger)}.coverage-flow-node.UNRESOLVED{border-top-color:var(--warn)}
.coverage-node-kind{display:block;color:var(--faint);font-size:9px;font-weight:800;letter-spacing:.06em;margin-bottom:5px}.coverage-node-label{display:block;font:600 10.5px var(--mono);overflow-wrap:anywhere}.coverage-node-loc{display:block;color:var(--faint);font:9px var(--mono);margin-top:6px;overflow-wrap:anywhere}
.coverage-arrow{flex:0 0 16px;align-self:center;color:var(--faint);font-size:18px;text-align:center}
.coverage-code-panel{padding:0;overflow:hidden}.coverage-code-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 12px;border-bottom:1px solid var(--line-soft)}
.coverage-code-title{margin:0;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--dim)}.coverage-code-location{font:10px var(--mono);color:var(--accent);overflow-wrap:anywhere;text-align:right}
.coverage-code-frame{margin:0;border:0;border-radius:0;background:#090b0f;max-height:330px;overflow:auto;padding:8px 0;color:#d8dce5}
:root[data-theme="light"] .coverage-code-frame{background:#f6f7fa;color:#222733}
.coverage-code-line{display:grid;grid-template-columns:52px minmax(max-content,1fr);min-width:100%;font:11px/1.55 var(--mono);white-space:pre}.coverage-code-line.hit{background:var(--warn-soft);box-shadow:inset 3px 0 0 var(--warn)}
.coverage-code-number{color:var(--faint);text-align:right;padding:0 11px 0 6px;border-right:1px solid var(--line-soft);user-select:none}.coverage-code-text{padding:0 12px}.coverage-code-empty{padding:18px;color:var(--faint);font-size:11px}
.coverage-source-links{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.coverage-source-link{border:1px solid var(--line);background:var(--surface);color:var(--accent);border-radius:999px;padding:3px 8px;font:10px var(--mono);cursor:pointer}.coverage-source-link:hover{border-color:var(--accent)}
.coverage-controls{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.coverage-control{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;border:1px solid var(--line);border-radius:var(--r-sm);background:var(--surface-2);color:var(--text);padding:8px 9px;text-align:left;cursor:pointer;font-size:11px}.coverage-control:hover,.coverage-control.active{border-color:var(--accent)}
.coverage-control-status{font:800 9.5px var(--mono)}.coverage-control-status.COVERED{color:var(--keep)}.coverage-control-status.MISSING{color:var(--danger)}.coverage-control-status.UNKNOWN{color:var(--warn)}.coverage-control-status.NOT_REQUIRED{color:var(--faint)}
.coverage-control-triage{font:800 8px var(--mono);border:1px solid var(--line);border-radius:999px;padding:1px 5px;color:var(--dim)}.coverage-control-triage.false-positive{color:var(--accent);border-color:var(--accent)}.coverage-control-triage.accepted-risk{color:var(--warn);border-color:var(--warn)}.coverage-control-triage.fixed{color:var(--keep);border-color:var(--keep)}.coverage-control-triage.confirmed{color:var(--danger);border-color:var(--danger)}
.coverage-detail{background:var(--surface-2)}.coverage-detail-title{font-weight:700;font-size:11.5px;margin-bottom:6px}.coverage-detail-list{margin:0;padding-left:17px;color:var(--dim);font-size:11px}.coverage-detail-list li{margin:4px 0;overflow-wrap:anywhere}.coverage-detail-empty{color:var(--faint);font-size:11px}
.coverage-explanation{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-bottom:10px}.coverage-explanation-card{border:1px solid var(--line);border-radius:var(--r-sm);background:var(--surface);padding:8px}.coverage-explanation-card.wide{grid-column:1/-1}.coverage-explanation-label{display:block;color:var(--faint);font-size:8.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px}.coverage-explanation-value{color:var(--dim);font-size:10.5px;overflow-wrap:anywhere}.coverage-confidence{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:1px 6px;font:800 8.5px var(--mono)}.coverage-confidence.HIGH{color:var(--keep);border-color:var(--keep)}.coverage-confidence.MEDIUM{color:var(--warn);border-color:var(--warn)}.coverage-confidence.REVIEW{color:var(--danger);border-color:var(--danger)}
.coverage-control-decision-panel{border-color:var(--accent-soft);box-shadow:inset 4px 0 0 var(--accent)}
.coverage-flow-triage-panel{border-color:var(--warn);box-shadow:inset 4px 0 0 var(--warn);background:linear-gradient(90deg,var(--warn-soft),var(--surface) 22%);margin-bottom:0}
.coverage-flow-triage-panel .coverage-panel-head h4{color:var(--warn)}
.coverage-flow-triage-fields{display:grid;grid-template-columns:minmax(175px,.35fr) minmax(220px,1fr);gap:8px}.coverage-flow-triage-field label{display:block;color:var(--faint);font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;margin:0 0 5px}.coverage-flow-decision,.coverage-flow-note{width:100%;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-sm);color:var(--text);padding:8px 9px;font-size:11px}.coverage-flow-decision{cursor:pointer}.coverage-flow-decision:hover,.coverage-flow-note:focus,.coverage-flow-decision:focus{border-color:var(--warn);outline:none}.coverage-flow-decision.confirmed{color:var(--danger);border-color:var(--danger)}.coverage-flow-decision.false-positive{color:var(--accent);border-color:var(--accent)}.coverage-flow-decision.accepted-risk{color:var(--warn);border-color:var(--warn)}.coverage-flow-decision.fixed{color:var(--keep);border-color:var(--keep)}
.coverage-control-triage-editor{display:grid;grid-template-columns:minmax(145px,.35fr) minmax(180px,1fr);gap:7px;margin-top:10px;padding-top:10px;border-top:1px dashed var(--line)}
.coverage-control-triage-editor label{grid-column:1/-1;color:var(--faint);font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase}.coverage-control-triage-editor select,.coverage-control-triage-editor input{width:100%;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-sm);color:var(--text);padding:7px 8px;font-size:11px}.coverage-control-triage-editor select{cursor:pointer}
.coverage-reference-panel{background:var(--surface-2)}.coverage-reference-list{display:flex;flex-direction:column;gap:7px}.coverage-reference-item{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:5px 10px;border:1px solid var(--line);border-radius:var(--r-sm);background:var(--surface);padding:8px 9px}.coverage-reference-entry{border:0;background:transparent;color:var(--accent);font:600 10.5px var(--mono);text-align:left;padding:0;cursor:pointer;overflow-wrap:anywhere}.coverage-reference-entry:hover{text-decoration:underline}.coverage-reference-policy{font:800 8.5px var(--mono);color:var(--dim)}.coverage-reference-path{grid-column:1/-1;color:var(--faint);font-size:9.5px;overflow-wrap:anywhere}.coverage-reference-rules{grid-column:1/-1;display:flex;gap:5px;flex-wrap:wrap;margin-top:2px}
.coverage-matrix{margin-top:12px;border:1px solid var(--line-soft);border-radius:var(--r-sm);overflow:hidden}.coverage-matrix>summary{cursor:pointer;color:var(--dim);font-size:11px;font-weight:600;padding:8px 10px}.coverage-matrix-scroll{overflow-x:auto;border-top:1px solid var(--line-soft)}
.coverage-table{width:100%;border-collapse:collapse;min-width:820px}
.coverage-table th,.coverage-table td{padding:8px 10px;border-bottom:1px solid var(--line-soft);text-align:left;font-size:12px}
.coverage-table th{color:var(--dim);font-weight:600}.coverage-table code{white-space:nowrap}
.cov-COVERED{color:var(--keep);font-weight:700}.cov-MISSING{color:var(--danger);font-weight:700}
.cov-UNKNOWN{color:var(--warn);font-weight:700}.cov-NOT_REQUIRED{color:var(--faint)}
@media (max-width:820px){.coverage-dashboard{grid-template-columns:1fr}.coverage-sidebar{border-right:0;border-bottom:1px solid var(--line)}.coverage-entry-list{max-height:210px}.coverage-controls,.coverage-attack-list,.coverage-flow-triage-fields,.coverage-explanation{grid-template-columns:1fr}.coverage-explanation-card.wide{grid-column:auto}.coverage-title{display:block}.coverage-totals{justify-content:flex-start;margin-top:10px}.coverage-control-triage-editor{grid-template-columns:1fr}}

:root{
color-scheme:dark;
--bg:#0b0d11;--surface:#13161d;--surface-2:#1a1e27;--surface-3:#222734;
--line:#262b36;--line-soft:#1c212a;--text:#e9ebf1;--dim:#98a0b1;--faint:#616978;
--accent:#6bb9ff;--accent-ink:#04202f;--accent-soft:#1d3a52;
--keep:#5fd3a0;--keep-soft:#16382c;
--warn:#f3b464;--warn-soft:#3f2f1a;
--danger:#f0716a;--danger-soft:#42221f;
--critical:#ff5a68;--critical-soft:#3a1418;--critical-ink:#2a0507;
--topbar-bg:rgba(11,13,17,.86);--bg-glow:#1b2c4630;
--r-lg:14px;--r-md:10px;--r-sm:7px;
--shadow:0 1px 2px rgba(0,0,0,.4),0 14px 34px -22px rgba(0,0,0,.9);
--mono:ui-monospace,'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
--sans:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
--topbar:61px;
}
:root[data-theme="light"]{
color-scheme:light;
--bg:#f4f5f8;--surface:#ffffff;--surface-2:#eef0f4;--surface-3:#e3e6ed;
--line:#d7dbe3;--line-soft:#e6e9ef;--text:#1b1e26;--dim:#5a6272;--faint:#828a9a;
--accent:#1c73c9;--accent-ink:#ffffff;--accent-soft:#d8e9fa;
--keep:#1c8a5c;--keep-soft:#dcf3e8;
--warn:#9a6208;--warn-soft:#fbedd4;
--danger:#c53a33;--danger-soft:#fbe0dd;
--critical:#c81e2c;--critical-soft:#fbdadc;--critical-ink:#ffffff;
--topbar-bg:rgba(255,255,255,.86);--bg-glow:#1c73c920;
--shadow:0 1px 2px rgba(20,25,40,.06),0 14px 34px -22px rgba(20,25,40,.18);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.5;
-webkit-font-smoothing:antialiased;min-height:100vh;transition:background .15s,color .15s}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
background:radial-gradient(900px 480px at 18% -18%,var(--bg-glow),transparent 70%)}
button{font-family:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.shell{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:0 24px 96px}
.topbar{position:sticky;top:0;z-index:40;background:var(--topbar-bg);backdrop-filter:blur(14px);
-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line-soft)}
.topbar-inner{max-width:1100px;margin:0 auto;padding:11px 24px;display:flex;align-items:center;gap:16px}
.brand{display:flex;align-items:center;gap:9px;flex:none}
.brand .mark{width:9px;height:9px;border-radius:2px;background:var(--accent);box-shadow:0 0 12px var(--accent)}
.brand h1{margin:0;font-size:14.5px;font-weight:700;letter-spacing:.01em}
.brand .version{font-size:10.5px;font-family:var(--mono);color:var(--dim);background:var(--surface-2);
border:1px solid var(--line);border-radius:999px;padding:2px 8px}
.brand-repo{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;color:var(--faint);
text-decoration:none;padding:3px 8px;border-radius:var(--r-sm);transition:color .12s,background .12s}
.brand-repo svg{width:14px;height:14px}
.brand-repo:hover{color:var(--accent);background:var(--surface-2)}
@media (max-width:760px){.brand-repo span{display:none}}
.topbar-meta{color:var(--faint);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topbar-actions{margin-left:auto;display:flex;align-items:center;gap:10px;flex:none}
.theme-toggle{background:var(--surface-2);border:1px solid var(--line);color:var(--dim);cursor:pointer;
flex:none;width:34px;height:34px;display:grid;place-items:center;border-radius:var(--r-md);padding:0;
transition:all .12s}
.theme-toggle:hover{color:var(--text);border-color:var(--accent-soft);background:var(--surface-3)}
.theme-toggle svg{width:17px;height:17px;display:block}
.theme-toggle .icon-sun{display:none}
:root[data-theme="light"] .theme-toggle .icon-moon{display:none}
:root[data-theme="light"] .theme-toggle .icon-sun{display:block}
.chips{display:flex;gap:0;border:1px solid var(--line);border-radius:var(--r-md);overflow:hidden;
background:var(--surface);margin:18px 0}
.chips div{flex:1;padding:10px 8px;border-right:1px solid var(--line-soft);text-align:center;
cursor:pointer;transition:background .12s}
.chips div:hover{background:var(--surface-2)}
.chips div.active{background:var(--surface-3);box-shadow:inset 0 -2px 0 var(--accent)}
.chips div.zero{opacity:.45}
.chips div:last-child{border-right:none}
.chips .num{display:block;font-size:18px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums;
line-height:1.2}
.chips .num.critical{color:var(--critical)}.chips .num.high{color:var(--danger)}
.chips .num.medium{color:var(--warn)}.chips .num.low{color:var(--accent)}
.chips .lbl{display:block;font-size:9.5px;color:var(--faint);letter-spacing:.07em;text-transform:uppercase;
margin-top:2px;font-weight:700}
.search-input{width:100%;background:var(--surface-2);border:1px solid var(--line);color:var(--text);
border-radius:var(--r-sm);padding:10px 13px;font-size:13px;font-family:var(--sans);
transition:border-color .12s}
.search-input::placeholder{color:var(--faint)}
.search-input:focus{outline:none;border-color:var(--accent)}
.filter-row{display:flex;gap:10px;margin:0 0 18px}
.filter-row .search-input{flex:1;min-width:0}
.type-filter{flex:none;background:var(--surface-2);color:var(--text);border:1px solid var(--line);
border-radius:var(--r-sm);padding:10px 12px;font-size:13px;font-family:var(--sans);cursor:pointer;
max-width:220px}
.type-filter:hover{border-color:var(--accent-soft)}
.type-filter:focus{outline:none;border-color:var(--accent)}
.type-filter option{color:var(--text);background:var(--surface-2)}
.mini-btn{flex:none;display:inline-flex;align-items:center;justify-content:center;
background:var(--surface-2);border:1px solid var(--line);color:var(--dim);
font-size:12.5px;font-weight:600;padding:10px 14px;border-radius:var(--r-sm);cursor:pointer;
white-space:nowrap;transition:all .12s}
.mini-btn:hover{color:var(--text);border-color:var(--accent-soft);background:var(--surface-3)}
@media (max-width:560px){.filter-row{flex-wrap:wrap}.type-filter{max-width:none;width:100%}
.mini-btn{width:100%}}
.empty-note{color:var(--faint);font-size:13px;text-align:center;padding:40px 12px}
.triage{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:12px;
padding-top:10px;border-top:1px dashed var(--line-soft)}
.triage label{font-size:11px;color:var(--faint);letter-spacing:.04em;text-transform:uppercase;
font-weight:700}
.triage-status{background:var(--surface-2);color:var(--text);border:1px solid var(--line);
border-radius:var(--r-sm);padding:5px 9px;font-size:12px;font-family:var(--sans);cursor:pointer}
.triage-status:focus{outline:none;border-color:var(--accent)}
.triage-status option{color:var(--text);background:var(--surface-2)}
.triage-note{flex:1;min-width:160px;background:var(--surface-2);color:var(--text);
border:1px solid var(--line);border-radius:var(--r-sm);padding:5px 9px;font-size:12px;
font-family:var(--sans)}
.triage-note::placeholder{color:var(--faint)}
.triage-note:focus{outline:none;border-color:var(--accent)}
.triage-saved{font-size:11px;color:var(--keep);opacity:0;transition:opacity .2s}
.triage-saved.show{opacity:1}
/* A triaged finding is dimmed so untouched ones stand out while working. */
.card.triaged{opacity:.62}
.card.triaged:hover{opacity:1}
.badge.st{border:1px solid var(--line);background:transparent;color:var(--dim);
text-transform:none;letter-spacing:0;font-weight:600}
.badge.st[data-st="fixed"]{color:var(--keep);border-color:var(--keep)}
.badge.st[data-st="false-positive"]{color:var(--accent);border-color:var(--accent)}
.badge.st[data-st="accepted"]{color:var(--warn);border-color:var(--warn)}
.badge.st[data-st="in-review"]{color:var(--dim);border-color:var(--dim)}
.triage-bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 18px;
padding:10px 12px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-md)}
.triage-bar .count{font-size:12px;color:var(--dim);margin-right:auto}
.triage-bar .count b{color:var(--text)}
.flow-decision-summary{display:none;align-items:center;gap:7px;flex-wrap:wrap;margin:-8px 0 18px;
padding:9px 12px;background:var(--surface);border:1px solid var(--accent-soft);border-radius:var(--r-md);box-shadow:inset 4px 0 0 var(--accent)}
.flow-decision-summary-label{font-size:10.5px;color:var(--dim);margin-right:2px}
.flow-decision-summary button{border:1px solid var(--line);background:var(--surface-2);color:var(--dim);border-radius:999px;padding:4px 9px;font:700 9.5px var(--mono);cursor:pointer}
.flow-decision-summary button:hover,.flow-decision-summary button.active{border-color:var(--accent);color:var(--text);background:var(--accent-soft)}
.flow-decision-summary button.false-positive{color:var(--accent)}
.flow-decision-summary button.confirmed{color:var(--danger)}
.flow-decision-summary button.accepted-risk{color:var(--warn)}
.flow-decision-summary button.fixed{color:var(--keep)}
.flow-decision-findings{display:none;margin:0 0 18px;padding:12px;background:var(--surface);border:1px solid var(--accent-soft);border-radius:var(--r-md);box-shadow:inset 4px 0 0 var(--accent)}
.flow-decision-findings-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:9px}.flow-decision-findings-head h2{font-size:12px;margin:0;text-transform:uppercase;letter-spacing:.06em;color:var(--accent)}.flow-decision-findings-head p{margin:2px 0 0;color:var(--faint);font-size:10.5px}.flow-decision-findings-count{font:800 9.5px var(--mono);color:var(--accent);border:1px solid var(--accent-soft);border-radius:999px;padding:2px 7px;white-space:nowrap}
.flow-decision-findings-list{display:flex;flex-direction:column;gap:7px}.flow-decision-record{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:5px 10px;padding:9px 10px;background:var(--surface-2);border:1px solid var(--line);border-left:4px solid var(--dim);border-radius:var(--r-sm)}.flow-decision-record.false-positive{border-left-color:var(--accent)}.flow-decision-record.accepted-risk{border-left-color:var(--warn)}.flow-decision-record.fixed{border-left-color:var(--keep)}.flow-decision-record.confirmed{border-left-color:var(--danger)}
.flow-decision-record-title{font:700 11px var(--mono);overflow-wrap:anywhere}.flow-decision-record-status{font:800 9px var(--mono);text-transform:uppercase;color:var(--dim)}.flow-decision-record-status.false-positive{color:var(--accent)}.flow-decision-record-status.accepted-risk{color:var(--warn)}.flow-decision-record-status.fixed{color:var(--keep)}.flow-decision-record-status.confirmed{color:var(--danger)}.flow-decision-record-meta,.flow-decision-record-note{grid-column:1/-1;color:var(--faint);font-size:10px;overflow-wrap:anywhere}.flow-decision-record-note{color:var(--dim)}.flow-decision-record-open{grid-column:1/-1;justify-self:start;border:1px solid var(--accent-soft);background:transparent;color:var(--accent);border-radius:999px;padding:3px 8px;font:700 9.5px var(--mono);cursor:pointer}.flow-decision-record-open:hover{border-color:var(--accent);color:var(--text)}
.card{background:var(--surface);border:1px solid var(--line);border-left-width:4px;border-radius:var(--r-lg);
box-shadow:var(--shadow);padding:16px 18px;margin:0 0 14px}
.card.CRITICAL{border-left-color:var(--critical);box-shadow:var(--shadow),0 0 0 1px var(--critical-soft) inset}
.card.HIGH{border-left-color:var(--danger)}
.card.MEDIUM{border-left-color:var(--warn)}.card.LOW{border-left-color:var(--accent)}
.card.INFO{border-left-color:var(--faint)}
.card-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:8px}
.badge{display:inline-flex;align-items:center;font-size:10px;font-weight:700;letter-spacing:.03em;
padding:3px 9px;border-radius:999px;text-transform:uppercase;flex:none}
.badge.CRITICAL{background:var(--critical);color:var(--critical-ink);font-weight:800}
.badge.HIGH{background:var(--danger-soft);color:var(--danger)}
.badge.MEDIUM{background:var(--warn-soft);color:var(--warn)}
.badge.LOW{background:var(--accent-soft);color:var(--accent)}
.badge.INFO{background:var(--surface-3);color:var(--faint)}
.badge.type-badge{background:transparent;color:var(--dim);border:1px solid var(--line);
font-weight:600;text-transform:none;letter-spacing:0}
.card-title{font-weight:700;color:var(--text);font-size:13.5px}
.card-status{color:var(--faint);font-size:12px;font-style:italic}
.loc{color:var(--faint);font-size:12px;font-family:var(--mono);margin-bottom:8px}
pre{background:var(--surface-2);border:1px solid var(--line-soft);border-radius:var(--r-sm);
padding:10px 12px;overflow-x:auto;font-size:12px;font-family:var(--mono);margin:8px 0;color:var(--text)}
code{background:var(--surface-2);border-radius:5px;padding:2px 6px;font-size:.9em;font-family:var(--mono);
color:var(--accent)}
.meta-line{color:var(--dim);font-size:12.5px;margin:6px 0}
.meta-line b{color:var(--text)}
ul.missing{margin:6px 0 6px 0;padding-left:0;list-style:none}
ul.missing li{font-size:12px;color:var(--dim);padding:3px 0 3px 16px;position:relative}
ul.missing li::before{content:'—';position:absolute;left:0;color:var(--warn)}
.fp{display:inline-block;font-family:var(--mono);font-size:10.5px;color:var(--faint);background:var(--surface-2);
border:1px solid var(--line);border-radius:999px;padding:2px 8px;margin-top:6px}
details.fix{border:1px solid var(--line-soft);background:var(--surface-2);border-radius:var(--r-md);
margin-top:10px}
details.fix>summary{list-style:none;cursor:pointer;padding:8px 12px;font-size:12px;color:var(--dim);
font-weight:600;display:flex;align-items:center;gap:7px}
details.fix>summary::-webkit-details-marker{display:none}
details.fix>summary::before{content:'▸';color:var(--faint);font-size:10px;transition:transform .15s}
details.fix[open]>summary::before{transform:rotate(90deg)}
details.fix pre{margin:0 12px 12px}
.site-foot{margin-top:34px;padding-top:16px;border-top:1px solid var(--line-soft);font-size:12px;
color:var(--faint);text-align:center;line-height:1.7}
.site-foot a{color:var(--dim);text-decoration:none;border-bottom:1px solid transparent}
.site-foot a:hover{color:var(--accent);border-color:var(--accent-soft)}
@media (max-width:640px){.shell{padding:0 14px 80px}.topbar-inner{padding:10px 14px}
.topbar-meta{display:none}.chips{flex-wrap:wrap}.chips div{min-width:33%}}

"""

HTML_JS = r"""

(function(){
"use strict";
var KEY='securityCheckTheme';
function apply(t){
  if(t==='light') document.documentElement.setAttribute('data-theme','light');
  else document.documentElement.removeAttribute('data-theme');
  var btn=document.getElementById('themeToggle');
  if(btn) btn.setAttribute('aria-label', t==='light' ? 'Switch to dark theme' : 'Switch to light theme');
}
var theme='dark';
try{ var saved=localStorage.getItem(KEY); if(saved==='light'||saved==='dark') theme=saved; }catch(e){}
apply(theme);
var toggle=document.getElementById('themeToggle');
if(toggle) toggle.addEventListener('click', function(){
  theme = theme==='light' ? 'dark' : 'light';
  apply(theme);
  try{ localStorage.setItem(KEY, theme); }catch(e){}
});

/* ---- Report views ----------------------------------------------------- */
var reportViewLinks=document.querySelectorAll('[data-report-view-target]');
function setReportView(view, updateHash){
  if(view!=='flow') view='findings';
  document.body.setAttribute('data-report-view',view);
  reportViewLinks.forEach(function(link){
    var active=link.getAttribute('data-report-view-target')===view;
    link.classList.toggle('active',active);
    link.setAttribute('aria-selected',active?'true':'false');
  });
  if(updateHash && window.history && history.replaceState){
    history.replaceState(null,'',view==='flow'?'#security-flow':'#findings');
  }
}
reportViewLinks.forEach(function(link){
  link.addEventListener('click',function(event){
    event.preventDefault();
    setReportView(link.getAttribute('data-report-view-target'),true);
  });
});
setReportView(location.hash==='#security-flow'?'flow':'findings',false);
var search=document.getElementById('findingSearch');
var typeFilter=document.getElementById('typeFilter');
var sevFilter=document.getElementById('severityFilter');
var statusFilter=document.getElementById('statusFilter');
var chips=document.getElementById('sevChips');
function applyFilters(){
  var q = search ? search.value.toLowerCase() : '';
  var t = typeFilter ? typeFilter.value : '';
  var s = sevFilter ? sevFilter.value : '';
  var st = statusFilter ? statusFilter.value : '';
  var cards=document.querySelectorAll('.card');
  var shown=0;
  cards.forEach(function(c){
    var textHit = c.getAttribute('data-search').indexOf(q) !== -1;
    var typeHit = !t || c.getAttribute('data-type') === t;
    var sevHit = !s || c.classList.contains(s);
    var cardStatus = c.getAttribute('data-status') || '';
    var statusHit = !st || (st === '__open' ? cardStatus === '' : cardStatus === st);
    var hit = textHit && typeHit && sevHit && statusHit;
    c.style.display = hit ? '' : 'none';
    if(hit) shown++;
  });
  renderFlowDecisionSummary();
  var flowShown=renderFlowDecisionFindings(st,q,t,s);
  var note=document.getElementById('noMatch');
  if(note) note.style.display = (shown + flowShown)===0 ? '' : 'none';
  if(chips){
    chips.querySelectorAll('div').forEach(function(d){
      d.classList.toggle('active', d.getAttribute('data-sev') === s && s !== '');
    });
  }
}
if(search) search.addEventListener('input', applyFilters);
if(typeFilter) typeFilter.addEventListener('change', applyFilters);
if(sevFilter) sevFilter.addEventListener('change', applyFilters);
if(statusFilter) statusFilter.addEventListener('change', applyFilters);
if(chips) chips.querySelectorAll('div').forEach(function(d){
  d.addEventListener('click', function(){
    var sev = d.getAttribute('data-sev');
    if(sevFilter) sevFilter.value = (sevFilter.value === sev) ? '' : sev;
    applyFilters();
  });
});
var toggleFixes=document.getElementById('toggleFixes');
if(toggleFixes) toggleFixes.addEventListener('click', function(){
  var details = document.querySelectorAll('.card details.fix');
  var anyClosed = Array.prototype.some.call(details, function(d){ return !d.open; });
  details.forEach(function(d){ d.open = anyClosed; });
  toggleFixes.textContent = anyClosed ? 'Collapse all fixes' : 'Expand all fixes';
});

/* ---- Interactive security-flow explorer ----------------------------- */
var coverageDataNode=document.getElementById('coverageData');
var coverageEntries=[];
var coveragePayload={};
var coverageAttackPaths=[];
try{
  coveragePayload=coverageDataNode ? JSON.parse(coverageDataNode.textContent) : {};
  coverageEntries=coveragePayload.entries || [];
  coverageAttackPaths=coveragePayload.attack_paths || [];
}catch(e){ coveragePayload={}; coverageEntries=[]; coverageAttackPaths=[]; }
var coverageSelected=0;
var coverageSelectedControl='';
var coverageLabels={authentication:'Authentication',authorization:'Authorization',
  tenant:'Tenant binding',validation:'Input validation',rate_limit:'Rate limiting',
  audit:'Security audit',path_resolution:'Path resolution',__flow__:'Complete flow'};
var coverageOrder=['authentication','authorization','tenant','validation',
                   'rate_limit','audit','path_resolution'];
var FLOW_TKEY='jspringguardFlowTriage';
var flowTriage={};
try{ flowTriage=JSON.parse(localStorage.getItem(FLOW_TKEY) || '{}') || {}; }catch(e){ flowTriage={}; }
var flowTriageLabels={'confirmed':'Confirmed','false-positive':'False Positive',
                      'accepted-risk':'Accepted Risk','fixed':'Fixed'};

function coverageElement(tag, className, textValue){
  var node=document.createElement(tag);
  if(className) node.className=className;
  if(textValue!==undefined) node.textContent=String(textValue);
  return node;
}
function coverageClear(node){ while(node && node.firstChild) node.removeChild(node.firstChild); }
function coverageControlKey(entry,control){
  var stable=[entry.file || '',entry.entrypoint || '',entry.method || '',control || ''].join('::');
  var legacy=[entry.file || '',entry.line || 0,entry.entrypoint || '',control || ''].join('::');
  if(!flowTriage[stable] && flowTriage[legacy]) flowTriage[stable]=flowTriage[legacy];
  return stable;
}
function currentFlowTriageRecords(){
  var records=[];
  coverageEntries.forEach(function(entry,index){
    var controls=['__flow__'];
    coverageOrder.forEach(function(control){
      if(Object.prototype.hasOwnProperty.call(entry.controls || {},control)) controls.push(control);
    });
    controls.forEach(function(control){
      var key=coverageControlKey(entry,control);
      var decision=flowTriage[key] || {};
      if(decision.status || decision.note){
        records.push({key:key,entry:entry,entryIndex:index,control:control,decision:decision});
      }
    });
  });
  return records;
}
function renderFlowDecisionSummary(){
  var host=document.getElementById('flowDecisionSummary');
  if(!host) return;
  coverageClear(host);
  var records=currentFlowTriageRecords();
  if(!records.length){ host.style.display='none'; return; }
  host.style.display='flex';
  host.appendChild(coverageElement('span','flow-decision-summary-label',
    'Flow/control decisions — quick filter:'));
  var counts={'false-positive':0,'confirmed':0,'accepted-risk':0,'fixed':0};
  records.forEach(function(record){
    var status=(record.decision || {}).status || '';
    if(Object.prototype.hasOwnProperty.call(counts,status)) counts[status]++;
  });
  [['','all','All',records.length],
   ['false-positive','false-positive','False Positive',counts['false-positive']],
   ['confirmed','confirmed','Confirmed',counts.confirmed],
   ['accepted','accepted-risk','Accepted Risk',counts['accepted-risk']],
   ['fixed','fixed','Fixed',counts.fixed]]
    .forEach(function(item){
      var button=coverageElement('button',item[1],item[2] + ' ' + item[3]);
      button.type='button';
      button.classList.toggle('active',Boolean(statusFilter) && statusFilter.value===item[0]);
      button.addEventListener('click',function(){
        if(statusFilter) statusFilter.value=item[0];
        if(typeFilter) typeFilter.value='';
        if(sevFilter) sevFilter.value='';
        applyFilters();
      });
      host.appendChild(button);
    });
}
function flowDecisionStatusMatches(status,filter){
  if(!filter) return true;
  if(filter==='__open') return !status;
  if(filter==='accepted') return status==='accepted-risk';
  return status===filter;
}
function openFlowTriageRecord(record){
  setReportView('flow',true);
  renderCoverageEntry(record.entryIndex);
  var target=null;
  if(record.control==='__flow__') target=document.querySelector('.coverage-flow-triage-panel');
  else{
    var control=document.querySelector('#coverageControls [data-control="' + record.control + '"]');
    if(control){ control.click(); target=document.getElementById('coverageDetail'); }
  }
  if(target) target.scrollIntoView({behavior:'smooth',block:'center'});
}
function renderFlowDecisionFindings(statusFilterValue,query,typeValue,severityValue){
  var host=document.getElementById('flowDecisionFindings');
  var list=document.getElementById('flowDecisionFindingsList');
  var count=document.getElementById('flowDecisionFindingsCount');
  if(!host || !list) return 0;
  coverageClear(list);
  var normalized=(query || '').toLowerCase();
  var records=currentFlowTriageRecords().filter(function(record){
    var decision=record.decision || {};
    if(!flowDecisionStatusMatches(decision.status || '',statusFilterValue || '')) return false;
    if(typeValue || severityValue) return false;
    var searchable=[record.entry.entrypoint,record.entry.file,
      coverageLabels[record.control] || record.control,decision.note || '',decision.status || '']
      .join(' ').toLowerCase();
    return !normalized || searchable.indexOf(normalized)!==-1;
  });
  records.forEach(function(record){
    var decision=record.decision || {};
    var status=decision.status || '';
    var item=coverageElement('div','flow-decision-record' + (status?' ' + status:''));
    item.appendChild(coverageElement('div','flow-decision-record-title',record.entry.entrypoint));
    item.appendChild(coverageElement('span','flow-decision-record-status' +
      (status?' ' + status:''),status ? (flowTriageLabels[status] || status) : 'Open / untriaged'));
    var subject=record.control==='__flow__' ? 'Complete flow' :
      'Control: ' + (coverageLabels[record.control] || record.control);
    item.appendChild(coverageElement('div','flow-decision-record-meta',subject + ' · ' +
      coverageLocation(record.entry)));
    if(decision.note) item.appendChild(coverageElement('div','flow-decision-record-note',
      'Note: ' + decision.note));
    var open=coverageElement('button','flow-decision-record-open','Open in Security Flow Explorer');
    open.type='button'; open.addEventListener('click',function(){ openFlowTriageRecord(record); });
    item.appendChild(open); list.appendChild(item);
  });
  /* The stylesheet hides this section by default.  Use an explicit display
     value when records exist; clearing the inline value would leave the
     stylesheet's display:none in force. */
  host.style.display=records.length?'block':'none';
  if(count) count.textContent=records.length + ' decision' + (records.length===1?'':'s');
  return records.length;
}
function saveFlowTriage(){
  try{ localStorage.setItem(FLOW_TKEY,JSON.stringify(flowTriage)); }catch(e){}
}
function updateFlowTriageCount(){
  var relevant=[];
  coverageEntries.forEach(function(entry){
    relevant.push(coverageControlKey(entry,'__flow__'));
    coverageOrder.forEach(function(control){
      if(Object.prototype.hasOwnProperty.call(entry.controls || {},control))
        relevant.push(coverageControlKey(entry,control));
    });
  });
  var count=relevant.filter(function(key){
    var item=flowTriage[key] || {}; return Boolean(item.status || item.note);
  }).length;
  var node=document.getElementById('flowTriageCount');
  if(node) node.innerHTML='Triaged <b>' + count + '</b> of <b>' + relevant.length +
    '</b> flow/control decisions';
  renderFlowDecisionSummary();
}
function updateControlTriageBadge(button,entry,control){
  if(!button) return;
  var old=button.querySelector('.coverage-control-triage');
  if(old) old.remove();
  var decision=flowTriage[coverageControlKey(entry,control)] || {};
  if(decision.status){
    button.appendChild(coverageElement('span','coverage-control-triage ' + decision.status,
      flowTriageLabels[decision.status] || decision.status));
  }
}
function updateFlowDecision(entry){
  var select=document.getElementById('coverageFlowDecision');
  var note=document.getElementById('coverageFlowDecisionNote');
  if(!select || !entry) return;
  var decision=flowTriage[coverageControlKey(entry,'__flow__')] || {};
  select.className='coverage-flow-decision' + (decision.status?' ' + decision.status:'');
  select.value=decision.status || '';
  if(note) note.value=decision.note || '';
}
function persistCompleteFlowDecision(entry){
  var select=document.getElementById('coverageFlowDecision');
  var note=document.getElementById('coverageFlowDecisionNote');
  if(!select || !entry) return;
  var key=coverageControlKey(entry,'__flow__');
  var decision={status:select.value,note:note ? note.value : '',
    updated:new Date().toISOString(),entrypoint:entry.entrypoint,
    control:'__flow__',file:entry.file,line:entry.line};
  if(!decision.status && !decision.note) delete flowTriage[key];
  else flowTriage[key]=decision;
  saveFlowTriage(); updateFlowTriageCount(); updateFlowDecision(entry);
  updateTriageCount(); applyFilters();
}
function renderFlowTriageEditor(entry,control){
  coverageSelectedControl=control || '';
  var host=document.getElementById('coverageControlTriage');
  if(!host) return;
  coverageClear(host);
  if(!entry || !control){ host.style.display='none'; return; }
  host.style.display='grid';
  var key=coverageControlKey(entry,control);
  var decision=flowTriage[key] || {};
  host.appendChild(coverageElement('label','',
    'Flow/control decision · ' + (coverageLabels[control] || control)));
  var select=coverageElement('select','');
  [['','Open / untriaged'],['confirmed','Confirmed'],['false-positive','False Positive'],
   ['accepted-risk','Accepted Risk'],['fixed','Fixed']].forEach(function(option){
    var node=coverageElement('option','',option[1]); node.value=option[0]; select.appendChild(node);
  });
  select.value=decision.status || '';
  var note=coverageElement('input',''); note.type='text';
  note.placeholder='Decision note or evidence…'; note.value=decision.note || '';
  function persist(){
    var value={status:select.value,note:note.value,updated:new Date().toISOString(),
      entrypoint:entry.entrypoint,control:control,file:entry.file,line:entry.line};
    if(!value.status && !value.note) delete flowTriage[key]; else flowTriage[key]=value;
    saveFlowTriage(); updateFlowTriageCount(); updateTriageCount(); applyFilters();
    if(control==='__flow__') updateFlowDecision(entry);
    else{
      var button=document.querySelector('#coverageControls [data-control="' + control + '"]');
      updateControlTriageBadge(button,entry,control);
    }
  }
  select.addEventListener('change',persist); note.addEventListener('change',persist);
  host.appendChild(select); host.appendChild(note);
}
function coverageOverall(entry){
  var values=Object.keys(entry.controls || {}).map(function(k){ return entry.controls[k]; });
  if(values.indexOf('MISSING')!==-1) return 'GAP';
  if(values.indexOf('UNKNOWN')!==-1) return 'REVIEW';
  return 'COVERED';
}
function coverageHasReferenceFlow(entry){
  if(typeof entry.reference_flow==='boolean') return entry.reference_flow;
  return Boolean((entry.flow_steps || []).length>1 || (entry.sinks || []).length ||
                 (entry.unresolved_calls || []).length);
}
function coverageMatchesFlowFilter(entry, filter){
  if(filter==='has-flow') return coverageHasReferenceFlow(entry);
  if(filter==='no-flow') return !coverageHasReferenceFlow(entry);
  if(filter==='sensitive') return Boolean((entry.sinks || []).length ||
                                          (entry.sensitive_sinks || []).length);
  if(filter==='unresolved') return Boolean((entry.unresolved_calls || []).length);
  if(filter==='risk') return coverageAttackPaths.some(function(path){
    return Number(path.entry_index)===coverageEntries.indexOf(entry);
  });
  return true;
}
function coverageLocation(item){
  if(!item || !item.file) return 'Source location unavailable';
  return item.file + (item.line ? ':' + item.line : '');
}
function showCoverageCode(source){
  var location=document.getElementById('coverageCodeLocation');
  var frame=document.getElementById('coverageCodeFrame');
  if(!frame) return;
  coverageClear(frame);
  if(location) location.textContent=coverageLocation(source);
  var context=source && source.context ? source.context : [];
  if(!context.length){
    frame.appendChild(coverageElement('div','coverage-code-empty',
      'No source context is available for this location.'));
    return;
  }
  var hit=null;
  context.forEach(function(row){
    var line=coverageElement('span','coverage-code-line' + (row.hit?' hit':''));
    line.appendChild(coverageElement('span','coverage-code-number',row.line));
    line.appendChild(coverageElement('span','coverage-code-text',row.text));
    frame.appendChild(line);
    if(row.hit) hit=line;
  });
  if(hit) frame.scrollTop=Math.max(0,hit.offsetTop-frame.clientHeight/2);
}
function coverageSameReference(candidate,target,kind){
  if(!candidate || !target) return false;
  /* Sink locations often point at different call sites.  Matching the modeled
     sink signature as well exposes all callers; the explorer keeps file/line
     evidence visible so reviewers can reject overloaded-method false positives. */
  if(kind==='SINK' && candidate.label && candidate.label===target.label) return true;
  if(candidate.file && target.file && candidate.line && target.line){
    return candidate.file===target.file && Number(candidate.line)===Number(target.line);
  }
  return Boolean(candidate.label && target.label && candidate.label===target.label);
}
function showCoverageReferences(target,kind){
  var list=document.getElementById('coverageReferenceList');
  var countNode=document.getElementById('coverageReferenceCount');
  var titleNode=document.getElementById('coverageReferenceTitle');
  if(!list) return;
  coverageClear(list);
  var references=[];
  coverageEntries.forEach(function(entry,index){
    var items=kind==='SINK' ? (entry.sinks || []) : (entry.flow_steps || []);
    if(items.some(function(item){ return coverageSameReference(item,target,kind); })){
      references.push({entry:entry,index:index});
    }
  });
  if(titleNode) titleNode.textContent='Find All References' +
    (target && target.label ? ' · ' + target.label : '');
  if(countNode) countNode.textContent=references.length +
    ' reachable entr' + (references.length===1?'y point':'y points');
  if(!references.length){
    list.appendChild(coverageElement('div','coverage-detail-empty',
      'No controller, listener, or scheduled entry point references this location.'));
    return;
  }
  references.forEach(function(reference){
    var entry=reference.entry;
    var item=coverageElement('div','coverage-reference-item');
    var open=coverageElement('button','coverage-reference-entry',entry.entrypoint);
    open.type='button';
    open.addEventListener('click',function(){ renderCoverageEntry(reference.index); });
    item.appendChild(open);
    item.appendChild(coverageElement('span','coverage-reference-policy',
      (entry.route_policy || 'unknown').toUpperCase()));
    var path=(entry.flow_steps || []).map(function(step){ return step.label; });
    (entry.sinks || []).forEach(function(sink){ path.push('SINK: ' + sink.label); });
    item.appendChild(coverageElement('span','coverage-reference-path',
      path.length ? path.join(' → ') : 'Entry point only'));
    var rules=coverageElement('div','coverage-reference-rules');
    (entry.policy_sources || []).forEach(function(source){
      var link=coverageElement('button','coverage-source-link',
        'Security rule · ' + coverageLocation(source));
      link.type='button'; link.addEventListener('click',function(){ showCoverageCode(source); });
      rules.appendChild(link);
    });
    if(!rules.childNodes.length){
      rules.appendChild(coverageElement('span','coverage-detail-empty',
        'No statically resolved security-rule source.'));
    }
    item.appendChild(rules); list.appendChild(item);
  });
}
function renderCoverageExplanation(body, explanation){
  if(!body || !explanation) return;
  var grid=coverageElement('div','coverage-explanation');
  function card(label,value,wide){
    var item=coverageElement('div','coverage-explanation-card' + (wide?' wide':''));
    item.appendChild(coverageElement('span','coverage-explanation-label',label));
    item.appendChild(coverageElement('div','coverage-explanation-value',value));
    grid.appendChild(item);
  }
  card('Decision rationale',explanation.summary || 'No rationale recorded.',true);
  card('Why this is sufficient / insufficient',explanation.why || 'No conclusion recorded.',true);
  card('Inspected',(explanation.inspected || []).join(' · ') || 'No inspection inventory.');
  card('Uncertainty',(explanation.uncertainty || []).join(' · ') || 'None recorded.');
  var confidence=coverageElement('span','coverage-confidence ' +
    (explanation.confidence || 'REVIEW'),explanation.confidence || 'REVIEW');
  var confidenceCard=coverageElement('div','coverage-explanation-card');
  confidenceCard.appendChild(coverageElement('span','coverage-explanation-label','Confidence'));
  confidenceCard.appendChild(confidence); grid.appendChild(confidenceCard);
  card('Evidence retained',(explanation.found || []).length + ' item(s)');
  body.appendChild(grid);
}
function showCoverageDetail(title, evidence, sources, explanation){
  var titleNode=document.getElementById('coverageDetailTitle');
  var body=document.getElementById('coverageDetailBody');
  if(titleNode) titleNode.textContent=title;
  if(!body) return;
  coverageClear(body);
  renderCoverageExplanation(body,explanation);
  if(!evidence || !evidence.length){
    body.appendChild(coverageElement('div','coverage-detail-empty','No additional static evidence is available.'));
  }else{
    var list=coverageElement('ul','coverage-detail-list');
    evidence.forEach(function(item){ list.appendChild(coverageElement('li','',item)); });
    body.appendChild(list);
  }
  if(sources && sources.length){
    var links=coverageElement('div','coverage-source-links');
    sources.forEach(function(source){
      var link=coverageElement('button','coverage-source-link',
        (source.label || 'Source') + ' · ' + coverageLocation(source));
      link.type='button';
      link.addEventListener('click',function(){ showCoverageCode(source); });
      links.appendChild(link);
    });
    body.appendChild(links);
  }
}
function appendCoveragePolicy(list, label, value){
  list.appendChild(coverageElement('dt','',label));
  list.appendChild(coverageElement('dd','',value));
}
function appendCoverageFlowNode(container, item, kind, evidence){
  if(container.childNodes.length) container.appendChild(coverageElement('span','coverage-arrow','→'));
  var button=coverageElement('button','coverage-flow-node ' + kind);
  button.type='button';
  button.appendChild(coverageElement('span','coverage-node-kind',kind.replace('_',' ')));
  button.appendChild(coverageElement('span','coverage-node-label',item.label || '<unknown>'));
  button.appendChild(coverageElement('span','coverage-node-loc',coverageLocation(item)));
  button.addEventListener('click',function(){
    container.querySelectorAll('.coverage-flow-node').forEach(function(node){ node.classList.remove('active'); });
    button.classList.add('active');
    showCoverageDetail((item.label || kind) + ' — source',
                       evidence || [coverageLocation(item)],[item]);
    showCoverageCode(item);
    showCoverageReferences(item,kind);
  });
  container.appendChild(button);
}
function renderCoverageEntry(index){
  if(!coverageEntries.length) return;
  coverageSelected=Math.max(0,Math.min(index,coverageEntries.length-1));
  var entry=coverageEntries[coverageSelected];
  document.querySelectorAll('.coverage-entry').forEach(function(button){
    button.classList.toggle('active',Number(button.getAttribute('data-index'))===coverageSelected);
  });
  var name=document.getElementById('coverageEntryName');
  var loc=document.getElementById('coverageEntryLocation');
  var state=document.getElementById('coverageEntryState');
  if(name) name.textContent=entry.entrypoint;
  if(loc) loc.textContent=coverageLocation(entry) + ' · ' + (entry.kind || 'entry point');
  var overall=coverageOverall(entry);
  if(state){ state.className='coverage-state ' + overall; state.textContent=overall; }
  updateFlowDecision(entry);
  var flowDecision=document.getElementById('coverageFlowDecision');
  if(flowDecision) flowDecision.onchange=function(){ persistCompleteFlowDecision(entry); };
  var flowDecisionNote=document.getElementById('coverageFlowDecisionNote');
  if(flowDecisionNote) flowDecisionNote.oninput=function(){ persistCompleteFlowDecision(entry); };

  var policy=document.getElementById('coveragePolicy');
  if(policy){
    coverageClear(policy);
    appendCoveragePolicy(policy,'Matched policy',(entry.route_policy || 'unknown').toUpperCase());
    appendCoveragePolicy(policy,'Route',entry.route || entry.entrypoint);
    appendCoveragePolicy(policy,'Configuration evidence',
      (entry.policy_evidence && entry.policy_evidence.length) ? entry.policy_evidence.join(' · ') :
      'No statically resolved route policy');
    appendCoveragePolicy(policy,'Required roles / authorities',
      (entry.required_permissions && entry.required_permissions.length) ?
        entry.required_permissions.join(', ') : 'No explicit role or authority extracted');
    var conditions=[];
    (entry.activation_conditions || []).forEach(function(item){ conditions.push(item); });
    (entry.policy_conditions || []).forEach(function(item){ if(conditions.indexOf(item)<0) conditions.push(item); });
    (entry.configuration_profiles || []).forEach(function(item){ if(conditions.indexOf(item)<0) conditions.push(item); });
    appendCoveragePolicy(policy,'Activation / environment',
      conditions.length ? conditions.join(' · ') : 'No profile or conditional bean constraint detected');
  }
  var policySource=document.getElementById('coveragePolicySource');
  var policySources=entry.policy_sources || [];
  if(policySource){
    policySource.style.display=policySources.length?'':'none';
    policySource.onclick=function(){
      if(policySources.length){
        showCoverageCode(policySources[0]);
        showCoverageDetail('Effective security configuration',
          entry.policy_evidence || [],policySources);
      }
    };
  }

  var flow=document.getElementById('coverageFlow');
  var steps=[];
  if(flow){
    coverageClear(flow);
    steps=(entry.flow_steps && entry.flow_steps.length) ? entry.flow_steps :
      (entry.flow || []).map(function(label,i){ return {label:label,file:i===0?entry.file:'',line:i===0?entry.line:0}; });
    steps.forEach(function(step,i){
      appendCoverageFlowNode(flow,step,i===0?'ENTRYPOINT':'METHOD',[
        coverageLocation(step),
        step.class_name && step.method ? 'Method: ' + step.class_name + '.' + step.method + '()' : step.label
      ]);
    });
    var sinks=(entry.sinks && entry.sinks.length) ? entry.sinks :
      (entry.sensitive_sinks || []).map(function(label){ return {label:label,file:'',line:0}; });
    sinks.forEach(function(sink){
      appendCoverageFlowNode(flow,sink,'SINK',[coverageLocation(sink),'Sensitive sink: ' + sink.label]);
    });
    (entry.unresolved_calls || []).forEach(function(call){
      appendCoverageFlowNode(flow,{label:call,file:'',line:0},'UNRESOLVED',[
        'The target implementation could not be resolved statically.',call]);
    });
    if(!flow.childNodes.length) flow.appendChild(
      coverageElement('div','coverage-detail-empty','No reachable processing path was resolved.'));
  }
  if(steps.length){ showCoverageCode(steps[0]); showCoverageReferences(steps[0],'ENTRYPOINT'); }
  else if((entry.sinks || []).length){
    showCoverageCode(entry.sinks[0]); showCoverageReferences(entry.sinks[0],'SINK');
  }else{ showCoverageCode({}); showCoverageReferences({},''); }

  var controls=document.getElementById('coverageControls');
  var firstGap='';
  if(controls){
    coverageClear(controls);
    coverageOrder.forEach(function(key){
      if(!Object.prototype.hasOwnProperty.call(entry.controls || {},key)) return;
      var status=entry.controls[key] || 'UNKNOWN';
      if(!firstGap && (status==='MISSING' || status==='UNKNOWN')) firstGap=key;
      var button=coverageElement('button','coverage-control');
      button.type='button'; button.setAttribute('data-control',key);
      button.appendChild(coverageElement('span','',coverageLabels[key] || key));
      button.appendChild(coverageElement('span','coverage-control-status ' + status,
        status==='NOT_REQUIRED' ? 'N/A' : status));
      updateControlTriageBadge(button,entry,key);
      button.addEventListener('click',function(){
        controls.querySelectorAll('.coverage-control').forEach(function(node){ node.classList.remove('active'); });
        button.classList.add('active');
        var sources=((entry.control_sources || {})[key] || []).slice();
        var fallback=false;
        if(!sources.length && (status==='MISSING' || status==='UNKNOWN')){
          sources=(entry.sinks || []).slice(0,2);
          fallback=Boolean(sources.length);
        }
        var detailEvidence=((entry.evidence || {})[key] || []).slice();
        if(fallback) detailEvidence.push(
          'No supporting control location was found; showing the terminal sink for false-positive review.');
        showCoverageDetail((coverageLabels[key] || key) + ' — ' + status,
                           detailEvidence,sources,
                           (entry.control_explanations || {})[key]);
        if(sources.length) showCoverageCode(sources[0]);
        renderFlowTriageEditor(entry,key);
      });
      controls.appendChild(button);
    });
  }
  var initial=firstGap || coverageOrder.find(function(key){
    return Object.prototype.hasOwnProperty.call(entry.controls || {},key);
  });
  if(initial){
    var initialButton=controls && controls.querySelector('[data-control="' + initial + '"]');
    if(initialButton) initialButton.classList.add('active');
    var initialSources=((entry.control_sources || {})[initial] || []).slice();
    var initialEvidence=((entry.evidence || {})[initial] || []).slice();
    if(!initialSources.length && (entry.controls[initial]==='MISSING' ||
                                  entry.controls[initial]==='UNKNOWN')){
      initialSources=(entry.sinks || []).slice(0,2);
      if(initialSources.length) initialEvidence.push(
        'No supporting control location was found; the terminal sink is available for false-positive review.');
    }
    showCoverageDetail((coverageLabels[initial] || initial) + ' — ' + entry.controls[initial],
                       initialEvidence,initialSources,
                       (entry.control_explanations || {})[initial]);
    renderFlowTriageEditor(entry,initial);
  }else{
    renderFlowTriageEditor(null,'');
  }
}
function renderCoverageList(){
  var list=document.getElementById('coverageEntryList');
  if(!list) return;
  coverageClear(list);
  var searchNode=document.getElementById('coverageSearch');
  var filterNode=document.getElementById('coverageFlowFilter');
  var normalized=(searchNode ? searchNode.value : '').toLowerCase();
  var flowFilter=filterNode ? filterNode.value : 'all';
  var visible=[];
  coverageEntries.forEach(function(entry,index){
    var searchable=(entry.entrypoint + ' ' + entry.file + ' ' + entry.method).toLowerCase();
    if(normalized && searchable.indexOf(normalized)===-1) return;
    if(!coverageMatchesFlowFilter(entry,flowFilter)) return;
    visible.push({entry:entry,index:index});
  });
  if(visible.length && !visible.some(function(item){ return item.index===coverageSelected; })){
    coverageSelected=visible[0].index;
    renderCoverageEntry(coverageSelected);
  }
  visible.forEach(function(item){
    var entry=item.entry, index=item.index;
    var overall=coverageOverall(entry);
    var button=coverageElement('button','coverage-entry' + (index===coverageSelected?' active':''));
    button.type='button'; button.setAttribute('data-index',String(index));
    button.appendChild(coverageElement('span','coverage-entry-dot ' + overall));
    var copy=coverageElement('span','');
    copy.appendChild(coverageElement('span','coverage-entry-name',entry.entrypoint));
    copy.appendChild(coverageElement('span','coverage-entry-loc',coverageLocation(entry)));
    copy.appendChild(coverageElement('span','coverage-entry-flow ' +
      (coverageHasReferenceFlow(entry)?'HAS_FLOW':'NO_FLOW'),
      coverageHasReferenceFlow(entry)?'REFERENCE FLOW':'NO REFERENCE FLOW'));
    button.appendChild(copy);
    button.addEventListener('click',function(){ renderCoverageEntry(index); });
    list.appendChild(button);
  });
  if(!list.childNodes.length) list.appendChild(
    coverageElement('div','coverage-detail-empty','No matching entry points.'));
}
if(coverageEntries.length){
  renderCoverageList(); renderCoverageEntry(coverageSelected);
  var coverageSearch=document.getElementById('coverageSearch');
  if(coverageSearch) coverageSearch.addEventListener('input',function(){
    renderCoverageList();
  });
  var coverageFlowFilter=document.getElementById('coverageFlowFilter');
  if(coverageFlowFilter) coverageFlowFilter.addEventListener('change',renderCoverageList);
}
document.querySelectorAll('[data-attack-entry]').forEach(function(button){
  button.addEventListener('click',function(){
    setReportView('flow',true);
    renderCoverageEntry(Number(button.getAttribute('data-attack-entry')) || 0);
    var dashboard=document.getElementById('coverageDashboard');
    if(dashboard) dashboard.scrollIntoView({behavior:'smooth',block:'start'});
  });
});

/* ---- Security-policy snapshots and drift --------------------------- */
function coveragePolicyIdentity(entry){
  return [entry.kind || '',entry.http_method || '',entry.route || entry.entrypoint || '',
          entry.method || ''].join('::');
}
function coveragePolicySnapshotEntry(entry){
  return {id:coveragePolicyIdentity(entry),entrypoint:entry.entrypoint || '',
    kind:entry.kind || '',http_method:entry.http_method || '',route:entry.route || '',
    method:entry.method || '',route_policy:entry.route_policy || 'unknown',
    controls:entry.controls || {},required_permissions:(entry.required_permissions || []).slice().sort(),
    activation_conditions:(entry.activation_conditions || []).slice().sort(),
    policy_conditions:(entry.policy_conditions || []).slice().sort(),
    configuration_profiles:(entry.configuration_profiles || []).slice().sort()};
}
function currentPolicySnapshot(){
  return {tool:'JSpringGuard',kind:'security-policy-snapshot',version:1,
    exported:new Date().toISOString(),entries:coverageEntries.map(coveragePolicySnapshotEntry)};
}
function policyArraysEqual(left,right){
  return JSON.stringify((left || []).slice().sort())===JSON.stringify((right || []).slice().sort());
}
function comparePolicySnapshots(previous){
  var priorEntries=previous && previous.entries ? previous.entries : [];
  if(!Array.isArray(priorEntries)) throw new Error('snapshot entries must be an array');
  var prior={},current={};
  priorEntries.forEach(function(entry){
    var normalized=coveragePolicySnapshotEntry(entry);
    prior[entry.id || normalized.id]=normalized;
  });
  coverageEntries.forEach(function(entry){
    var normalized=coveragePolicySnapshotEntry(entry); current[normalized.id]=normalized;
  });
  var changes=[];
  Object.keys(current).forEach(function(id){
    var now=current[id],before=prior[id];
    if(!before){ changes.push({kind:'added',entrypoint:now.entrypoint,
      text:'New security entry point'}); return; }
    if((before.route_policy || 'unknown')!==(now.route_policy || 'unknown')){
      var weak=['permitall','anonymous','unknown'];
      changes.push({kind:weak.indexOf((now.route_policy || '').toLowerCase())>=0?'degraded':'changed',
        entrypoint:now.entrypoint,text:'Route policy: ' + before.route_policy + ' → ' + now.route_policy});
    }
    var keys={}; Object.keys(before.controls || {}).forEach(function(key){keys[key]=true;});
    Object.keys(now.controls || {}).forEach(function(key){keys[key]=true;});
    var rank={MISSING:0,UNKNOWN:1,COVERED:2,NOT_REQUIRED:2};
    Object.keys(keys).forEach(function(key){
      var oldStatus=(before.controls || {})[key] || 'UNKNOWN';
      var newStatus=(now.controls || {})[key] || 'UNKNOWN';
      if(oldStatus===newStatus) return;
      var kind=(rank[newStatus] || 0)<(rank[oldStatus] || 0)?'degraded':
        (rank[newStatus] || 0)>(rank[oldStatus] || 0)?'improved':'changed';
      changes.push({kind:kind,entrypoint:now.entrypoint,
        text:(coverageLabels[key] || key) + ': ' + oldStatus + ' → ' + newStatus});
    });
    if(!policyArraysEqual(before.required_permissions,now.required_permissions)){
      changes.push({kind:'changed',entrypoint:now.entrypoint,
        text:'Permissions: ' + ((before.required_permissions || []).join(', ') || 'none') +
          ' → ' + ((now.required_permissions || []).join(', ') || 'none')});
    }
    var oldConditions=(before.activation_conditions || []).concat(
      before.policy_conditions || [],before.configuration_profiles || []);
    var newConditions=(now.activation_conditions || []).concat(
      now.policy_conditions || [],now.configuration_profiles || []);
    if(!policyArraysEqual(oldConditions,newConditions)){
      changes.push({kind:'changed',entrypoint:now.entrypoint,
        text:'Spring profile / bean activation conditions changed'});
    }
  });
  Object.keys(prior).forEach(function(id){
    if(!current[id]) changes.push({kind:'removed',entrypoint:prior[id].entrypoint,
      text:'Previously reachable security entry point is no longer present'});
  });
  return changes;
}
function renderPolicyDrift(changes){
  var host=document.getElementById('coverageDrift');
  var list=document.getElementById('coverageDriftList');
  var summary=document.getElementById('coverageDriftSummary');
  if(!host || !list) return;
  coverageClear(list); host.style.display='block';
  if(summary){
    var degraded=changes.filter(function(item){return item.kind==='degraded';}).length;
    summary.textContent=changes.length + ' change(s) · ' + degraded + ' degradation(s)';
  }
  if(!changes.length){
    list.appendChild(coverageElement('div','coverage-detail-empty',
      'No security-policy drift was detected against the imported snapshot.'));
    return;
  }
  changes.forEach(function(change){
    var item=coverageElement('div','coverage-drift-item ' + change.kind);
    item.appendChild(coverageElement('div','coverage-drift-entry',change.entrypoint));
    item.appendChild(coverageElement('span','coverage-drift-change',change.text));
    list.appendChild(item);
  });
}
var exportPolicySnapshot=document.getElementById('exportPolicySnapshot');
if(exportPolicySnapshot) exportPolicySnapshot.addEventListener('click',function(){
  downloadDecisionJson('jspringguard-security-policy-snapshot.json',currentPolicySnapshot());
});
var importPolicySnapshot=document.getElementById('importPolicySnapshot');
if(importPolicySnapshot) importPolicySnapshot.addEventListener('change',function(){
  var file=importPolicySnapshot.files && importPolicySnapshot.files[0]; if(!file) return;
  var reader=new FileReader();
  reader.onload=function(){
    try{
      var previous=JSON.parse(reader.result);
      if(previous.kind && previous.kind!=='security-policy-snapshot')
        throw new Error('not a JSpringGuard security-policy snapshot');
      renderPolicyDrift(comparePolicySnapshots(previous));
    }catch(error){ alert('Could not compare that security-policy snapshot:\n' + error); }
    importPolicySnapshot.value='';
  };
  reader.readAsText(file);
});
updateFlowTriageCount();
function flowTriageExportPayload(exported){
  return {tool:'JSpringGuard',kind:'flow-control-triage',version:1,
    exported:exported,entries:flowTriage};
}
var importFlowTriage=document.getElementById('importFlowTriage');
if(importFlowTriage) importFlowTriage.addEventListener('change',function(){
  var file=importFlowTriage.files && importFlowTriage.files[0]; if(!file) return;
  var reader=new FileReader();
  reader.onload=function(){
    try{
      var data=JSON.parse(reader.result);
      var entries=data && data.entries ? data.entries : data;
      if(typeof entries!=='object' || entries===null) throw new Error('unexpected format');
      Object.keys(entries).forEach(function(key){ flowTriage[key]=entries[key]; });
      saveFlowTriage(); updateFlowTriageCount(); renderCoverageEntry(coverageSelected);
      updateTriageCount(); applyFilters();
      alert('Imported ' + Object.keys(entries).length + ' flow/control triage entries.');
    }catch(error){
      alert('Could not read that file as a JSpringGuard flow-triage export:\n' + error);
    }
    importFlowTriage.value='';
  };
  reader.readAsText(file);
});

/* ---- Triage: per-finding status + note, keyed by fingerprint ----------
   The fingerprint is stable across re-scans, so a decision made in one
   report can be imported into the next one and still match. Stored in
   localStorage for convenience; Export/Import makes it portable and
   shareable (localStorage is per-browser and can be cleared at any time,
   so it must not be the only copy of real triage work).             */
var TKEY='jspringguardTriage';
var triage={};
try{ triage = JSON.parse(localStorage.getItem(TKEY) || '{}') || {}; }catch(e){ triage={}; }

var STATUS_LABEL={'confirmed':'Confirmed','in-review':'In review','fixed':'Fixed',
                  'false-positive':'False positive','accepted':'Accepted risk'};

function saveTriage(){
  try{ localStorage.setItem(TKEY, JSON.stringify(triage)); }catch(e){}
}
function flashSaved(el){
  var card = el.closest('.card');
  var tag = card && card.querySelector('.triage-saved');
  if(!tag) return;
  tag.classList.add('show');
  setTimeout(function(){ tag.classList.remove('show'); }, 900);
}
function renderCardTriage(card){
  var sel = card.querySelector('.triage-status');
  if(!sel) return;
  var fp = sel.getAttribute('data-fp');
  var entry = triage[fp] || {};
  var status = entry.status || '';
  sel.value = status;
  var note = card.querySelector('.triage-note');
  if(note) note.value = entry.note || '';
  card.setAttribute('data-status', status);
  card.classList.toggle('triaged', status !== '');
  var old = card.querySelector('.badge.st');
  if(old) old.remove();
  if(status){
    var b = document.createElement('span');
    b.className = 'badge st';
    b.setAttribute('data-st', status);
    b.textContent = STATUS_LABEL[status] || status;
    var head = card.querySelector('.card-head');
    if(head) head.appendChild(b);
  }
}
function updateTriageCount(){
  var cards = document.querySelectorAll('.card');
  var done = 0;
  cards.forEach(function(c){ if(c.getAttribute('data-status')) done++; });
  var flowDone=currentFlowTriageRecords().length;
  var el = document.getElementById('triageCount');
  if(el) el.innerHTML = 'Finding triage <b>' + done + '</b> of <b>' + cards.length +
    '</b> · Flow/control decisions <b>' + flowDone + '</b>';
}
function renderAllTriage(){
  document.querySelectorAll('.card').forEach(renderCardTriage);
  updateTriageCount();
  renderFlowDecisionFindings(statusFilter ? statusFilter.value : '',
    search ? search.value.toLowerCase() : '',typeFilter ? typeFilter.value : '',
    sevFilter ? sevFilter.value : '');
}
renderAllTriage();

document.querySelectorAll('.triage-status').forEach(function(sel){
  sel.addEventListener('change', function(){
    var fp = sel.getAttribute('data-fp');
    var card = sel.closest('.card');
    var note = card.querySelector('.triage-note');
    var entry = triage[fp] || {};
    entry.status = sel.value;
    entry.note = note ? note.value : '';
    entry.ts = new Date().toISOString();
    if(!entry.status && !entry.note) delete triage[fp]; else triage[fp] = entry;
    saveTriage(); renderCardTriage(card); updateTriageCount(); flashSaved(sel);
    applyFilters();
  });
});
document.querySelectorAll('.triage-note').forEach(function(inp){
  inp.addEventListener('change', function(){
    var fp = inp.getAttribute('data-fp');
    var card = inp.closest('.card');
    var sel = card.querySelector('.triage-status');
    var entry = triage[fp] || {};
    entry.note = inp.value;
    entry.status = sel ? sel.value : '';
    entry.ts = new Date().toISOString();
    if(!entry.status && !entry.note) delete triage[fp]; else triage[fp] = entry;
    saveTriage(); flashSaved(inp);
  });
});

function downloadDecisionJson(filename,payload){
  var blob = new Blob([JSON.stringify(payload, null, 2)], {type:'application/json'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(function(){ URL.revokeObjectURL(a.href); },1000);
}
var exportTriage=document.getElementById('exportTriage');
if(exportTriage) exportTriage.addEventListener('click',function(){
  downloadDecisionJson('jspringguard-finding-triage.json',{
    tool:'JSpringGuard',kind:'triage',version:1,entries:triage});
});
var exportAllTriage=document.getElementById('exportAllTriage');
if(exportAllTriage) exportAllTriage.addEventListener('click',function(){
  var exported=new Date().toISOString();
  downloadDecisionJson('jspringguard-finding-triage.json',{
    tool:'JSpringGuard',kind:'triage',version:1,exported:exported,entries:triage
  });
  downloadDecisionJson('jspringguard-flow-triage.json',flowTriageExportPayload(exported));
});

var importInput=document.getElementById('importTriage');
if(importInput) importInput.addEventListener('change', function(){
  var file = importInput.files && importInput.files[0];
  if(!file) return;
  var reader = new FileReader();
  reader.onload = function(){
    try{
      var data = JSON.parse(reader.result);
      var entries = data && data.entries ? data.entries : data;
      if(typeof entries !== 'object' || entries === null) throw new Error('unexpected format');
      var added = 0;
      Object.keys(entries).forEach(function(fp){
        triage[fp] = entries[fp]; added++;
      });
      saveTriage(); renderAllTriage(); applyFilters();
      alert('Imported ' + added + ' triage entr' + (added===1?'y':'ies') + '.');
    }catch(err){
      alert('Could not read that file as a JSpringGuard triage export:\n' + err);
    }
    importInput.value = '';
  };
  reader.readAsText(file);
});

var clearBtn=document.getElementById('clearTriage');
if(clearBtn) clearBtn.addEventListener('click', function(){
  if(!confirm('Remove all statuses and notes stored in this browser?\n' +
              'Export first if you want to keep them.')) return;
  triage = {};
  saveTriage(); renderAllTriage(); applyFilters();
});
// Scrollt jeden Code-Block automatisch auf die markierte Treffer-Zeile
document.querySelectorAll('.source-context').forEach(function(pre){
  var hit = pre.querySelector('.context-hit');
  if(hit) pre.scrollTop = hit.offsetTop - pre.clientHeight / 2;
});
})();

"""


def to_html(findings: List[Finding], scanned: int, builds: int,
            coverage: Optional[Sequence[CoverageEntry]] = None) -> str:
    esc = html_mod.escape
    counts = summary_counts(findings)
    sev_key = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}

    parts = ["<!doctype html>", "<html lang='en'>", "<head>", "<meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width, initial-scale=1'>",
             "<title>JSpringGuard Report</title>", f"<style>{HTML_CSS}</style>", "</head>", "<body>"]

    parts.append("<header class='topbar'><div class='topbar-inner'>")
    parts.append("<div class='brand'><span class='mark' aria-hidden='true'></span>"
                 "<h1>JSpringGuard</h1>"
                 f"<span class='version'>v{VERSION}</span>"
                 f"<a class='brand-repo' href='{REPO_URL}' "
                 f"target='_blank' rel='noopener noreferrer' title='{AUTHOR}/JSpringGuard on GitHub'>"
                 "<svg viewBox='0 0 16 16' aria-hidden='true'><path fill='currentColor' d='M8 0a8 8 0 0 0-2.53 "
                 "15.59c.4.07.55-.17.55-.38l-.01-1.34c-2.23.48-2.7-1.07-2.7-1.07-.36-.93-.89-1.18-.89-1.18-.73-.5"
                 ".05-.49.05-.49.8.06 1.23.83 1.23.83.72 1.23 1.88.87 2.34.67.07-.52.28-.87.51-1.07-1.78-.2-3.64-"
                 ".89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 "
                 "0c1.53-1.03 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 "
                 "3.95.29.25.54.73.54 1.48l-.01 2.2c0 .21.15.46.55.38A8 8 0 0 0 8 0z'/></svg>"
                 f"<span>{AUTHOR}/JSpringGuard</span></a></div>")
    parts.append(f"<div class='topbar-meta'>{scanned} source file(s) &middot; {builds} build file(s) "
                 f"&middot; {len(findings)} finding(s)</div>")
    parts.append("<div class='topbar-actions'>"
                 "<button class='theme-toggle' id='themeToggle' type='button' title='Toggle theme'>"
                 "<svg class='icon-moon' viewBox='0 0 20 20' aria-hidden='true'><path fill='currentColor' "
                 "d='M17.3 12.6a7 7 0 0 1-9.9-9.9 8 8 0 1 0 9.9 9.9z'/></svg>"
                 "<svg class='icon-sun' viewBox='0 0 20 20' aria-hidden='true'>"
                 "<circle cx='10' cy='10' r='4' fill='currentColor'/>"
                 "<g stroke='currentColor' stroke-width='1.6' stroke-linecap='round'>"
                 "<path d='M10 1.5v2.2M10 16.3v2.2M18.5 10h-2.2M3.7 10H1.5M15.7 4.3l-1.5 1.5M5.8 14.2l-1.5 1.5"
                 "M15.7 15.7l-1.5-1.5M5.8 5.8 4.3 4.3'/></g></svg></button></div>")
    parts.append("</div></header>")

    parts.append("<div class='shell'>")
    parts.append("<nav class='report-menu' role='tablist' aria-label='Report views'>"
                 "<a class='report-menu-link active' href='#findings' role='tab' "
                 "aria-selected='true' data-report-view-target='findings'>Findings"
                 f"<span class='report-menu-count'>{len(findings)}</span></a>")
    if coverage is not None:
        parts.append("<a class='report-menu-link' href='#security-flow' role='tab' "
                     "aria-selected='false' data-report-view-target='flow'>Security Flow Explorer"
                     f"<span class='report-menu-count'>{len(coverage)}</span></a>")
    parts.append("<button class='report-menu-action' id='exportAllTriage' type='button'>"
                 "Export all triage</button></nav><span id='findings'></span>")

    def _chip(sev: str, css_class: str, label: str, extra_attr: str = "") -> str:
        n = counts.get(sev, 0)
        cls_attr = " class='zero'" if n == 0 else ""
        num_cls = f"num {css_class}".strip() if css_class else "num"
        return (f"<div data-sev='{sev}'{cls_attr}{extra_attr}>"
                f"<span class='{num_cls}'>{n}</span><span class='lbl'>{label}</span></div>")

    parts.append("<div class='chips' id='sevChips'>"
                 + _chip("CRITICAL", "critical", "Critical")
                 + _chip("HIGH", "high", "High")
                 + _chip("MEDIUM", "medium", "Medium")
                 + _chip("LOW", "low", "Low")
                 + _chip("INFO", "", "Info",
                        " title='Informational findings (e.g. hardened confirmations) are excluded by "
                        "the default --min-severity LOW. Re-run with --min-severity INFO to include them.'")
                 + "</div>")

    if coverage is not None:
        parts.append(coverage_explorer_html(coverage))

    if findings or coverage is not None:
        categories = sorted({categorize_rule(f.rule_id) for f in findings})
        cat_counts = Counter(categorize_rule(f.rule_id) for f in findings)
        parts.append("<div class='filter-row'>")
        parts.append("<input type='text' id='findingSearch' class='search-input' "
                     "placeholder='Filter by rule, file, message…'>")
        type_opts = ["<option value=''>All types</option>"]
        for cat in categories:
            type_opts.append(f"<option value='{esc(cat)}'>{esc(cat)} ({cat_counts[cat]})</option>")
        parts.append("<select id='typeFilter' class='type-filter'>" + "".join(type_opts) + "</select>")
        sev_opts = ["<option value=''>All severities</option>"]
        for sev in reversed(SEVERITY_LIST):
            sev_opts.append(f"<option value='{esc(sev)}'>{esc(sev)} ({counts.get(sev, 0)})</option>")
        parts.append("<select id='severityFilter' class='type-filter'>" + "".join(sev_opts) + "</select>")
        parts.append("<select id='statusFilter' class='type-filter'>"
                     "<option value=''>All statuses</option>"
                     "<option value='__open'>Open (untriaged)</option>"
                     "<option value='confirmed'>Confirmed</option>"
                     "<option value='in-review'>In review</option>"
                     "<option value='fixed'>Fixed</option>"
                     "<option value='false-positive'>False positive</option>"
                     "<option value='accepted'>Accepted risk</option>"
                     "</select>")
        parts.append("<button type='button' id='toggleFixes' class='mini-btn' "
                     "title='Expand or collapse every Fix template at once'>Expand all fixes</button>")
        parts.append("</div>")
        parts.append(
            "<div class='triage-bar'>"
            "<span class='count' id='triageCount'></span>"
            "<button type='button' id='exportTriage' class='mini-btn' "
            "title='Download your statuses and notes as JSON'>Export triage</button>"
            "<label class='mini-btn' for='importTriage' "
            "title='Load a previously exported triage file'>Import triage"
            "<input type='file' id='importTriage' accept='.json,application/json' hidden></label>"
            "<button type='button' id='clearTriage' class='mini-btn' "
            "title='Remove all statuses and notes stored in this browser'>Clear</button>"
            "</div>")

    parts.append("<div class='flow-decision-summary' id='flowDecisionSummary' aria-label='Quick filters for flow and control triage decisions'></div><section class='flow-decision-findings' id='flowDecisionFindings' aria-labelledby='flowDecisionFindingsTitle'><div class='flow-decision-findings-head'><div><h2 id='flowDecisionFindingsTitle'>Flow/control triage decisions</h2><p>Decisions created in the Security Flow Explorer and matched by the status filter.</p></div><span class='flow-decision-findings-count' id='flowDecisionFindingsCount'>0 decisions</span></div><div class='flow-decision-findings-list' id='flowDecisionFindingsList'></div></section>")

    if not findings:
        parts.append("<div class='empty-note'>No findings above the configured threshold.</div>")
    else:
        parts.append("<div id='noMatch' class='empty-note' style='display:none'>No findings match your filter.</div>")

    for f in sort_findings(findings):
        search_blob = esc(" ".join([f.rule_id, f.rule_name, f.file, f.severity,
                                    f.status, f.note] + f.flow).lower())
        vuln_type = categorize_rule(f.rule_id)
        parts.append(f"<div class='card {f.severity}' data-search='{search_blob}' "
                     f"data-type='{esc(vuln_type)}'>")
        parts.append("<div class='card-head'>"
                     f"<span class='badge {f.severity}'>{f.severity}</span>"
                     f"<span class='badge type-badge'>{esc(vuln_type)}</span>"
                     f"<span class='card-title'>{esc(f.rule_id)} &ndash; {esc(f.rule_name)}</span>"
                     f"<span class='card-status'>({esc(f.status)})</span></div>")
        parts.append(f"<div class='loc'>{esc(f.file)}:{f.line}"
                     + (f" &middot; {esc(f.method)}()" if f.method else "") + "</div>")
        if f.code or f.context:
            rows = []
            width = len(str(f.context[-1][0])) if f.context else 0
            for n, line in f.context:
                marker = ">" if n == f.line else " "
                cls = " class='context-hit'" if n == f.line else ""
                num = str(n).rjust(width)
                rows.append(f"<span{cls}>{esc(marker + ' ' + num + ' | ' + line)}</span>")
            rendered = "\n".join(rows) if rows else esc(f.code)
            parts.append(f"<pre class='source-context'>{rendered}</pre>")
        if f.guards_found:
            parts.append(f"<div class='meta-line'><b>Set:</b> <code>{esc(', '.join(f.guards_found))}</code></div>")
        if f.guards_missing:
            parts.append("<div class='meta-line'><b>Missing:</b></div><ul class='missing'>" + "".join(
                f"<li>{esc(GUARD_HINTS.get(g, g))}</li>" for g in f.guards_missing) + "</ul>")
        if f.taint:
            parts.append(f"<div class='meta-line'>External input: {esc(', '.join(f.taint))}</div>")
        if f.flow:
            parts.append(f"<div class='meta-line'>Data flow: {esc(' -> '.join(f.flow))}</div>")
        if f.is_test:
            parts.append("<div class='meta-line'>Test code</div>")
        if f.note:
            parts.append(f"<div class='meta-line'>{esc(f.note)}</div>")
        parts.append(f"<span class='fp'>{esc(f.fingerprint)}</span>")
        rule = RULE_BY_ID.get(f.rule_id)
        fix_text = f.fix or (rule.fix if rule else "")
        if fix_text:
            parts.append(f"<details class='fix'><summary>Fix template</summary><pre>{esc(fix_text)}</pre></details>")
        # Triage row: the status is keyed by the finding's fingerprint, which is
        # stable across re-scans, so a decision made here survives into the next
        # report as long as the underlying code line is unchanged.
        parts.append(
            "<div class='triage'><label>Status</label>"
            f"<select class='triage-status' data-fp='{esc(f.fingerprint)}'>"
            "<option value=''>Open</option>"
            "<option value='confirmed'>Confirmed</option>"
                     "<option value='in-review'>In review</option>"
            "<option value='fixed'>Fixed</option>"
            "<option value='false-positive'>False positive</option>"
            "<option value='accepted'>Accepted risk</option>"
            "</select>"
            f"<input type='text' class='triage-note' data-fp='{esc(f.fingerprint)}' "
            "placeholder='Note (optional) — why fixed / why accepted …'>"
            "<span class='triage-saved'>saved</span></div>")
        parts.append("</div>")

    parts.append(f"<footer class='site-foot'>JSpringGuard <b>v{VERSION}</b> &middot; "
                 "runs entirely offline, nothing leaves this file."
                 f"<br>By <a href='{AUTHOR_URL}' target='_blank' "
                 f"rel='noopener noreferrer'>{AUTHOR}</a> &middot; "
                 f"<a href='{REPO_URL}' target='_blank' "
                 f"rel='noopener noreferrer'>github.com/{AUTHOR}/JSpringGuard</a>.</footer>")
    parts.append("</div>")
    parts.append(f"<script>{HTML_JS}</script>")
    parts.append("</body></html>")
    return "\n".join(parts)


def to_markdown(findings: List[Finding], scanned: int, builds: int,
                coverage: Optional[Sequence[CoverageEntry]] = None) -> str:
    out = ["# JSpringGuard Report", "",
           f"- Version: {VERSION}",
           f"- Author: [{AUTHOR}]({AUTHOR_URL}) &middot; [{REPO_URL}]({REPO_URL})",
           f"- Scanned: {scanned} source file(s), {builds} build file(s)",
           f"- Findings: {len(findings)}", ""]
    counts = summary_counts(findings)
    if counts:
        out.append("| Severity | Count |")
        out.append("|---|---|")
        for k in reversed(SEVERITY_LIST):
            if k in counts:
                out.append(f"| {k} | {counts[k]} |")
        out.append("")
    if coverage is not None:
        out += ["## Security control coverage", ""]
        if not coverage:
            out += ["No supported HTTP, listener, or scheduled entry points were found.", ""]
        else:
            out.append("| Entry point | " + " | ".join(label for _, label in _COVERAGE_COLUMNS) + " |")
            out.append("|---|" + "---|" * len(_COVERAGE_COLUMNS))
            for entry in coverage:
                values = [_COVERAGE_MARK.get(entry.controls.get(key, "UNKNOWN"), "UNKNOWN")
                          for key, _ in _COVERAGE_COLUMNS]
                out.append("| `" + entry.entrypoint.replace("|", "\\|") + "` | "
                           + " | ".join(values) + " |")
            out.append("")
            totals = coverage_summary(coverage)
            out.append("Coverage summary: " + "; ".join(
                f"{status}: {totals.get(status, 0)}"
                for status in ("COVERED", "MISSING", "UNKNOWN", "NOT_REQUIRED")))
            out.append("")
    if not findings:
        out.append("No findings at the selected filters.")
        out.append("")
        out.append(f"---\n*JSpringGuard v{VERSION} by [{AUTHOR}]({AUTHOR_URL}) - {REPO_URL}*")
        return "\n".join(out)

    out += ["## Findings", "", "| Severity | Status | Rule | Location | Code |", "|---|---|---|---|---|"]
    for f in sort_findings(findings):
        code = f.code.replace("|", "\\|")
        out.append(f"| {f.severity} | {f.status} | {f.rule_id} | `{f.file}:{f.line}` | `{code}` |")
    out.append("")
    out.append("## Details")
    out.append("")
    for f in sort_findings(findings):
        out.append(f"### {f.rule_id} - `{f.file}:{f.line}`")
        out.append("")
        out.append(f"- Status: **{f.status}** ({f.severity})")
        if f.method:
            out.append(f"- Method: `{f.method}()`")
        if f.guards_found:
            out.append(f"- Set: {', '.join(f.guards_found)}")
        if f.guards_missing:
            out.append("- Missing: " + "; ".join(GUARD_HINTS.get(g, g) for g in f.guards_missing))
        if f.taint:
            out.append(f"- External input in file: {', '.join(f.taint)}")
        if f.flow:
            out.append(f"- Data flow: `{' -> '.join(f.flow)}`")
        if f.note:
            out.append(f"- Note: {f.note}")
        out.append(f"- Fingerprint: `{f.fingerprint}`")
        source = finding_context_text(f)
        fence = "`" * max(3, 1 + max((len(m.group()) for m in re.finditer(r"`+", source)), default=0))
        out += ["", "Source context ( > marks the finding):", "", fence + "text", source, fence]
        rule = RULE_BY_ID.get(f.rule_id)
        fix_text = f.fix or (rule.fix if rule else "")
        if fix_text:
            out += ["", "```java", fix_text, "```"]
        out.append("")
    out.append(f"---\n*JSpringGuard v{VERSION} by [{AUTHOR}]({AUTHOR_URL}) - {REPO_URL}*")
    return "\n".join(out)


def to_sarif(findings: List[Finding]) -> dict:
    level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                 "LOW": "note", "INFO": "note"}
    rules_seen: Dict[str, dict] = {}
    results = []
    for f in findings:
        rules_seen.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.rule_name,
            "shortDescription": {"text": f.rule_name},
            "fullDescription": {"text": f.note or f.rule_name},
            "helpUri": rule_help_uri(f.rule_id),
            "help": {"text": f.note or f.rule_name},
        })
        results.append({
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "warning"),
            "partialFingerprints": {"xxeCheck/v1": f.fingerprint},
            "message": {"text": f"{f.status}: {f.rule_name}. "
                                f"Missing: {', '.join(f.guards_missing) or '-'}"
                                + (f". Flow: {' -> '.join(f.flow)}" if f.flow else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                    "region": {"startLine": f.line, "snippet": {"text": f.code}},
                    **({"contextRegion": {
                        "startLine": f.context[0][0], "endLine": f.context[-1][0],
                        "snippet": {"text": "\n".join(row for _, row in f.context)}
                    }} if f.context else {}),
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "JSpringGuard", "version": VERSION,
                                "organization": AUTHOR,
                                "informationUri": REPO_URL,
                                "rules": list(rules_seen.values())}},
            "results": results,
        }],
    }


# --------------------------------------------------------------------------
# Self-test, fix output, PoC
# --------------------------------------------------------------------------

SAMPLES = {
    "Vulnerable.java": '''
package demo;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.servlet.http.HttpServletRequest;

public class Vulnerable {
    public void handle(HttpServletRequest request) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder().parse(request.getInputStream());
    }
}
''',
    "Safe.java": '''
package demo;
import javax.xml.parsers.DocumentBuilderFactory;

public class Safe {
    public void handle(java.io.InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder().parse(in);
    }
}
''',
    "MethodScope.java": '''
package demo;
import javax.xml.parsers.DocumentBuilderFactory;

public class MethodScope {
    public void safeOne(java.io.InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder().parse(in);
    }

    public void unsafeOne(java.io.InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder().parse(in);
    }
}
''',
    "XmlUtils.java": '''
package demo;
import javax.xml.parsers.DocumentBuilderFactory;

public final class XmlUtils {
    public static DocumentBuilderFactory secureFactory() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf;
    }
}
''',
    "UsesHelper.java": '''
package demo;
import javax.xml.parsers.DocumentBuilderFactory;

public class UsesHelper {
    public void handle(java.io.InputStream in) throws Exception {
        DocumentBuilderFactory dbf = XmlUtils.secureFactory();
        dbf.newDocumentBuilder().parse(in);
    }
}
''',
    "Suppressed.java": '''
package demo;
import javax.xml.parsers.DocumentBuilderFactory;

public class Suppressed {
    public void handle(java.io.InputStream in) throws Exception {
        // sec-check:ignore - internal, self-generated XML structure only
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder().parse(in);
    }
}
''',
    "pom.xml": '''<project>
  <dependencies>
    <dependency>
      <groupId>dom4j</groupId>
      <artifactId>dom4j</artifactId>
      <version>2.1.1</version>
    </dependency>
    <dependency>
      <groupId>com.thoughtworks.xstream</groupId>
      <artifactId>xstream</artifactId>
      <version>1.4.10</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.security</groupId>
      <artifactId>spring-security-web</artifactId>
      <version>5.6.0</version>
    </dependency>
    <dependency>
      <groupId>com.nimbusds</groupId>
      <artifactId>nimbus-jose-jwt</artifactId>
      <version>9.10</version>
    </dependency>
  </dependencies>
</project>
''',
    "SecurityConfigBad.java": '''
package app;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
@EnableWebSecurity
public class SecurityConfigBad {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(c -> c.disable())
            .cors(c -> c.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/**").permitAll()
                .anyRequest().permitAll()
            )
            .rememberMe();
        return http.build();
    }
    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }
}
''',
    "application.properties": '''
management.endpoints.web.exposure.include=*
management.endpoint.shutdown.enabled=true
spring.security.debug=true
jwt.secret=mysecret
spring.datasource.password=admin123
server.ssl.client-auth=want
server.ssl.key-store-password=changeit
server.ssl.trust-store-password=trustme
spring.security.oauth2.client.provider.alpha.issuer-uri=https://alpha.example
spring.security.oauth2.client.provider.beta.issuer-uri=https://beta.example
''',
    "SecurityConfigGood.java": '''
package app;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.config.Customizer;
@EnableWebSecurity
public class SecurityConfigGood {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(Customizer.withDefaults())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation().newSession())
            .requiresChannel(c -> c.anyRequest().requiresSecure())
            .headers(h -> h
                .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true))
                .frameOptions(fo -> fo.deny())
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
''',
    "MoreVulnClasses.java": '''
package demo;
import java.io.File;
import org.springframework.web.client.RestTemplate;
import javax.naming.directory.DirContext;

public class MoreVulnClasses {
    public String fetch(String url) {
        RestTemplate rt = new RestTemplate();
        return rt.getForObject(url, String.class);   // SRC-SSRF
    }
    public String fetchSafe() {
        RestTemplate rt = new RestTemplate();
        return rt.getForObject("https://api.internal.example/health", String.class);
    }
    public void readFile(String filename) {
        File f = new File("/data/uploads/" + filename);   // SRC-PATH-TRAVERSAL
    }
    public void readFixed() {
        File f = new File("/data/fixed.txt");
    }
    public void doRedirect(String target, javax.servlet.http.HttpServletResponse resp) throws Exception {
        resp.sendRedirect(target);   // SRC-OPEN-REDIRECT
    }
    public void doRedirectSafe(javax.servlet.http.HttpServletResponse resp) throws Exception {
        resp.sendRedirect("/home");
    }
    public void ldapSearch(DirContext ctx, String user) throws Exception {
        ctx.search("ou=users", "(uid=" + user + ")", null);   // SRC-LDAP-INJECTION
    }
    public void sqliVuln(java.sql.Statement stmt, String username) throws Exception {
        String sql = "select * from users where username = '" + username + "'";
        stmt.executeQuery(sql);   // SRC-SQLI-VAR-CONCAT (cross-line)
    }
    public void sqliSafe(java.sql.Connection con, String username) throws Exception {
        String sql = "select * from users where username = ?";
        java.sql.PreparedStatement st = con.prepareStatement(sql);   // no finding: no '+' in assignment
        st.setString(1, username);
    }
}
''',
    "ShortHardcodedSecret.java": '''
package demo;
public class ShortHardcodedSecret {
    private static final String SECRET = "123456";   // SpringSecurityCheck-HARDCODED-SECRET (short value)
}
''',
    "JwtBadConfig.java": '''
package demo;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

// JWT-NO-EXPIRY: signed without .expiration()
// JWT-NO-AUDIENCE: no .audience() set
// JWT-BLANK-SECRET: empty secret
// HARDEN-JWT-STRONG-ALG: NOT present (HS256 implicit)
public class JwtBadConfig {
    public String buildToken(String userId) {
        return Jwts.builder()
                .subject(userId)
                .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor("".getBytes()))
                .compact();
    }

    // JWT-JWKS-HTTP: plain HTTP JWK URI
    public io.jsonwebtoken.JwtParser buildParserBad() {
        return Jwts.parserBuilder()
                .setSigningKey(io.jsonwebtoken.Jwts.SIG.RS256.keyPair().build().getPublic())
                .build();
    }

    public static final String JWKS = "http://auth.example.com/.well-known/jwks.json";  // JWT-JWKS-HTTP
    public void loadJwks() throws Exception {
        org.springframework.security.oauth2.jwt.NimbusJwtDecoder
            .withJwkSetUri("http://auth.example.com/.well-known/jwks.json").build();
    }
}
''',
    "JwtGoodConfig.java": '''
package demo;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import java.util.Date;

// HARDEN-JWT-STRONG-ALG + HARDEN-JWT-EXPIRY-SET + HARDEN-JWT-ISSUER-VALIDATION
// HARDEN-JWT-SECRET-FROM-ENV
public class JwtGoodConfig {
    @Value("${app.jwt.secret}")
    private String jwtSecret;

    public String buildToken(String userId) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(userId)
                .issuer("https://auth.example.com")
                .audience().add("my-api").and()
                .expiration(new Date(now + 900_000L))
                .signWith(SignatureAlgorithm.RS256,
                          java.security.KeyFactory.getInstance("RSA"))
                .compact();
    }

    public io.jsonwebtoken.JwtParser buildParser() {
        return Jwts.parserBuilder()
                .requireIssuer("https://auth.example.com")
                .setSigningKey(getPublicKey())
                .build();
    }
    private java.security.PublicKey getPublicKey() { return null; }
}
''',
    "Oauth2BadConfig.java": '''
package demo;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

// OAUTH2-TOKEN-LOGGING: Bearer token in logger
// OAUTH2-INTROSPECTION-HTTP: plain HTTP introspection endpoint
// OAUTH2-SCOPE-HARDCODED: scope baked into source
public class Oauth2BadConfig {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Oauth2BadConfig.class);

    public void logToken(String accessToken) {
        log.debug("Received accessToken: " + accessToken);   // OAUTH2-TOKEN-LOGGING
    }

    public void setupIntrospection() {
        String introspectionUri = "http://auth.example.com/oauth/introspect";  // OAUTH2-INTROSPECTION-HTTP
    }

    public void setupScopes() {
        registration.scopes("openid", "profile");  // OAUTH2-SCOPE-HARDCODED
    }
    private Object registration;
}
''',
    "JwtHeaderUrlBad.java": '''
package demo;
import java.net.URL;
import com.nimbusds.jose.jwk.JWKSet;

public class JwtHeaderUrlBad {
    public java.io.File loadKid(org.springframework.security.oauth2.jwt.Jwt jwt) {
        String kid = jwt.getHeader("kid");
        return new java.io.File(kid); // JWT-KID-INJECTION
    }

    public JWKSet loadJku(org.springframework.security.oauth2.jwt.Jwt jwt) throws Exception {
        String jku = jwt.getHeaders().get("jku").toString();
        return JWKSet.load(new URL(jku)); // JWT-JKU-INJECTION
    }

    public java.io.InputStream loadX5u(com.nimbusds.jwt.SignedJWT token) throws Exception {
        String x5u = token.getHeader().getX509CertURL().toString();
        URL certificateUrl = new URL(x5u); // JWT-X5U-INJECTION
        return certificateUrl.openStream();
    }
}
''',
    "PkcePlainBad.java": '''
package demo;
public class PkcePlainBad {
    public void configure() {
        request.codeChallengeMethod("plain"); // OAUTH2-PKCE-PLAIN
    }
    private Object request;
}
''',
    "CookieJwtAuth.java": '''
package demo;
import org.springframework.web.bind.annotation.CookieValue;
public class CookieJwtAuth {
    public String authenticate(@CookieValue("access_token") String token) {
        return token;
    }
}
''',
    "IdorDataflow.java": '''
package demo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
public class IdorDataflow {
    @GetMapping("/orders/{id}")
    public Object order(@PathVariable Long id) {
        Long lookupId = id;
        return orderRepository.findById(lookupId).orElseThrow(); // AUTHZ-IDOR-DATAFLOW
    }
    private Object orderRepository;
}
''',
    "IdorAuthorized.java": '''
package demo;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
public class IdorAuthorized {
    @PreAuthorize("hasPermission(#id, 'Order', 'read')")
    @GetMapping("/orders/{id}")
    public Object order(@PathVariable Long id) {
        return orderRepository.findById(id).orElseThrow();
    }
    private Object orderRepository;
}
''',
    "JwtEmbeddedKeyBad.java": '''
package demo;
public class JwtEmbeddedKeyBad {
    public Object trustJwk(org.springframework.security.oauth2.jwt.Jwt jwt) throws Exception {
        Object embeddedJwk = jwt.getHeaders().get("jwk");
        return com.nimbusds.jose.jwk.JWK.parse(embeddedJwk.toString()).toRSAKey().toPublicKey();
    }
    public Object trustX5c(com.nimbusds.jwt.SignedJWT token) throws Exception {
        Object embeddedChain = token.getHeader().get("x5c");
        return com.nimbusds.jose.util.X509CertChainUtils.parse(embeddedChain.toString()).get(0);
    }
}
''',
    "JwtEmbeddedKeyGood.java": '''
package demo;
public class JwtEmbeddedKeyGood {
    public Object fixedKey() throws Exception {
        return com.nimbusds.jose.jwk.JWK.parse(TRUSTED_SERVER_CONFIG).toRSAKey().toPublicKey();
    }
    public Object validatedChain(com.nimbusds.jwt.SignedJWT token) throws Exception {
        Object chain = token.getHeader().get("x5c");
        java.security.cert.CertPathValidator.getInstance("PKIX");
        return com.nimbusds.jose.util.X509CertChainUtils.parse(chain.toString()).get(0);
    }
    private static final String TRUSTED_SERVER_CONFIG = "configured-key";
}
''',
    "AuthzMatcherOrderBad.java": '''
package demo;
public class AuthzMatcherOrderBad {
    public void configure(Object auth) {
        auth.requestMatchers("/**").permitAll()
            .requestMatchers("/admin/**").hasRole("ADMIN");
    }
}
''',
    "AuthzMatcherOrderGood.java": '''
package demo;
public class AuthzMatcherOrderGood {
    public void configure(Object auth) {
        auth.requestMatchers("/admin/**").hasRole("ADMIN")
            .requestMatchers("/public/**").permitAll()
            .anyRequest().authenticated();
    }
}
''',
    "OauthTokenSemanticsBad.java": '''
package demo;
public class OauthTokenSemanticsBad {
    public boolean redirectAllowed(String redirectUri, String registeredRedirect) {
        return redirectUri.startsWith(registeredRedirect);
    }
    public void buildUrl(Object builder, String accessToken, String clientSecret) {
        builder.queryParam("access_token", accessToken);
        builder.queryParam("client_secret", clientSecret);
    }
    public void forwardIdToken(Object oidcUser, Object headers) {
        String idToken = oidcUser.getIdToken().getTokenValue();
        headers.setBearerAuth(idToken);
    }
    public boolean validateAudience(org.springframework.security.oauth2.core.oidc.OidcIdToken idToken,
                                    String clientId) {
        return idToken.getAudience().contains(clientId);
    }
    public Object authenticate(String rawToken, Object decoder) {
        Object jwt = decoder.decode(rawToken);
        return new JwtAuthenticationToken(jwt);
    }
}
''',
    "OauthTokenSemanticsGood.java": '''
package demo;
public class OauthTokenSemanticsGood {
    public boolean redirectAllowed(String redirectUri, java.util.Set<String> registered) {
        return registered.contains(java.net.URI.create(redirectUri).normalize().toString());
    }
    public void forwardAccessToken(String accessToken, Object headers) {
        headers.setBearerAuth(accessToken);
    }
    public boolean validateAudience(org.springframework.security.oauth2.core.oidc.OidcIdToken idToken,
                                    String clientId) {
        return idToken.getAudience().contains(clientId)
            && clientId.equals(idToken.getClaimAsString("azp"));
    }
    public Object authenticate(String rawToken, Object decoder) {
        Object jwt = decoder.decode(rawToken);
        if (!"access".equals(jwt.getClaimAsString("token_use"))) throw new RuntimeException();
        return new JwtAuthenticationToken(jwt);
    }
}
''',
    "RefreshLifecycleBad.java": '''
package demo;
public class RefreshLifecycleBad {
    public String refresh(String refreshToken) {
        return generateAccessToken(refreshToken);
    }
    public void logout() {
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
    }
    private String generateAccessToken(String value) { return value; }
}
''',
    "RefreshRotationGood.java": '''
package demo;
public class RefreshRotationGood {
    public String refresh(String refreshToken) {
        String replacement = generateRefreshToken();
        refreshTokenRepository.save(replacement);
        return generateAccessToken(refreshToken);
    }
    private String generateRefreshToken() { return "new"; }
    private String generateAccessToken(String value) { return value; }
    private Object refreshTokenRepository;
}
''',
    "TlsBadConfig.java": '''
package demo;
public class TlsBadConfig {
    String keyStorePassword = "changeit";
    String trustStorePassword = "trustme";
    public void configure(javax.net.ssl.SSLEngine engine,
                          java.security.cert.PKIXParameters params) throws Exception {
        javax.net.ssl.SSLContext.getInstance("TLSv1.1");
        engine.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"});
        Object trust = new org.apache.http.conn.ssl.TrustSelfSignedStrategy();
        params.setRevocationEnabled(false);
        engine.setWantClientAuth(true);
    }
}
''',
    "TlsGoodConfig.java": '''
package demo;
public class TlsGoodConfig {
    String keyStorePassword = System.getenv("TLS_KEYSTORE_PASSWORD");
    String trustStorePassword = System.getenv("TLS_TRUSTSTORE_PASSWORD");
    public void configure(javax.net.ssl.SSLEngine engine,
                          java.security.cert.PKIXParameters params) throws Exception {
        javax.net.ssl.SSLContext.getInstance("TLSv1.3");
        engine.setEnabledCipherSuites(new String[]{"TLS_AES_256_GCM_SHA384"});
        params.setRevocationEnabled(true);
        engine.setNeedClientAuth(true);
    }
}
''',
    "FilterChainsBad.java": '''
package demo;
public class FilterChainsBad {
    @Bean @Order(1)
    public SecurityFilterChain fallback(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).build();
    }
    @Bean @Order(2)
    public SecurityFilterChain api(HttpSecurity http) throws Exception {
        return http.securityMatcher("/api/**")
            .authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();
    }
}
''',
    "FilterChainsNoFallback.java": '''
package demo;
public class FilterChainsNoFallback {
    @Bean @Order(1)
    public SecurityFilterChain api(HttpSecurity http) throws Exception {
        return http.securityMatcher("/api/**").build();
    }
    @Bean @Order(2)
    public SecurityFilterChain admin(HttpSecurity http) throws Exception {
        return http.securityMatcher("/admin/**").build();
    }
}
''',
    "FilterChainsGood.java": '''
package demo;
public class FilterChainsGood {
    @Bean @Order(1)
    public SecurityFilterChain api(HttpSecurity http) throws Exception {
        return http.securityMatcher("/api/**").build();
    }
    @Bean @Order(99)
    public SecurityFilterChain fallback(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();
    }
}
''',
    "TenantController.java": '''
package demo;
public class TenantController {
    public Object order(@PathVariable String tenantId, @PathVariable Long id) {
        return tenantService.load(tenantId, id);
    }
    private Object tenantService;
}
''',
    "TenantService.java": '''
package demo;
public class TenantService {
    public Object load(String scope, Long id) {
        return orderRepository.findById(id).orElseThrow();
    }
    private Object orderRepository;
}
''',
    "TenantFlowGood.java": '''
package demo;
public class TenantFlowGood {
    public Object order(@PathVariable String tenantId, @PathVariable Long id) {
        String currentTenant = tenantFromAuthentication();
        return orderRepository.findByIdAndTenantId(id, currentTenant).orElseThrow();
    }
    private String tenantFromAuthentication() { return "trusted"; }
    private Object orderRepository;
}
''',
    "CoverageSecurityConfig.java": '''
package demo;
public class CoverageSecurityConfig {
    public SecurityFilterChain coverage(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/coverage-open/**").permitAll()
            .requestMatchers("/coverage-secure/**").hasRole("USER")
            .anyRequest().authenticated()).build();
    }
}
''',
    "CoverageBadController.java": '''
package demo;
public class CoverageBadController {
    @PostMapping("/coverage-open/orders/{tenantId}/{id}")
    public Object update(@PathVariable String tenantId, @PathVariable Long id,
                         @RequestBody OrderUpdate input) {
        return coverageOrderService.update(tenantId, id, input);
    }
    @PostMapping("/coverage-open/login")
    public Object login(@RequestBody LoginRequest input) {
        return authenticationManager.authenticate(input);
    }
    private Object coverageOrderService;
    private Object authenticationManager;
}
''',
    "CoverageGoodController.java": '''
package demo;
public class CoverageGoodController {
    @PreAuthorize("hasAuthority('orders:write')")
    @PostMapping("/coverage-secure/orders/{tenantId}/{id}")
    public Object update(@PathVariable String tenantId, @PathVariable Long id,
                         @Valid @RequestBody OrderUpdate input) {
        String currentTenant = tenantFromAuthentication();
        auditService.recordAudit(id, currentTenant);
        return coverageOrderService.update(currentTenant, id, input);
    }
    private String tenantFromAuthentication() { return "trusted"; }
    private Object coverageOrderService;
    private Object auditService;
}
''',
    "CoverageOrderService.java": '''
package demo;
public class CoverageOrderService {
    public Object update(String tenantId, Long id, OrderUpdate input) {
        Object order = orderRepository.findById(id).orElseThrow();
        return orderRepository.save(order);
    }
    private Object orderRepository;
}
''',
    "CoverageEntryPoints.java": '''
package demo;
@RestController
@RequestMapping("/coverage-secure/catalog")
public class CoverageEntryPoints {
    @PreAuthorize("hasAuthority('catalog:read')")
    @GetMapping("/items")
    public Object items() {
        return catalogRepository.findAll();
    }
    @PreAuthorize("hasAuthority('orders:consume')")
    @KafkaListener(topics = "orders")
    public void consume(@Valid OrderEvent event) {
        auditService.recordAudit(event);
        orderRepository.save(event);
    }
    @Scheduled(cron = "0 0 * * * *")
    public void cleanup() {
        auditService.recordAudit("cleanup");
        orderRepository.deleteExpired();
    }
    private Object catalogRepository;
    private Object orderRepository;
    private Object auditService;
}
''',
    "AdvancedJwtBad.java": '''
package demo;
public class AdvancedJwtBad {
    private Object sharedKey;
    public Object readNested(String raw, Object decrypter) throws Exception {
        EncryptedJWT token = EncryptedJWT.parse(raw);
        token.decrypt(decrypter);
        return token.getJWTClaimsSet();
    }
    public Object resolveKey(SignedJWT token) {
        SigningKeyResolver resolver = null;
        String kid = token.getHeader().getKeyID();
        return keys.get(kid);
    }
    public String generateAccessToken() { return Jwts.builder().signWith(sharedKey).compact(); }
    public String generateRefreshToken() { return Jwts.builder().signWith(sharedKey).compact(); }
    public void compressed(Object header) {
        header.setCompressionAlgorithm(CompressionAlgorithmIdentifiers.DEF);
    }
    private java.util.Map<String,Object> keys;
}
''',
    "AdvancedJwtGood.java": '''
package demo;
public class AdvancedJwtGood {
    private Object accessKey, refreshKey;
    public Object readNested(String raw, Object decrypter, Object trustedVerifier) throws Exception {
        EncryptedJWT token = EncryptedJWT.parse(raw);
        token.decrypt(decrypter);
        SignedJWT inner = token.getPayload().toSignedJWT();
        if (!inner.verify(trustedVerifier)) throw new RuntimeException();
        return inner.getJWTClaimsSet();
    }
    public String generateAccessToken() { return Jwts.builder().signWith(accessKey).compact(); }
    public String generateRefreshToken() { return Jwts.builder().signWith(refreshKey).compact(); }
}
''',
    "OauthMixupBad.java": '''
package demo;
public class OauthMixupBad {
    @GetMapping("/oauth/callback")
    public Object callback(String code) {
        return exchangeAuthorizationCode(code);
    }
}
''',
    "DpopBad.java": '''
package demo;
public class DpopBad {
    public boolean validateDPoP(String accessToken, Object proof, Object response) {
        java.time.Duration maxAge = java.time.Duration.ofMinutes(10);
        response.setHeader("DPoP-Nonce", createNonce());
        return proof.verify();
    }
}
''',
    "DpopGood.java": '''
package demo;
public class DpopGood {
    public boolean validateDPoP(String accessToken, Object proof, Object request, String expectedNonce) {
        String jti = proof.getJWTID();
        replayCache.putIfAbsent(jti, proof.getIssueTime());
        proof.getClaim("htm").equals(request.getMethod());
        proof.getClaim("htu").equals(request.getRequestURL());
        java.time.Duration maxAge = java.time.Duration.ofMinutes(5);
        proof.getClaim("ath");
        return expectedNonce.equals(proof.getClaim("nonce"));
    }
    private java.util.Map replayCache;
}
''',
    "Pkcs12Bad.java": '''
package demo;
public class Pkcs12Bad {
    public void load(java.io.InputStream in) throws Exception {
        java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
        store.load(in, null);
    }
}
''',
    "PasswordResetBad.java": '''
package demo;
public class PasswordResetBad {
    public String createResetToken(String email) {
        String resetToken = Long.toString(System.currentTimeMillis()) + new java.util.Random().nextInt();
        resetTokenRepository.save(resetToken);
        return resetToken;
    }
    public void resetPassword(String resetToken, String password) {
        Object token = resetTokenRepository.findByToken(resetToken);
        user.setPassword(passwordEncoder.encode(password));
    }
    private Object resetTokenRepository, user, passwordEncoder;
}
''',
    "PasswordResetGood.java": '''
package demo;
public class PasswordResetGood {
    public String createResetToken() {
        byte[] value = new byte[32];
        new java.security.SecureRandom().nextBytes(value);
        java.time.Instant expiresAt = java.time.Instant.now().plus(java.time.Duration.ofMinutes(15));
        return resetTokens.save(value, expiresAt);
    }
    public void resetPassword(String resetToken, String password) {
        Object token = resetTokens.findByToken(resetToken);
        resetTokens.markUsed(token);
        user.setPassword(passwordEncoder.encode(password));
    }
}
''',
    "AuthResilienceBad.java": '''
package demo;
public class AuthResilienceBad {
    @PostMapping("/login")
    public Object login(String username, String password) {
        return authenticationManager.authenticate(username, password);
    }
    public boolean verifyMFA(String otp) {
        try { return mfaService.verify(otp); }
        catch (Exception unavailable) { return true; }
    }
}
''',
    "AuthResilienceGood.java": '''
package demo;
public class AuthResilienceGood {
    @PostMapping("/login")
    public Object login(String username, String password) {
        rateLimiter.acquire(username);
        return authenticationManager.authenticate(username, password);
    }
    public boolean verifyMFA(String otp) {
        try { return mfaService.verify(otp); }
        catch (Exception unavailable) { return false; }
    }
}
''',
    "test-private.key": '''-----BEGIN PRIVATE KEY-----
TEST-ONLY-NOT-A-REAL-KEY
-----END PRIVATE KEY-----
''',
    "Oauth2GoodConfig.java": '''
package demo;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;

// HARDEN-OAUTH2-PKCE-ENABLED + HARDEN-OAUTH2-STATE-PARAM
// HARDEN-JWT-AUDIENCE-VALIDATION + HARDEN-JWT-CLOCK-SKEW
public class Oauth2GoodConfig {
    public void configureValidator() {
        // audience check
        new org.springframework.security.oauth2.jwt.JwtClaimValidator<java.util.List<String>>("aud", a -> a.contains("my-api"));
        // bounded clock skew
        new org.springframework.security.oauth2.jwt.JwtTimestampValidator(java.time.Duration.ofMinutes(2));
        // PKCE
        boolean requireProofKey = registration.requireProofKey(true);
        // state
        request.state(java.util.UUID.randomUUID().toString());
    }
    private Object registration, request;
}
''',
    "CryptoVulnConfig.java": '''
package demo;
import javax.crypto.Cipher;
import java.security.SecureRandom;

// SRC-CRYPTO-RSA-NO-OAEP + SRC-CRYPTO-STATIC-IV + SRC-RANDOM-PREDICTABLE-SEED
public class CryptoVulnConfig {
    public void badRsa() throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");  // SRC-CRYPTO-RSA-NO-OAEP
    }
    public void badIv() throws Exception {
        javax.crypto.spec.GCMParameterSpec spec =
            new javax.crypto.spec.GCMParameterSpec(128, new byte[12]);  // SRC-CRYPTO-STATIC-IV
    }
    public void badSeed() {
        SecureRandom rng = new SecureRandom(new byte[]{1,2,3,4});  // SRC-RANDOM-PREDICTABLE-SEED
    }
}
''',
    "CryptoGoodConfig.java": '''
package demo;
import javax.crypto.Cipher;
import java.security.SecureRandom;

// HARDEN-RSA-OAEP + HARDEN-CRYPTO-GCM-RANDOM-IV
public class CryptoGoodConfig {
    public void goodRsa() throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");  // HARDEN-RSA-OAEP
    }
    public void goodIv() throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);  // HARDEN-CRYPTO-GCM-RANDOM-IV
        new javax.crypto.spec.GCMParameterSpec(128, iv);
    }
}
''',
    "SpringSecBadMisc.java": '''
package demo;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.access.prepost.PreAuthorize;

// SpringSecurityCheck-REGEX-NO-DOTALL + SRC-SSTI-VIEW-NAME
public class SpringSecBadMisc {
    public org.springframework.security.web.util.matcher.RegexRequestMatcher buildMatcher() {
        return new RegexRequestMatcher("/admin/.*", null);  // SpringSecurityCheck-REGEX-NO-DOTALL
    }
    public String handleView(String viewName) {
        return "redirect:" + viewName;  // SRC-SSTI-VIEW-NAME
    }
}
''',
}


def run_selftest() -> int:
    tmp = tempfile.mkdtemp(prefix="jspringguard_")
    coverage_fixture = os.path.join(tmp, 'coverage-fixture')
    os.makedirs(coverage_fixture, exist_ok=True)
    with open(os.path.join(coverage_fixture, 'pom.xml'), 'w', encoding='utf-8') as handle:
        handle.write('<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>'
                     '<artifactId>coverage</artifactId><version>1</version></project>')
    for name, content in SAMPLES.items():
        if name.startswith('Coverage'):
            content = content.replace('private Object coverageOrderService;',
                                      'private CoverageOrderService coverageOrderService;')
            if name == 'CoverageSecurityConfig.java':
                content = content.replace('public class', '@EnableMethodSecurity\npublic class', 1)
            name = os.path.join('coverage-fixture', name)
        with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
            fh.write(content)

    coverage: List[CoverageEntry] = []
    findings = scan(tmp, exts=DEFAULT_EXTS, exclude=set(DEFAULT_EXCLUDE_DIRS),
                    skip_tests=False, show_hardened=True, jobs=2, with_deps=True,
                    coverage_out=coverage)[0]

    by_key: Dict[str, Finding] = {}
    for f in findings:
        by_key[f"{os.path.basename(f.file)}:{f.line}"] = f

    def status_of(fname: str) -> List[str]:
        return [f.status for f in findings if os.path.basename(f.file) == fname]

    def has_rule(fname: str, rid: str) -> bool:
        return any(os.path.basename(f.file) == fname and f.rule_id == rid for f in findings)
    def rule_status(fname: str, rid: str) -> List[str]:
        return [f.status for f in findings if os.path.basename(f.file) == fname and f.rule_id == rid]
    def coverage_entry(entrypoint: str) -> Optional[CoverageEntry]:
        return next((entry for entry in coverage if entry.entrypoint == entrypoint), None)
    def coverage_status(entrypoint: str, control: str) -> str:
        entry = coverage_entry(entrypoint)
        return entry.controls.get(control, "") if entry else ""

    checks: List[Tuple[str, bool]] = [
        # XXE
        ("Vulnerable.java detected", status_of("Vulnerable.java") == ["VULNERABLE"]),
        ("Safe.java marked as hardened",
         status_of("Safe.java") == ["HARDENED", "HARDENED"]),
        ("Method scope separates safe/unsafe",
         sorted(status_of("MethodScope.java")) == ["HARDENED", "HARDENED", "VULNERABLE"]),
        ("Helper factory resolved", status_of("UsesHelper.java") == ["HARDENED"]),
        ("Suppression applies", status_of("Suppressed.java") == []),
        ("dom4j 2.1.1 flagged for dependency review",
         any(f.rule_id == "DEP-DOM4J" and f.status == "REVIEW" for f in findings)),
        ("XStream 1.4.10 flagged for dependency review",
         any(f.rule_id == "DEP-XSTREAM" and f.status == "REVIEW" for f in findings)),
        # Spring Security
        ("SpringSecurityCheck-CSRF-DISABLED detected (bad config)",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-CSRF-DISABLED")),
        ("SpringSecurityCheck-ANY-REQUEST-PERMIT detected",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-ANY-REQUEST-PERMIT")),
        ("SpringSecurityCheck-NOOP-ENCODER detected",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-NOOP-ENCODER")),
        ("SpringSecurityCheck-REMEMBERME-NO-KEY detected",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-REMEMBERME-NO-KEY")),
        ("spring-security-web 5.6.0 flagged for dependency review",
         any(f.rule_id == "DEP-SPRING-SECURITY-WEB" and f.status == "REVIEW" for f in findings)),
        ("nimbus-jose-jwt 9.10 flagged for dependency review",
         any(f.rule_id == "DEP-NIMBUS-JOSE-JWT" and f.status == "REVIEW" for f in findings)),
        ("SpringSecurityCheck-PROP-ACTUATOR-ALL detected",
         has_rule("application.properties", "SpringSecurityCheck-PROP-ACTUATOR-ALL")),
        ("SpringSecurityCheck-PROP-SHUTDOWN detected",
         has_rule("application.properties", "SpringSecurityCheck-PROP-SHUTDOWN")),
        ("SecurityConfigGood.java has no CRITICAL/HIGH findings",
         not any(os.path.basename(f.file) == "SecurityConfigGood.java"
                 and f.severity in ("CRITICAL", "HIGH")
                 and f.status not in ("HARDENED",) for f in findings)),
        # More vulnerability class examples
        ("SRC-SSRF detected", has_rule("MoreVulnClasses.java", "SRC-SSRF")),
        ("SRC-PATH-TRAVERSAL detected", has_rule("MoreVulnClasses.java", "SRC-PATH-TRAVERSAL")),
        ("SRC-OPEN-REDIRECT detected", has_rule("MoreVulnClasses.java", "SRC-OPEN-REDIRECT")),
        ("SRC-LDAP-INJECTION detected", has_rule("MoreVulnClasses.java", "SRC-LDAP-INJECTION")),
        # #1: cross-line SQLi (query built via concatenation, executed on a later line)
        ("SRC-SQLI-VAR-CONCAT detected", has_rule("MoreVulnClasses.java", "SRC-SQLI-VAR-CONCAT")),
        ("SRC-SQLI-VAR-CONCAT does not fire on a literal-only prepared statement",
         not any(os.path.basename(f.file) == "MoreVulnClasses.java" and f.line >= 12
                 and f.rule_id == "SRC-SQLI-VAR-CONCAT" and "sqliSafe" in (f.method or "")
                 for f in findings)),
        # #2: short hardcoded secrets (e.g. "123456") are no longer missed
        ("SpringSecurityCheck-HARDCODED-SECRET detected for a short value",
         has_rule("ShortHardcodedSecret.java", "SpringSecurityCheck-HARDCODED-SECRET")),
        # JWT rules
        ("JWT-NO-EXPIRY detected on JwtBadConfig",
         has_rule("JwtBadConfig.java", "JWT-NO-EXPIRY")),
        ("JWT-BLANK-SECRET detected on JwtBadConfig",
         has_rule("JwtBadConfig.java", "JWT-BLANK-SECRET")),
        ("JWT-JWKS-HTTP detected on JwtBadConfig",
         has_rule("JwtBadConfig.java", "JWT-JWKS-HTTP")),
        ("HARDEN-JWT-EXPIRY-SET fires on JwtGoodConfig",
         has_rule("JwtGoodConfig.java", "HARDEN-JWT-EXPIRY-SET")),
        ("HARDEN-JWT-ISSUER-VALIDATION fires on JwtGoodConfig",
         has_rule("JwtGoodConfig.java", "HARDEN-JWT-ISSUER-VALIDATION")),
        ("HARDEN-JWT-SECRET-FROM-ENV fires on JwtGoodConfig",
         has_rule("JwtGoodConfig.java", "HARDEN-JWT-SECRET-FROM-ENV")),
        # OAuth2 rules
        ("OAUTH2-TOKEN-LOGGING detected on Oauth2BadConfig",
         has_rule("Oauth2BadConfig.java", "OAUTH2-TOKEN-LOGGING")),
        ("OAUTH2-INTROSPECTION-HTTP detected on Oauth2BadConfig",
         has_rule("Oauth2BadConfig.java", "OAUTH2-INTROSPECTION-HTTP")),
        ("OAUTH2-SCOPE-HARDCODED detected on Oauth2BadConfig",
         has_rule("Oauth2BadConfig.java", "OAUTH2-SCOPE-HARDCODED")),
        ("JWT-JKU-INJECTION tracks jku into a remote JWK loader",
         has_rule("JwtHeaderUrlBad.java", "JWT-JKU-INJECTION")),
        ("JWT-X5U-INJECTION tracks x5u into a certificate URL",
         has_rule("JwtHeaderUrlBad.java", "JWT-X5U-INJECTION")),
        ("JWT-KID-INJECTION produces a valid finding instead of crashing",
         has_rule("JwtHeaderUrlBad.java", "JWT-KID-INJECTION")),
        ("OAUTH2-PKCE-PLAIN detected on PkcePlainBad",
         has_rule("PkcePlainBad.java", "OAUTH2-PKCE-PLAIN")),
        ("CSRF disabled plus JWT cookie correlation detected",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-CSRF-DISABLED-JWT-COOKIE")),
        ("AUTHZ-IDOR-DATAFLOW tracks PathVariable into repository lookup",
         has_rule("IdorDataflow.java", "AUTHZ-IDOR-DATAFLOW")),
        ("AUTHZ-IDOR-DATAFLOW accepts visible @PreAuthorize enforcement",
         not has_rule("IdorAuthorized.java", "AUTHZ-IDOR-DATAFLOW")),
        ("OAUTH2-PKCE-PLAIN does not flag the S256/requireProofKey example",
         not has_rule("Oauth2GoodConfig.java", "OAUTH2-PKCE-PLAIN")),
        ("JWT-EMBEDDED-JWK-TRUST tracks embedded key material",
         has_rule("JwtEmbeddedKeyBad.java", "JWT-EMBEDDED-JWK-TRUST")),
        ("JWT-X5C-TRUST tracks an embedded certificate chain",
         has_rule("JwtEmbeddedKeyBad.java", "JWT-X5C-TRUST")),
        ("Embedded-key rules accept configured keys and validated x5c chains",
         not has_rule("JwtEmbeddedKeyGood.java", "JWT-EMBEDDED-JWK-TRUST")
         and not has_rule("JwtEmbeddedKeyGood.java", "JWT-X5C-TRUST")),
        ("AUTHZ-MATCHER-ORDER detects a shadowed admin matcher",
         has_rule("AuthzMatcherOrderBad.java", "AUTHZ-MATCHER-ORDER")),
        ("AUTHZ-MATCHER-ORDER accepts specific-before-broad ordering",
         not has_rule("AuthzMatcherOrderGood.java", "AUTHZ-MATCHER-ORDER")),
        ("AUTHZ-PREAUTHORIZE-WITHOUT-METHODSECURITY detected",
         has_rule("IdorAuthorized.java", "AUTHZ-PREAUTHORIZE-WITHOUT-METHODSECURITY")),
        ("OAUTH2-REDIRECT-PREFIX-MATCH detected",
         has_rule("OauthTokenSemanticsBad.java", "OAUTH2-REDIRECT-PREFIX-MATCH")),
        ("OAUTH2-TOKEN-QUERY-PARAM detected",
         has_rule("OauthTokenSemanticsBad.java", "OAUTH2-TOKEN-QUERY-PARAM")),
        ("OAUTH2-CLIENT-SECRET-URL detected",
         has_rule("OauthTokenSemanticsBad.java", "OAUTH2-CLIENT-SECRET-URL")),
        ("OIDC-IDTOKEN-AS-ACCESS-TOKEN tracks an ID token into Bearer auth",
         has_rule("OauthTokenSemanticsBad.java", "OIDC-IDTOKEN-AS-ACCESS-TOKEN")),
        ("OIDC-AZP-NOT-VALIDATED detected on custom audience validation",
         has_rule("OauthTokenSemanticsBad.java", "OIDC-AZP-NOT-VALIDATED")),
        ("JWT-TOKEN-TYPE-CONFUSION detected on custom authentication",
         has_rule("OauthTokenSemanticsBad.java", "JWT-TOKEN-TYPE-CONFUSION")),
        ("Token-semantic rules accept exact redirects, access tokens, azp and token_use checks",
         not any(os.path.basename(f.file) == "OauthTokenSemanticsGood.java" and f.rule_id in {
             "OAUTH2-REDIRECT-PREFIX-MATCH", "OIDC-IDTOKEN-AS-ACCESS-TOKEN",
             "OIDC-AZP-NOT-VALIDATED", "JWT-TOKEN-TYPE-CONFUSION"} for f in findings)),
        ("REFRESH-TOKEN-NO-ROTATION detected",
         has_rule("RefreshLifecycleBad.java", "REFRESH-TOKEN-NO-ROTATION")),
        ("REFRESH-TOKEN-NO-ROTATION accepts visible rotation",
         not has_rule("RefreshRotationGood.java", "REFRESH-TOKEN-NO-ROTATION")),
        ("REFRESH-TOKEN-NO-REVOKE-ON-LOGOUT detected",
         has_rule("RefreshLifecycleBad.java", "REFRESH-TOKEN-NO-REVOKE-ON-LOGOUT")),
        ("TLS-OLD-PROTOCOL detected",
         has_rule("TlsBadConfig.java", "TLS-OLD-PROTOCOL")),
        ("TLS-WEAK-CIPHER detected",
         has_rule("TlsBadConfig.java", "TLS-WEAK-CIPHER")),
        ("TLS-TRUST-SELF-SIGNED detected",
         has_rule("TlsBadConfig.java", "TLS-TRUST-SELF-SIGNED")),
        ("TLS-REVOCATION-DISABLED detected",
         has_rule("TlsBadConfig.java", "TLS-REVOCATION-DISABLED")),
        ("TLS-MTLS-WANT-INSTEAD-OF-NEED detected",
         has_rule("TlsBadConfig.java", "TLS-MTLS-WANT-INSTEAD-OF-NEED")),
        ("TLS-KEYSTORE-PASSWORD-HARDCODED detected",
         has_rule("TlsBadConfig.java", "TLS-KEYSTORE-PASSWORD-HARDCODED")),
        ("TLS-TRUSTSTORE-PASSWORD-HARDCODED detected",
         has_rule("TlsBadConfig.java", "TLS-TRUSTSTORE-PASSWORD-HARDCODED")),
        ("TLS client-auth property 'want' detected",
         has_rule("application.properties", "TLS-MTLS-WANT-INSTEAD-OF-NEED")),
        ("TLS keystore password property detected",
         has_rule("application.properties", "TLS-KEYSTORE-PASSWORD-HARDCODED")),
        ("TLS truststore password property detected",
         has_rule("application.properties", "TLS-TRUSTSTORE-PASSWORD-HARDCODED")),
        ("Modern TLS configuration has no new TLS antipattern findings",
         not any(os.path.basename(f.file) == "TlsGoodConfig.java" and f.rule_id in {
             "TLS-OLD-PROTOCOL", "TLS-WEAK-CIPHER", "TLS-TRUST-SELF-SIGNED",
             "TLS-REVOCATION-DISABLED", "TLS-MTLS-WANT-INSTEAD-OF-NEED",
             "TLS-KEYSTORE-PASSWORD-HARDCODED", "TLS-TRUSTSTORE-PASSWORD-HARDCODED"}
                 for f in findings)),
        ("AUTHZ-SECURITYFILTERCHAIN-ORDER detects broad earlier chain",
         has_rule("FilterChainsBad.java", "AUTHZ-SECURITYFILTERCHAIN-ORDER")),
        ("AUTHZ-FILTERCHAIN-NO-FALLBACK detects scoped-only chains",
         has_rule("FilterChainsNoFallback.java", "AUTHZ-FILTERCHAIN-NO-FALLBACK")),
        ("SecurityFilterChain rules accept specific-first plus fallback",
         not any(os.path.basename(f.file) == "FilterChainsGood.java" and f.rule_id in {
             "AUTHZ-SECURITYFILTERCHAIN-ORDER", "AUTHZ-FILTERCHAIN-NO-FALLBACK"}
                 for f in findings)),
        ("AUTHZ-TENANT-DATAFLOW crosses controller-service boundary",
         has_rule("TenantService.java", "AUTHZ-TENANT-DATAFLOW")),
        ("AUTHZ-IDOR-DATAFLOW crosses controller-service boundary",
         has_rule("TenantService.java", "AUTHZ-IDOR-DATAFLOW")),
        ("AUTHZ-TENANT-DATAFLOW accepts authenticated tenant binding",
         not has_rule("TenantFlowGood.java", "AUTHZ-TENANT-DATAFLOW")),
        ("Coverage matrix inventories insecure and secured endpoints",
         coverage_entry("POST /coverage-open/orders/{tenantId}/{id}") is not None
         and coverage_entry("POST /coverage-secure/orders/{tenantId}/{id}") is not None),
        ("Coverage matrix combines class-level and method-level routes",
         coverage_entry("GET /coverage-secure/catalog/items") is not None),
        ("Coverage matrix inventories message consumers and scheduled jobs",
         coverage_entry("KafkaListener orders") is not None
         and any(entry.kind == "Scheduled" and entry.method == "cleanup" for entry in coverage)),
        ("Coverage matrix marks missing controls on insecure path",
         all(coverage_status("POST /coverage-open/orders/{tenantId}/{id}", key) == "MISSING"
             for key in ("authentication", "authorization", "tenant", "validation", "audit"))),
        ("Coverage matrix accepts controls on secured path",
         all(coverage_status("POST /coverage-secure/orders/{tenantId}/{id}", key) == "COVERED"
             for key in ("authentication", "authorization", "tenant", "validation", "audit"))),
        ("Coverage findings retain one finding per missing control",
         has_rule("CoverageOrderService.java", "AUTHZ-SENSITIVE-SINK-UNCOVERED")
         and has_rule("CoverageOrderService.java", "TENANT-CONTEXT-LOST")
         and has_rule("CoverageOrderService.java", "VALIDATION-COVERAGE-GAP")
         and has_rule("CoverageOrderService.java", "AUDIT-COVERAGE-GAP")),
        ("Coverage detects mixed authorization callers for shared service",
         has_rule("CoverageOrderService.java", "AUTHZ-PARTIALLY-PROTECTED-SERVICE")),
        ("Coverage detects missing login throttling",
         has_rule("CoverageBadController.java", "RATE-LIMIT-COVERAGE-GAP")),
        ("OAUTH2-ISSUER-MIXUP detected with multiple configured issuers",
         has_rule("OauthMixupBad.java", "OAUTH2-ISSUER-MIXUP")),
        ("JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED detected",
         has_rule("AdvancedJwtBad.java", "JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED")),
        ("JWE-ZIP-ENABLED detected",
         has_rule("AdvancedJwtBad.java", "JWE-ZIP-ENABLED")),
        ("JWT-KEY-ISSUER-NOT-BOUND detected",
         has_rule("AdvancedJwtBad.java", "JWT-KEY-ISSUER-NOT-BOUND")),
        ("JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES detected",
         has_rule("AdvancedJwtBad.java", "JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES")),
        ("Advanced JWT rules accept verified inner JWS and separated keys",
         not any(os.path.basename(f.file) == "AdvancedJwtGood.java" and f.rule_id in {
             "JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED", "JWE-ZIP-ENABLED",
             "JWT-KEY-ISSUER-NOT-BOUND", "JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES"}
                 for f in findings)),
        ("CERT-PRIVATE-KEY-COMMITTED scans .key files",
         has_rule("test-private.key", "CERT-PRIVATE-KEY-COMMITTED")),
        ("CERT-EMPTY-PKCS12-PASSWORD detected",
         has_rule("Pkcs12Bad.java", "CERT-EMPTY-PKCS12-PASSWORD")),
        ("PASSWORD-RESET-NO-EXPIRY detected",
         has_rule("PasswordResetBad.java", "PASSWORD-RESET-NO-EXPIRY")),
        ("PASSWORD-RESET-TOKEN-REUSE detected",
         has_rule("PasswordResetBad.java", "PASSWORD-RESET-TOKEN-REUSE")),
        ("PASSWORD-RESET-PREDICTABLE-TOKEN detected",
         has_rule("PasswordResetBad.java", "PASSWORD-RESET-PREDICTABLE-TOKEN")),
        ("Password reset rules accept random expiring one-time tokens",
         not any(os.path.basename(f.file) == "PasswordResetGood.java" and f.rule_id.startswith("PASSWORD-RESET-")
                 for f in findings)),
        ("AUTH-LOGIN-NO-RATE-LIMIT detected",
         has_rule("AuthResilienceBad.java", "AUTH-LOGIN-NO-RATE-LIMIT")),
        ("MFA-FAIL-OPEN detected",
         has_rule("AuthResilienceBad.java", "MFA-FAIL-OPEN")),
        ("Auth resilience rules accept throttling and MFA fail-closed",
         not any(os.path.basename(f.file) == "AuthResilienceGood.java" and f.rule_id in {
             "AUTH-LOGIN-NO-RATE-LIMIT", "MFA-FAIL-OPEN"} for f in findings)),
        ("DPOP-JTI-NOT-REPLAY-CHECKED detected",
         has_rule("DpopBad.java", "DPOP-JTI-NOT-REPLAY-CHECKED")),
        ("DPOP-HTM-HTU-NOT-VALIDATED detected",
         has_rule("DpopBad.java", "DPOP-HTM-HTU-NOT-VALIDATED")),
        ("DPOP-IAT-WINDOW-TOO-LARGE detected",
         has_rule("DpopBad.java", "DPOP-IAT-WINDOW-TOO-LARGE")),
        ("DPOP-ATH-NOT-VALIDATED detected",
         has_rule("DpopBad.java", "DPOP-ATH-NOT-VALIDATED")),
        ("DPOP-NONCE-NOT-VALIDATED detected",
         has_rule("DpopBad.java", "DPOP-NONCE-NOT-VALIDATED")),
        ("DPoP rules accept complete proof validation",
         not any(os.path.basename(f.file) == "DpopGood.java" and f.rule_id.startswith("DPOP-")
                 for f in findings)),
        ("HARDEN-JWT-AUDIENCE-VALIDATION fires on Oauth2GoodConfig",
         has_rule("Oauth2GoodConfig.java", "HARDEN-JWT-AUDIENCE-VALIDATION")),
        ("HARDEN-JWT-CLOCK-SKEW fires on Oauth2GoodConfig",
         has_rule("Oauth2GoodConfig.java", "HARDEN-JWT-CLOCK-SKEW")),
        ("HARDEN-OAUTH2-PKCE-ENABLED fires on Oauth2GoodConfig",
         has_rule("Oauth2GoodConfig.java", "HARDEN-OAUTH2-PKCE-ENABLED")),
        ("HARDEN-OAUTH2-STATE-PARAM fires on Oauth2GoodConfig",
         has_rule("Oauth2GoodConfig.java", "HARDEN-OAUTH2-STATE-PARAM")),
        # Crypto + Spring-Misc rules (3.11)
        ("SRC-CRYPTO-RSA-NO-OAEP detected on CryptoVulnConfig",
         has_rule("CryptoVulnConfig.java", "SRC-CRYPTO-RSA-NO-OAEP")),
        ("SRC-CRYPTO-STATIC-IV detected on CryptoVulnConfig",
         has_rule("CryptoVulnConfig.java", "SRC-CRYPTO-STATIC-IV")),
        ("SRC-RANDOM-PREDICTABLE-SEED detected on CryptoVulnConfig",
         has_rule("CryptoVulnConfig.java", "SRC-RANDOM-PREDICTABLE-SEED")),
        ("HARDEN-RSA-OAEP fires on CryptoGoodConfig",
         has_rule("CryptoGoodConfig.java", "HARDEN-RSA-OAEP")),
        ("HARDEN-CRYPTO-GCM-RANDOM-IV fires on CryptoGoodConfig",
         has_rule("CryptoGoodConfig.java", "HARDEN-CRYPTO-GCM-RANDOM-IV")),
        ("SpringSecurityCheck-REGEX-NO-DOTALL detected on SpringSecBadMisc",
         has_rule("SpringSecBadMisc.java", "SpringSecurityCheck-REGEX-NO-DOTALL")),
        ("SRC-SSTI-VIEW-NAME detected on SpringSecBadMisc",
         has_rule("SpringSecBadMisc.java", "SRC-SSTI-VIEW-NAME")),
    ]

    ok = True
    for label, passed in checks:
        print(f"[{'OK  ' if passed else 'FAIL'}] {label}")
        ok = ok and passed
    print("\nSelf-test " + ("passed." if ok else "FAILED."))
    print(f"Test files: {tmp}")
    return 0 if ok else 2


def print_fixes(keys: Sequence[str]) -> int:
    wanted = [k.upper() for k in keys] if keys else []
    printed = 0
    for rule in RULES:
        short = rule.rid.split("-", 1)[1]
        if wanted and not any(w in rule.rid.upper() or w == short for w in wanted):
            continue
        if not rule.fix:
            continue
        print(f"### {rule.rid} - {rule.name}")
        print(rule.fix)
        print()
        printed += 1
    if not printed:
        print("No matching rule. Available: " + ", ".join(r.rid for r in RULES))
        return 2
    return 0


POC_TEXT = """\
Dynamic counter-test (only against your own systems, or with written authorization):

1) Are entities expanded at all?
   <?xml version="1.0"?>
   <!DOCTYPE t [ <!ENTITY e "XXE-TEST-OK"> ]>
   <t>&e;</t>

2) Local file (choose a harmless target file):
   <?xml version="1.0"?>
   <!DOCTYPE t [ <!ENTITY e SYSTEM "file:///etc/hostname"> ]>
   <t>&e;</t>

3) Out-of-band / SSRF against a listener you control:
   <?xml version="1.0"?>
   <!DOCTYPE t [ <!ENTITY e SYSTEM "http://127.0.0.1:8000/ping"> ]>
   <t>&e;</t>

4) Parameter-entity variant (works when only general entities are blocked):
   <?xml version="1.0"?>
   <!DOCTYPE t [ <!ENTITY % p SYSTEM "http://127.0.0.1:8000/x.dtd"> %p; ]>
   <t/>

5) XInclude (works without a DOCTYPE if setXIncludeAware(true) is set):
   <t xmlns:xi="http://www.w3.org/2001/XInclude">
     <xi:include parse="text" href="file:///etc/hostname"/>
   </t>

Expected with a correctly hardened parser: an error such as
"DOCTYPE is disallowed when the feature
http://apache.org/xml/features/disallow-doctype-decl set to true".

Blind cases: the response is empty, but the listener from (3)/(4) gets a hit.
Also check error messages and logs - the entity content often ends up there too.
"""


# --------------------------------------------------------------------------
# Scan orchestration
# --------------------------------------------------------------------------

def scan(root: str, exts: Tuple[str, ...], exclude: Set[str], skip_tests: bool,
         show_hardened: bool, jobs: int, with_deps: bool,
         paths: Optional[List[str]] = None, context_radius: int = 3,
         build_inventory: Optional[List[str]] = None,
         module_evidence: Optional[Dict[str, str]] = None,
         active_rules: Optional[Sequence[Rule]] = None,
         coverage_out: Optional[List[CoverageEntry]] = None) -> Tuple[List[Finding], int, int]:
    targets = paths or [root]
    inventory, build_files = walk(targets, tuple(set(exts) | set(PROP_EXTS) |
        set(CERT_TEXT_EXTS) | {".html", ".htm", ".properties"}), exclude, skip_tests, True)
    inventory = sorted(set(inventory))
    build_files = sorted(set(build_files))
    if build_inventory is not None:
        build_inventory.extend(build_files)
    src_files = [p for p in inventory if p.endswith(exts) and not p.endswith((".html", ".htm"))]
    template_files = [p for p in inventory if p.endswith((".html", ".htm"))]
    certificate_text_files = [p for p in inventory if p.endswith(CERT_TEXT_EXTS)]
    props_files = [p for p in inventory if p.endswith(PROP_EXTS) and
        (p in targets or any(k in os.path.basename(p) for k in
         ("application", "security", "bootstrap", "management", "actuator")))]
    loaded: Dict[str, Tuple[List[str], List[Method]]] = {}
    raw_map: Dict[str, List[str]] = {}
    def _load(p: str):
        return p, load_file(p)
    if jobs > 1 and len(src_files) > 4:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(_load, src_files))
    else:
        results = [_load(p) for p in src_files]
    for p, data in results:
        if data:
            _, raw_lines, lines, methods = data
            loaded[p] = (lines, methods)
            raw_map[p] = raw_lines
    results.clear()
    helper_index = build_helper_index(loaded)
    findings: List[Finding] = []
    active_ids = ({rule.rid for rule in active_rules}
                  if active_rules is not None else {rule.rid for rule in RULES})
    for p, (lines, methods) in loaded.items():
        findings.extend(analyze_file(p, raw_map[p], lines, methods, helper_index, root,
                                     show_hardened, active_rules, context_radius))
        if p.endswith((".java", ".kt")):
            rel = os.path.relpath(p, root) if root else p
            text = "\n".join(lines)
            extra = []
            method_bounds = list(_web_methods(text))
            for analyzer in (analyze_spel_from_request, analyze_ldap_injection,
                             analyze_log_injection, analyze_sqli_var_concat,
                             analyze_web_source, analyze_structured_dataflow):
                if analyzer in (analyze_web_source, analyze_structured_dataflow):
                    extra.extend(analyzer(rel, text, context_radius=context_radius,
                                          method_bounds=method_bounds))
                else:
                    extra.extend(analyzer(rel, text, context_radius=context_radius))
            findings.extend(f for f in extra if not finding_suppressed(raw_map[p], f))
            jose_rule_ids = active_ids & {"JWT-JKU-INJECTION", "JWT-X5U-INJECTION"}
            if jose_rule_ids:
                jose_hits = analyze_jose_header_url_injection(
                    rel, text, context_radius=context_radius,
                    method_bounds=method_bounds, enabled=jose_rule_ids)
                findings.extend(f for f in jose_hits if not finding_suppressed(raw_map[p], f))
            embedded_rule_ids = active_ids & {"JWT-EMBEDDED-JWK-TRUST", "JWT-X5C-TRUST"}
            if embedded_rule_ids:
                embedded_hits = analyze_embedded_jose_key_trust(
                    rel, text, context_radius=context_radius,
                    method_bounds=method_bounds, enabled=embedded_rule_ids)
                findings.extend(f for f in embedded_hits if not finding_suppressed(raw_map[p], f))
            if "AUTHZ-IDOR-DATAFLOW" in active_ids:
                idor_hits = analyze_authz_idor_dataflow(
                    rel, text, context_radius=context_radius, method_bounds=method_bounds)
                findings.extend(f for f in idor_hits if not finding_suppressed(raw_map[p], f))
            if "AUTHZ-MATCHER-ORDER" in active_ids:
                matcher_hits = analyze_authz_matcher_order(rel, text, context_radius=context_radius)
                findings.extend(f for f in matcher_hits if not finding_suppressed(raw_map[p], f))
            chain_rule_ids = active_ids & {"AUTHZ-SECURITYFILTERCHAIN-ORDER", "AUTHZ-FILTERCHAIN-NO-FALLBACK"}
            if chain_rule_ids:
                chain_hits = analyze_security_filter_chains(
                    rel, text, context_radius=context_radius,
                    method_bounds=method_bounds, enabled=chain_rule_ids)
                findings.extend(f for f in chain_hits if not finding_suppressed(raw_map[p], f))
            if "OIDC-IDTOKEN-AS-ACCESS-TOKEN" in active_ids:
                id_token_hits = analyze_idtoken_as_access_token(
                    rel, text, context_radius=context_radius, method_bounds=method_bounds)
                findings.extend(f for f in id_token_hits if not finding_suppressed(raw_map[p], f))
            semantic_rule_ids = active_ids & {"OIDC-AZP-NOT-VALIDATED", "JWT-TOKEN-TYPE-CONFUSION"}
            if semantic_rule_ids:
                semantic_hits = analyze_token_semantics(
                    rel, text, context_radius=context_radius,
                    method_bounds=method_bounds, enabled=semantic_rule_ids)
                findings.extend(f for f in semantic_hits if not finding_suppressed(raw_map[p], f))
            if "REFRESH-TOKEN-NO-ROTATION" in active_ids:
                refresh_hits = analyze_refresh_rotation(
                    rel, text, context_radius=context_radius, method_bounds=method_bounds)
                findings.extend(f for f in refresh_hits if not finding_suppressed(raw_map[p], f))
            jwt_advanced_ids = active_ids & {
                "JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED", "JWT-KEY-ISSUER-NOT-BOUND",
                "JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES"}
            if jwt_advanced_ids:
                advanced_hits = analyze_jwt_advanced_semantics(
                    rel, text, context_radius=context_radius,
                    method_bounds=method_bounds, enabled=jwt_advanced_ids)
                findings.extend(f for f in advanced_hits if not finding_suppressed(raw_map[p], f))
            dpop_ids = active_ids & {"DPOP-JTI-NOT-REPLAY-CHECKED", "DPOP-HTM-HTU-NOT-VALIDATED",
                                     "DPOP-IAT-WINDOW-TOO-LARGE", "DPOP-ATH-NOT-VALIDATED",
                                     "DPOP-NONCE-NOT-VALIDATED"}
            if dpop_ids:
                dpop_hits = analyze_dpop_validation(
                    rel, text, context_radius=context_radius,
                    method_bounds=method_bounds, enabled=dpop_ids)
                findings.extend(f for f in dpop_hits if not finding_suppressed(raw_map[p], f))
            if "CERT-EMPTY-PKCS12-PASSWORD" in active_ids:
                pkcs12_hits = analyze_pkcs12_empty_password(
                    rel, text, context_radius=context_radius, method_bounds=method_bounds)
                findings.extend(f for f in pkcs12_hits if not finding_suppressed(raw_map[p], f))
            reset_ids = active_ids & {"PASSWORD-RESET-NO-EXPIRY", "PASSWORD-RESET-TOKEN-REUSE",
                                      "PASSWORD-RESET-PREDICTABLE-TOKEN"}
            if reset_ids:
                reset_hits = analyze_password_reset(
                    rel, text, context_radius=context_radius,
                    method_bounds=method_bounds, enabled=reset_ids)
                findings.extend(f for f in reset_hits if not finding_suppressed(raw_map[p], f))
            resilience_ids = active_ids & {"AUTH-LOGIN-NO-RATE-LIMIT", "MFA-FAIL-OPEN"}
            if resilience_ids:
                resilience_hits = analyze_auth_resilience(
                    rel, text, context_radius=context_radius,
                    method_bounds=method_bounds, enabled=resilience_ids)
                findings.extend(f for f in resilience_hits if not finding_suppressed(raw_map[p], f))
            kid_hits = _check_kid_injection(rel, lines, raw_map[p], methods, context_radius)
            findings.extend(f for f in kid_hits if not finding_suppressed(raw_map[p], f))
    if "SpringSecurityCheck-CSRF-DISABLED-JWT-COOKIE" in active_ids:
        findings.extend(analyze_csrf_disabled_jwt_cookie(
            loaded, raw_map, root, build_files, context_radius=context_radius))
    if "AUTHZ-PREAUTHORIZE-WITHOUT-METHODSECURITY" in active_ids:
        findings.extend(analyze_preauthorize_without_method_security(
            loaded, raw_map, root, build_files, context_radius=context_radius))
    if "REFRESH-TOKEN-NO-REVOKE-ON-LOGOUT" in active_ids:
        findings.extend(analyze_refresh_logout_revocation(
            loaded, raw_map, root, build_files, context_radius=context_radius))
    project_dataflow_ids = active_ids & {
        "AUTHZ-TENANT-DATAFLOW", "AUTHZ-IDOR-DATAFLOW"}
    if project_dataflow_ids:
        findings.extend(analyze_interprocedural_tenant_dataflow(
            loaded, raw_map, root, context_radius=context_radius,
            enabled=project_dataflow_ids))
    if "OAUTH2-ISSUER-MIXUP" in active_ids:
        findings.extend(analyze_oauth_issuer_mixup(
            loaded, raw_map, root, props_files, context_radius=context_radius))
    if coverage_out is not None:
        coverage_entries, coverage_findings = analyze_security_coverage(
            loaded, raw_map, root, context_radius=context_radius, enabled=active_ids,
            build_files=build_files, props_files=props_files)
        coverage_out.extend(coverage_entries)
        findings.extend(coverage_findings)
    for p in template_files:
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                raw_map[p] = fh.read().splitlines()
        except OSError:
            continue
        rel = os.path.relpath(p, root) if root else p
        findings.extend(f for f in analyze_template(rel, "\n".join(raw_map[p]), context_radius=context_radius)
                        if not finding_suppressed(raw_map[p], f))
    if "CERT-PRIVATE-KEY-COMMITTED" in active_ids:
        for p in certificate_text_files:
            findings.extend(analyze_certificate_text_file(p, root, context_radius=context_radius))
    if with_deps:
        # The nearest inventoried POM owns a source file; sibling modules cannot
        # accidentally satisfy a combination's source/security prerequisite.
        pom_dirs = {os.path.abspath(os.path.dirname(b)) for b in build_files if os.path.basename(b) == "pom.xml"}
        module_sources: Dict[str, List[str]] = {}
        for p, (lines, _) in loaded.items():
            if TEST_PATH.search(p):
                continue
            parent = os.path.abspath(os.path.dirname(p))
            while parent not in pom_dirs and os.path.dirname(parent) != parent:
                parent = os.path.dirname(parent)
            if parent in pom_dirs:
                module_sources.setdefault(parent, []).append("\n".join(lines))
        for b in build_files:
            findings.extend(analyze_build_file(b, root))
            findings.extend(analyze_build_hygiene(b, root))
            module = os.path.abspath(os.path.dirname(b))
            evidence = "\n".join(module_sources.get(module, []))
            if module_evidence is not None:
                module_evidence[os.path.abspath(b)] = evidence
            findings.extend(analyze_boot_combinations(b, root, evidence))
        for p in inventory:
            if os.path.basename(p) == "gradle-wrapper.properties":
                findings.extend(analyze_build_hygiene(p, root))
    for pf in props_files:
        findings.extend(analyze_props_file(pf, root))
    findings = dedupe_findings(findings)
    enrich_context(findings, root, context_radius, raw_map)
    return findings, len(src_files) + len(template_files) + len(certificate_text_files), len(build_files) if with_deps else 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Output path helper
# --------------------------------------------------------------------------

EXT_BY_FORMAT = {"html": ".html", "markdown": ".md", "json": ".json", "sarif": ".sarif"}


def auto_report_path(fmt: str, root: str) -> str:
    """Builds an auto-generated report filename in the current directory, e.g.
    jspringguard-myproject-20260905-142301.html. Used whenever --format is
    not 'text' and --out was not given, so html/json/sarif/markdown reports
    always land in a file instead of being dumped to the terminal."""
    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = EXT_BY_FORMAT.get(fmt, ".txt")
    base = os.path.basename(os.path.abspath(root)) if root else "report"
    base = re.sub(r"[^\w.-]", "_", base) or "report"
    return f"jspringguard-{base}-{ts}{ext}"


def auto_osv_cache_path(root: str) -> str:
    """Builds an auto-generated OSV cache filename in the current directory,
    e.g. osv-cache-myproject-20260905-142301.json. Used whenever --check-osv
    runs a live check and --osv-cache-write was not given, so the results are
    always saved for later offline/air-gapped reuse instead of being lost."""
    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.basename(os.path.abspath(root)) if root else "osv"
    base = re.sub(r"[^\w.-]", "_", base) or "osv"
    return f"osv-cache-{base}-{ts}.json"


def _recover_windows_quoted_path(p: str) -> str:
    """Recovers from the classic Windows cmd.exe/PowerShell quoting bug.

    A single trailing backslash right before a closing double-quote (e.g.
    "C:\\ordner\\") is not treated as ending the path: the CRT argv parser
    Windows uses treats an odd run of backslashes before a '"' as an escaped,
    literal quote character rather than a delimiter - so quoted-mode never
    closes and a stray '"' ends up embedded in the argument (and, with more
    arguments after it, the rest of the command line gets swallowed into the
    same argument too). The visible symptom is a path that silently doesn't
    exist - no crash, no findings, no error - while the same path without
    the trailing backslash works fine.

    If the path as given doesn't exist but stripping one trailing '"' does,
    this recovers the intended path automatically. Anything else is returned
    unchanged; the caller reports it as missing.
    """
    if p and p.endswith('"') and not os.path.exists(p):
        stripped = p[:-1]
        if os.path.exists(stripped):
            return stripped
    return p


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="JSpringGuard: XXE + Spring Security for JVM source code (v%s), "
                    "by %s - %s. "
                    "Standalone - this one file is all you need, no Semgrep/CodeQL/other "
                    "tools required." % (VERSION, AUTHOR, REPO_URL),
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("paths", nargs="*", help="Files or directories")
    ap.add_argument("--ext", default=",".join(DEFAULT_EXTS), help="Extensions, comma-separated")
    ap.add_argument("--exclude", default="", help="Additional directories, comma-separated")
    ap.add_argument("--skip-tests", action="store_true", help="Skip test directories")
    ap.add_argument("--show-hardened", action="store_true", default=True,
                    help="List hardened/good-practice locations too (default: on; kept for "
                         "compatibility with scripts that already pass it)")
    ap.add_argument("--hide-hardened", action="store_true",
                    help="Suppress hardened/good-practice findings (undo the --show-hardened default)")
    ap.add_argument("--no-deps", action="store_true", help="Skip the dependency check")
    ap.add_argument("--resolve-deps", action="store_true",
                    help="Opt in to Maven/Gradle runtime dependency resolution; executes the project wrapper/build")
    ap.add_argument("--resolver-timeout", type=int, default=180, metavar="SECONDS",
                    help="Timeout per Maven/Gradle module for --resolve-deps (default 180)")
    ap.add_argument("--osv-db", metavar="FILE", help="Scan against a complete local Maven SQLite snapshot; no network access")
    ap.add_argument("--osv-db-update", metavar="FILE", help="Download the complete official Maven OSV export and atomically create/update FILE; then exit")
    ap.add_argument("--osv-db-build", metavar="ZIP", help="Import a local Maven OSV ZIP into --osv-db FILE; then exit without network access")
    ap.add_argument("--osv-db-info", metavar="FILE", help="Print local OSV database metadata and exit")
    ap.add_argument("--check-osv", action="store_true",
                    help="Check dependencies against osv.dev, live. Always writes a local "
                         "cache file afterwards (see --osv-cache-write) for later offline reuse.")
    ap.add_argument("--osv-cache-write", metavar="FILE",
                    help="With --check-osv: save the live results to FILE instead of an "
                         "auto-generated name, to copy to an air-gapped machine later")
    ap.add_argument("--check-osv-read", "--osv-cache-read", dest="osv_cache_read", metavar="FILE",
                    help="Read a previously saved OSV cache FILE and report from it directly - "
                         "no network call at all, no need to also pass --check-osv (for "
                         "air-gapped machines)")
    ap.add_argument("--codeql-sarif", action="append", metavar="FILE",
                    help="Import CodeQL CLI/Action SARIF findings into this report; repeatable")
    ap.add_argument("--min-severity", default="LOW", choices=SEVERITY_LIST)
    ap.add_argument("--fail-on", default="MEDIUM", choices=SEVERITY_LIST + ["NONE"])
    ap.add_argument("--format", default="text", choices=["text", "json", "sarif", "markdown", "html"])
    ap.add_argument("--coverage", action="store_true",
                    help="Add a project-wide security-control coverage matrix and coverage findings")
    ap.add_argument("--coverage-format", default="table", choices=["table", "json"],
                    help="Coverage rendering for text reports (default: table; other report formats use their native representation)")
    ap.add_argument("--fail-on-coverage-gap", action="store_true",
                    help="Exit with status 1 when the coverage matrix contains a required MISSING control")
    ap.add_argument("--out", help="Output file. If omitted and --format is not "
                    "'text', a filename is generated automatically (e.g. "
                    "security-check-<project>-<timestamp>.html).")
    ap.add_argument("--baseline", help="JSON baseline: fingerprints it contains are hidden")
    ap.add_argument("--write-baseline", metavar="PATH", help="Save current findings as a baseline")
    ap.add_argument("--show-fix", action="store_true", help="Also print a fix snippet per finding")
    ap.add_argument("--context", type=int, default=999_999, metavar="N",
                    help="Source lines before and after findings (default: entire file; 0: matched line only; N: ±N lines)")
    ap.add_argument("--jobs", type=int, default=4, help="Parallel readers (default 4)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--list-rules", action="store_true", help="List all rule IDs, base severities and descriptions; no scan required")
    ap.add_argument("--include-rule", "--enable-rule", action="append", default=[], metavar="GLOB",
                    help="Only report matching rule IDs; repeat or comma-separate (e.g. 'SRC-XSS-*,OSV-*')")
    ap.add_argument("--exclude-rule", "--disable-rule", action="append", default=[], metavar="GLOB",
                    help="Suppress matching rule IDs; repeat or comma-separate; exclusion wins")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--fix", nargs="*", metavar="RULE",
                    help="Print hardened code templates (e.g. --fix DOM STAX)")
    ap.add_argument("--poc", action="store_true", help="Test payloads for the counter-test")
    ap.add_argument("--version", action="version",
                    version=f"JSpringGuard {VERSION} by {AUTHOR} - {REPO_URL}")
    args = ap.parse_args(argv)
    db_commands = sum(bool(x) for x in (args.osv_db_update, args.osv_db_build, args.osv_db_info))
    if db_commands > 1:
        ap.error("Use only one database management command at a time")
    if args.osv_db_build and not args.osv_db:
        ap.error("--osv-db-build ZIP requires --osv-db FILE")
    if (args.osv_db or db_commands) and (args.osv_cache_read or args.osv_cache_write):
        ap.error("A complete OSV database and a per-query cache are different modes; do not combine them")
    if args.osv_db and not args.osv_db_build and (args.no_deps or args.resolve_deps):
        ap.error("--osv-db cannot combine with --no-deps or --resolve-deps; offline scans must not execute network-capable build tools")
    if db_commands:
        try:
            if args.osv_db_info:
                db = OfflineOsvDatabase(args.osv_db_info)
                try:
                    metadata = db.metadata
                finally:
                    db.close()
            elif args.osv_db_build:
                metadata = build_osv_database(args.osv_db_build, args.osv_db)
            else:
                print("[osv-db] Downloading the Java OSV database for Maven and Gradle projects...", file=sys.stderr)
                metadata = update_osv_database(args.osv_db_update)
            print(json.dumps(metadata, indent=2))
            return 0
        except offline_database_error_types() as exc:
            print(f"[osv-db] {exc}", file=sys.stderr)
            return 2
    if args.osv_db:
        args.check_osv = True
    if args.context < 0:
        ap.error("--context must be non-negative")
    if args.resolver_timeout < 1:
        ap.error("--resolver-timeout must be positive")
    if args.resolve_deps and args.no_deps:
        ap.error("--resolve-deps cannot be combined with --no-deps")
    if args.hide_hardened:
        args.show_hardened = False

    print(f"JSpringGuard v{VERSION} by {AUTHOR} - {REPO_URL}", file=sys.stderr)
    include_rules = parse_rule_patterns(args.include_rule)
    exclude_rules = parse_rule_patterns(args.exclude_rule)
    active_rules = [r for r in RULES if rule_selected(r.rid, include_rules, exclude_rules)]

    if (args.osv_cache_read or args.osv_cache_write) and not args.check_osv:
        print("[osv] --osv-cache-read/--osv-cache-write given without --check-osv - "
             "enabling --check-osv automatically (it would otherwise be silently ignored).",
             file=sys.stderr)
        args.check_osv = True

    if args.list_rules:
        for rid, (severity, description) in sorted(rule_catalog().items()):
            if rule_selected(rid, include_rules, exclude_rules):
                print(f"{rid}\t{severity}\t{description}")
        return 0

    if args.poc:
        print(POC_TEXT)
        return 0
    if args.fix is not None:
        return print_fixes(args.fix)
    if args.selftest:
        return run_selftest()
    if not args.paths:
        ap.error("Please provide at least one path (or --selftest / --fix / --poc).")

    args.paths = [_recover_windows_quoted_path(p) for p in args.paths]
    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        for p in missing:
            hint = ""
            if p.endswith('"') or p.endswith("\\"):
                hint = (" (on Windows, a quoted path that ends in a single backslash, e.g. "
                        '"C:\\ordner\\", is misparsed by cmd.exe/PowerShell: that backslash '
                        "escapes the closing quote instead of ending the path, so the rest of "
                        "the command line gets absorbed into it. Drop the trailing backslash "
                        "(C:\\ordner), double it (C:\\ordner\\\\), or pass the path unquoted.)")
            print(f"[error] path not found: {p}{hint}", file=sys.stderr)
        return 2

    exts = tuple(e if e.startswith(".") else "." + e
                 for e in (x.strip() for x in args.ext.split(",")) if e)
    exclude = set(DEFAULT_EXCLUDE_DIRS) | {x.strip() for x in args.exclude.split(",") if x.strip()}
    root = args.paths[0] if len(args.paths) == 1 and os.path.isdir(args.paths[0]) else ""

    osv_build_files: List[str] = []
    osv_incomplete = False
    resolver_incomplete = False
    resolved_dependencies: List[ResolvedDependency] = []
    module_evidence: Dict[str, str] = {}
    if args.format == "html":
        args.coverage = True
    coverage_entries: Optional[List[CoverageEntry]] = (
        [] if args.coverage or args.fail_on_coverage_gap else None)
    findings, n_src, n_build = scan(root, exts, exclude, args.skip_tests, args.show_hardened,
                                    max(1, args.jobs), not args.no_deps, paths=args.paths,
                                    context_radius=args.context, build_inventory=osv_build_files,
                                    module_evidence=module_evidence,
                                    active_rules=active_rules,
                                    coverage_out=coverage_entries)

    if args.codeql_sarif:
        try:
            codeql_findings = load_codeql_sarif(args.codeql_sarif, root)
            enrich_context(codeql_findings, root, args.context)
            findings.extend(codeql_findings)
            print(f"[codeql] Imported {len(codeql_findings)} SARIF finding(s).", file=sys.stderr)
        except ValueError as exc:
            print(f"[codeql] {exc}", file=sys.stderr)
            return 2

    if args.resolve_deps:
        print("[resolver] Executing project Maven/Gradle dependency resolution (explicitly enabled).",
              file=sys.stderr)
        resolved_dependencies, resolver_errors = resolve_project_dependencies(
            osv_build_files, root, args.resolver_timeout)
        if not osv_build_files:
            resolver_errors.append("no Maven or Gradle build files found")
        resolver_incomplete = bool(resolver_errors)
        successful_files = {os.path.abspath(d.build_file) for d in resolved_dependencies}
        successful_rel = {os.path.relpath(path, root) if root else path
                          for path in successful_files}
        # Effective versions supersede declaration-only DEP findings for modules
        # whose resolver completed. Combination and build-hygiene rules remain.
        findings = [f for f in findings
                    if not ((f.rule_id.startswith("DEP-") or
                             f.rule_id in RESOLVED_COMBINATION_RULES)
                            and f.file in successful_rel)]
        resolved_findings = analyze_resolved_dependencies(resolved_dependencies, root)
        resolved_findings.extend(analyze_resolved_combinations(
            resolved_dependencies, root, module_evidence))
        enrich_context(resolved_findings, root, args.context)
        findings.extend(resolved_findings)
        print(f"[resolver] Resolved {len(resolved_dependencies)} unique runtime coordinates "
              f"across {len(successful_files)} module(s).", file=sys.stderr)
        for error in resolver_errors:
            print(f"[resolver] WARNING: {error}", file=sys.stderr)

    if args.check_osv:
        cache_read: Optional[Dict[str, dict]] = None
        cache_write: Optional[Dict[str, dict]] = None
        local_database = None
        if args.osv_db:
            try:
                local_database = OfflineOsvDatabase(args.osv_db)
                print("[osv-db] Local Java database for Maven and Gradle projects", file=sys.stderr)
                print(f"[osv-db] {int(local_database.metadata['advisories']):,} advisories | "
                      f"{int(local_database.metadata['packages']):,} packages | Offline mode", file=sys.stderr)
                print(f"[osv-db] Snapshot: {local_database.metadata.get('created_utc')}", file=sys.stderr)
            except offline_database_error_types() as exc:
                print(f"[osv-db] Cannot open database: {exc}", file=sys.stderr)
                return 2
        elif args.osv_cache_read:
            # Read-only mode: report from the local file, no network call, and
            # nothing is written back - there is nothing new to save.
            try:
                with open(args.osv_cache_read, "r", encoding="utf-8") as fh:
                    cache_read = json.load(fh)
                if not isinstance(cache_read, dict):
                    raise ValueError("cache root must be a JSON object")
                print(f"[osv] Using local cache only, no network call: {args.osv_cache_read} "
                     f"({len(cache_read)} package(s))", file=sys.stderr)
            except (OSError, ValueError) as exc:
                print(f"[osv] Cannot read cache file, aborting OSV check: {exc}", file=sys.stderr)
                cache_read = {}
        else:
            # Live mode: --check-osv ALWAYS writes a cache file afterwards, so
            # the run's results are never just lost - pass --osv-cache-write to
            # choose the path yourself, otherwise one is generated automatically.
            write_path = args.osv_cache_write or auto_osv_cache_path(
                root or (args.paths[0] if args.paths else "."))
            args.osv_cache_write = write_path
            cache_write = {}
            if os.path.isfile(write_path):
                try:
                    with open(write_path, "r", encoding="utf-8") as fh:
                        cache_write.update(json.load(fh))
                except (OSError, ValueError):
                    pass
        osv_diagnostics = {}
        try:
            osv_findings, osv_occurrences, osv_unique, osv_failed, osv_first_error = osv_check_build_files(
                osv_build_files, root, cache_read, cache_write, jobs=max(1, args.jobs),
                resolved=resolved_dependencies, diagnostics=osv_diagnostics, offline_db=local_database)
        except offline_database_error_types() as exc:
            print(f"[osv] Assessment failed: {exc}", file=sys.stderr)
            return 2
        finally:
            if local_database is not None:
                local_database.close()
        osv_incomplete = osv_diagnostics["incomplete"]
        enrich_context(osv_findings, root, args.context)
        findings.extend(osv_findings)
        print_osv_summary(len(osv_findings), osv_occurrences, osv_unique,
                          osv_failed, osv_first_error, osv_diagnostics,
                          offline=cache_read is not None, database=local_database is not None)
        if cache_write is not None:
            try:
                with open(args.osv_cache_write, "w", encoding="utf-8") as fh:
                    json.dump(cache_write, fh, indent=2)
                abs_cache = os.path.abspath(args.osv_cache_write)
                print(f"[osv] Cache written: {abs_cache} ({len(cache_write)} total cached package(s); "
                     f"{osv_diagnostics['successful']} refreshed in this run) "
                     f"- copy this file to the air-gapped machine and use --check-osv-read there.",
                     file=sys.stderr)
                if osv_incomplete:
                    print("[osv] The cache does not cover skipped dependencies or failed lookups.", file=sys.stderr)
            except OSError as exc:
                print(f"[osv] Cannot write cache file: {exc}", file=sys.stderr)
    if not n_src and not n_build and not findings:
        print("No matching files found.", file=sys.stderr)
        return 2

    if args.baseline:
        try:
            with open(args.baseline, "r", encoding="utf-8") as fh:
                known = set(json.load(fh).get("fingerprints", []))
            findings = [f for f in findings if f.fingerprint not in known]
        except OSError as exc:
            print(f"[!] Baseline unreadable: {exc}", file=sys.stderr)

    findings = [f for f in findings
                if rule_selected(f.rule_id, include_rules, exclude_rules)]
    threshold = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings
                if SEVERITY_ORDER[f.severity] >= threshold
                or (args.show_hardened and f.status == "HARDENED")]


    if args.write_baseline:
        payload = {"tool": "JSpringGuard", "version": VERSION,
                   "author": AUTHOR, "repository": REPO_URL,
                   "fingerprints": sorted({f.fingerprint for f in findings})}
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"Baseline written with {len(payload['fingerprints'])} entries: "
              f"{args.write_baseline}", file=sys.stderr)

    out_path = args.out
    if args.format != "text" and not out_path:
        out_path = auto_report_path(args.format, root or (args.paths[0] if args.paths else "."))

    if args.format == "text":
        if out_path:
            with open(out_path, "w", encoding="utf-8") as fh:
                old, sys.stdout = sys.stdout, fh
                try:
                    print_text(findings, n_src, n_build, False, args.show_fix,
                               coverage_entries if args.coverage else None,
                               args.coverage_format)
                finally:
                    sys.stdout = old
        else:
            print_text(findings, n_src, n_build,
                       not args.no_color and sys.stdout.isatty(), args.show_fix,
                       coverage_entries if args.coverage else None,
                       args.coverage_format)
    elif args.format in ("markdown", "html"):
        text = (to_markdown(findings, n_src, n_build,
                            coverage_entries if args.coverage else None)
                if args.format == "markdown"
                else to_html(findings, n_src, n_build,
                             coverage_entries if args.coverage else None))
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        payload = (to_sarif(findings) if args.format == "sarif"
                   else {"tool": "JSpringGuard", "version": VERSION,
                         "author": AUTHOR, "repository": REPO_URL,
                         "files_scanned": n_src, "build_files_scanned": n_build,
                         "findings": [asdict(f) for f in findings],
                         **({"coverage": coverage_payload(coverage_entries or [])}
                            if args.coverage else {})})
        text = json.dumps(payload, indent=2, ensure_ascii=False)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    if out_path:
        abs_path = os.path.abspath(out_path)
        print(f"Report written: {abs_path}", file=sys.stderr)
        print(f"Open it: file://{abs_path}", file=sys.stderr)

    if osv_incomplete or resolver_incomplete:
        return 2
    if (args.fail_on_coverage_gap and coverage_entries is not None and
            any(status == "MISSING" for entry in coverage_entries
                for status in entry.controls.values())):
        return 1
    if args.fail_on == "NONE":
        return 0
    limit = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= limit and f.status != "HARDENED"
                    for f in findings) else 0
# ==========================================================================
#  MERGE BLOCK  ->  jspringguard.py
# --------------------------------------------------------------------------
#  Folds the detection logic of the earlier standalone scanners
#  (springboot_security_scanner.py + spring_security_audit.py) into this one
#  tool. jspringguard.py already covered XXE, Spring Security, dependencies
#  and config properties; this block only adds the gaps that previously lived
#  ONLY in the older scanners:
#
#    1) non-XML injection heuristics (source):
#       native deserialization, Jackson default typing, SnakeYAML,
#       command exec, SpEL, JNDI, SQL string concatenation
#    2) weak crypto (source): MD5/SHA-1, java.util.Random
#    3) build supply-chain hygiene (build files): HTTP repositories,
#       allowInsecureProtocol, mavenLocal, jcenter, dynamic/SNAPSHOT
#       versions, Gradle wrapper over HTTP
#    4) extra config rules: ddl-auto=create(-drop), cookie flags
#    5) the CodeQL Spring detection techniques, ported to pure Python
#
#  HOW TO APPLY:  paste this whole block ONCE into jspringguard.py, AFTER all
#  definitions (Rule, RULES, PROP_RULES, RULE_BY_ID, Finding, fingerprint, bump,
#  walk, scan) and BEFORE the final `if __name__ == "__main__":` block.
#  No other changes to the existing code are required.
# ==========================================================================

# --- 1) + 2) source rules (injection / crypto heuristics) -----------------
# Deliberately heuristic (patterns, no taint tracking). "always_report" + kind
# "sink" => status REVIEW (inspect manually); kind "antipattern" => a clear
# misconfiguration. The taint bonus / test-code discount from analyze_file
# still applies automatically, because these are real Rule objects.
MERGE_SRC_RULES: List[Rule] = [
    Rule("SRC-DESER-NATIVE", "Java native deserialization (ObjectInputStream)",
         re.compile(r"\bObjectInputStream\s*\("),
         "HIGH", [], [], always_report=True, kind="sink",
         note="readObject() on untrusted data is a direct RCE path (gadget chains).",
         fix="Do not deserialize native serialization data from untrusted sources; "
             "switch to data-oriented formats (JSON with a fixed target type), "
             "and set an ObjectInputFilter/allowlist if needed."),
    Rule("SRC-DESER-JACKSON-DEFTYPING", "Jackson default typing enabled",
         re.compile(r"(?:enableDefaultTyping|activateDefaultTyping)\s*\("),
         "HIGH", [], [], kind="antipattern",
         note="Polymorphic deserialization enables RCE gadget chains.",
         fix="No default typing; use @JsonTypeInfo with a strict "
             "PolymorphicTypeValidator / allowlist instead."),
    Rule("SRC-DESER-SNAKEYAML", "SnakeYAML new Yaml(...) without SafeConstructor",
         re.compile(r"\bnew\s+(?:[\w.]*\.)?Yaml\s*\("),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="Without SafeConstructor arbitrary types can be instantiated (CVE-2022-1471). "
              "No finding if SafeConstructor/SnakeYAML>=2.0 is used in the same context.",
         fix="new Yaml(new SafeConstructor(new LoaderOptions())) or SnakeYAML >= 2.0."),
    Rule("SRC-CMD-EXEC", "Process execution (Runtime.exec / ProcessBuilder)",
         re.compile(r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bnew\s+ProcessBuilder\s*\("),
         "HIGH", [], [], always_report=True, kind="sink",
         note="Command injection as soon as arguments are externally influenced.",
         fix="Fixed commands + separate, strictly validated arguments; no shell concatenation."),
    Rule("SRC-SPEL-DYNAMIC", "Dynamic SpEL expression (parseExpression)",
         re.compile(r"parseExpression\s*\(\s*(?![\"'])"),
         "HIGH", [], [], kind="antipattern",
         note="parseExpression with a non-literal argument: injection/RCE (Spring4Shell class).",
         fix="Do not parse user-influenced strings as SpEL; use SimpleEvaluationContext "
             "or fixed expressions."),
    Rule("SRC-JNDI-LOOKUP", "JNDI lookup with a non-literal name",
         re.compile(r"\.lookup\s*\(\s*(?![\"'])"),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="JNDI injection when externally influenced (Log4Shell class).",
         fix="Do not build lookup names from input; restrict JNDI to fixed, trusted names."),
    Rule("SRC-SQLI-CONCAT", "Possible SQL injection (string concatenation)",
         re.compile(r"(?:createQuery|createNativeQuery|prepareStatement|prepareCall|"
                    r"executeQuery|executeUpdate|execute)\s*\(\s*(?:[^)]*?[\"']\s*\+|"
                    r"[A-Za-z_$][\w$]*\s*\+)"),
         "HIGH", [], [], always_report=True, kind="sink",
         note="Query assembled via string concatenation.",
         fix="Use parameterized queries (PreparedStatement with bind parameters, "
             "or JPA query parameters)."),
    Rule("SRC-CRYPTO-WEAK-HASH", "Weak hash function (MD5/SHA-1)",
         re.compile(r"MessageDigest\s*\.\s*getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']\s*\)"),
         "MEDIUM", [], [], kind="antipattern",
         note="MD5/SHA-1 are broken for security purposes.",
         fix="Use SHA-256+ for security purposes; for passwords use an adaptive "
             "PasswordEncoder (BCrypt/Argon2)."),
    Rule("SRC-CRYPTO-WEAK-RANDOM", "java.util.Random for security-relevant values",
         re.compile(r"\bnew\s+(?:java\.util\.)?Random\s*\("),
         "LOW", [], [], always_report=True, kind="sink",
         note="java.util.Random is predictable; unsuitable for tokens/keys/nonces.",
         fix="Use SecureRandom for security-relevant random values."),
    # sprig SPR-CORS-001 (implicit-default): a bare @CrossOrigin WITHOUT parentheses
    # allows every origin by default. SpringSecurityCheck-CROSS-ORIGIN-BROAD only catches
    # @CrossOrigin() or (origins="*") - this rule adds the parenthesis-less case.
    Rule("SRC-CROSSORIGIN-BARE", "@CrossOrigin without parentheses (default: all origins)",
         re.compile(r"@CrossOrigin\b(?!\s*\()"),
         "MEDIUM", [], [], kind="antipattern",
         note="@CrossOrigin without arguments allows all origins by default.",
         fix="Set origins/originPatterns explicitly, or configure CORS globally; "
             "do not combine '*' with credentials."),

    # --- Optimization pass #2 (found scanning JoyChou93/java-sec-code) -----
    Rule("SRC-CORS-ORIGIN-REFLECTION", "CORS: request's own Origin header reflected back",
         re.compile(r"\.setHeader\s*\(\s*[\"']Access-Control-Allow-Origin[\"']\s*,\s*(?!\s*[\"'])"),
         "CRITICAL", [], [], always_report=True, kind="antipattern",
         note="The Access-Control-Allow-Origin header is set from a non-literal value - if it "
              "echoes back the request's own Origin header, this is worse than a static wildcard: "
              "it allows any site to read the response, and (unlike '*') can be combined with "
              "Access-Control-Allow-Credentials: true, enabling full cross-origin credentialed access.",
         fix="Validate the Origin against an explicit allowlist before reflecting it, or use "
             "Spring's CorsConfiguration/CorsRegistry with a fixed list of trusted origins."),
    Rule("SRC-FASTJSON-PARSE", "Fastjson JSON.parseObject/parse on untrusted input",
         re.compile(r"\bJSON\s*\.\s*parse(?:Object|Array)?\s*\("),
         "HIGH", [], [], always_report=True, kind="sink",
         note="Fastjson's JSON.parseObject/parse can trigger polymorphic deserialization "
              "(autoType) leading to RCE on vulnerable versions, especially when the input is "
              "attacker-controlled and Feature.SupportAutoType / a permissive autoType config is set.",
         fix="Upgrade to a patched Fastjson version with autoType disabled by default, keep "
             "safe-mode enabled, and never enable Feature.SupportAutoType for untrusted input; "
             "prefer Jackson with a fixed target class instead."),
    Rule("SRC-CRLF-HEADER-INJECTION", "HTTP header/cookie value taken directly from request input",
         re.compile(r"\.(?:addHeader|setHeader)\s*\(\s*[^,]+,\s*(?:request\s*\.\s*getParameter|"
                    r"request\s*\.\s*getHeader)\s*\("),
         "HIGH", [], [], always_report=True, kind="sink",
         note="A response header is set directly from request input with no CRLF/newline "
              "filtering - allows HTTP response splitting / header injection (e.g. injecting "
              "extra headers or a fake response body via encoded \\r\\n sequences).",
         fix="Strip/reject CR and LF characters from the value before setting it as a header, "
             "or use an allowlist of expected values instead of passing request input through."),
    Rule("SRC-SSRF", "Possible SSRF (outbound call with a non-literal URL)",
         re.compile(r"(?:new\s+URL|(?:URI|RestTemplate)\s*\.\s*create|"
                    r"\.getForObject|\.getForEntity|\.postForObject|\.postForEntity|"
                    r"\.exchange|WebClient[^;]{0,40}\.uri|HttpClient[^;]{0,60}\.newBuilder\s*\(\s*\)"
                    r"[^;]{0,120}\.uri)\s*\(\s*(?![\"'])"),
         "HIGH", [], [], always_report=True, kind="sink",
         note="An outbound HTTP call is built from a non-literal URL/URI - if the value is "
              "externally influenced, this enables Server-Side Request Forgery (SSRF), "
              "reaching internal services or cloud metadata endpoints.",
         fix="Validate the target against an allowlist of hosts/schemes before making the "
             "request; never resolve a request-supplied URL directly."),
    Rule("SRC-PATH-TRAVERSAL", "Possible path traversal (file access with a non-literal path)",
         re.compile(r"\bnew\s+File\s*\(\s*(?:[A-Za-z_$][\w$.]*\s*(?:,|\))|[\"'][^\"']*[\"']\s*\+)|"
                    r"Paths\s*\.\s*get\s*\(\s*(?:(?![\"'])[A-Za-z_$][\w$.]*\s*(?:,|\))|"
                    r"[\"'][^\"']*[\"']\s*\+)"),
         "HIGH", [], [], always_report=True, kind="sink",
         note="A file/path object is built from a non-literal, externally-influenced value - "
              "without normalization and a base-directory check this allows path traversal "
              "(reading/writing files outside the intended directory, e.g. via '../').",
         fix="Resolve against a fixed base directory and reject the path unless "
             "path.normalize() stays inside it (or use Path#toRealPath and compare prefixes)."),
    Rule("SRC-OPEN-REDIRECT", "Possible open redirect (redirect target not validated)",
         re.compile(r"\.sendRedirect\s*\(\s*(?![\"'])|"
                    r"RedirectView\s*\(\s*(?![\"'])|"
                    r"redirect:\s*\"\s*\+"),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="A redirect target is built from a non-literal value - if externally "
              "influenced, this enables open redirect (phishing via a trusted domain).",
         fix="Validate the target against an allowlist of paths/hosts, or only allow "
             "relative paths within the application."),
    Rule("SRC-XPATH-INJECTION", "Dynamic XPath expression",
         re.compile(r"(?:XPath|xpath)\s*\.\s*(?:evaluate|compile)\s*\(\s*(?![\"'])", re.I),
         "HIGH", [], [], always_report=True, kind="sink",
         note="An XPath expression is built from a non-literal value and may be injectable.",
         fix="Use a fixed XPath or bind values with XPath variables; validate input before evaluation."),
    Rule("SRC-REGEX-INJECTION", "Dynamic regular expression (ReDoS risk)",
         re.compile(r"(?:Pattern\s*\.\s*compile|\.(?:matches|replaceAll|replaceFirst|split))\s*\(\s*(?![\"'])", re.I),
         "HIGH", [], [], always_report=True, kind="sink",
         note="Attacker-controlled regular expressions can cause catastrophic backtracking.",
         fix="Use a strict allowlist/length limit and a safe regex engine or timeout."),
    Rule("SRC-REFLECTION-INJECTION", "Reflection with dynamic class or member name",
         re.compile(r"(?:Class\s*\.\s*forName|\.getDeclaredMethod|\.getMethod|\.invoke|"
                    r"Constructor\s*\.\s*newInstance)\s*\(\s*(?![\"'])", re.I),
         "HIGH", [], [], always_report=True, kind="sink",
         note="Dynamic reflection can turn untrusted input into arbitrary code or class access.",
         fix="Use an explicit class/member allowlist and avoid reflection on request data."),
    Rule("SRC-MASS-ASSIGNMENT", "Unrestricted Spring data binding",
         re.compile(r"@ModelAttribute\s+(?:[\w.$<>?]+\s+)?\w+|\bWebDataBinder\b", re.I),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="Automatic binding may let callers set security-sensitive fields such as role/admin.",
         fix="Bind into a narrow DTO and configure setAllowedFields/setDisallowedFields explicitly."),
    Rule("SRC-DECOMPRESSION-BOMB", "Unbounded decompression or archive extraction",
         re.compile(r"\bnew\s+(?:ZipInputStream|GZIPInputStream|InflaterInputStream|"
                    r"TarArchiveInputStream)\s*\(", re.I),
         "HIGH", [], [], always_report=True, kind="sink",
         note="Compressed attacker input is processed without a visible size/entry limit.",
         fix="Enforce compressed and expanded byte limits, entry-count limits, and safe paths."),
    Rule("SRC-IDOR", "Object endpoint with identifier but no visible ownership check",
         re.compile(r"@(Get|Put|Patch|Delete)Mapping\s*\([^)]*\{(?:id|userId|accountId|orderId)\b", re.I),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="An identifier-based endpoint needs an explicit object-level authorization check.",
         fix="Check ownership/tenant scope in the service and enforce it with method security."),
    Rule("SRC-CRYPTO-WEAK-CIPHER", "Weak cipher or ECB mode",
         re.compile(r"Cipher\s*\.\s*getInstance\s*\(\s*[\"'](?:DES|3DES|DESede|RC4|RC2|.*?/ECB(?:/[^\"']*)?)[\"']", re.I),
         "HIGH", [], [], kind="antipattern",
         note="DES/RC4 or ECB mode provides insufficient confidentiality.",
         fix="Use an authenticated mode such as AES/GCM with a unique nonce."),
    Rule("SRC-CRYPTO-WEAK-KEY", "Weak asymmetric key size",
         re.compile(r"(?:KeyPairGenerator|RSA|DSA)[^;\n]{0,100}\b(?:initialize|init)\s*\(\s*(?:512|768|1024)\b", re.I),
         "HIGH", [], [], kind="antipattern",
         note="The configured key size is below modern security recommendations.",
         fix="Use at least RSA-2048/3072 or an approved modern curve."),
    Rule("SRC-RESOURCE-EXHAUSTION", "Unbounded request, file, or response size",
         re.compile(r"\bMultipartFile\b|Files\s*\.\s*readAllBytes\s*\(|InputStream\s*\.\s*readAllBytes\s*\(", re.I),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="The operation can consume attacker-controlled memory or disk without a visible limit.",
         fix="Set multipart, request, decompressed, and response size limits and stream large data."),
    Rule("SRC-LOG-SENSITIVE", "Sensitive value written to application logs",
         re.compile(r"\b(?:log|logger)\s*\.\s*(?:trace|debug|info|warn|error)\s*\([^\n]{0,180}\b(?:password|passwd|secret|token|authorization|cookie)\b", re.I),
         "HIGH", [], [], always_report=True, kind="sink",
         note="Tokens, credentials, or session material must not be written to logs.",
         fix="Remove the value from logs or redact it before logging."),
    Rule("SRC-SENSITIVE-URL", "Sensitive value placed in a URL or query string",
         re.compile(r"(?:sendRedirect|URI\s*\.\s*create|new\s+URL|queryParam)\s*\([^\n]{0,180}\b(?:password|passwd|secret|token|session|authorization)\b", re.I),
         "HIGH", [], [], always_report=True, kind="sink",
         note="Secrets in URLs leak through browser history, proxies, referrers, and access logs.",
         fix="Send secrets in protected headers or request bodies and rotate exposed values."),
    Rule("SRC-HOSTNAME-VERIFIER", "Custom hostname verifier may accept any host",
         re.compile(r"setHostnameVerifier\s*\(\s*(?:\([^)]*\)\s*[-=]>\s*true|new\s+HostnameVerifier)", re.I),
         "HIGH", [], [], always_report=True, kind="antipattern",
         note="A permissive custom hostname verifier defeats TLS endpoint identity checks.",
         fix="Use the platform default hostname verifier and certificate validation."),
    Rule("SRC-TIMING-SECRET-COMPARE", "Secret compared with ordinary equals",
         re.compile(r"\b(?:password|passwd|secret|token|signature|hmac)\b[^\n]{0,40}\.equals\s*\(", re.I),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="Ordinary string comparison can leak information through timing differences.",
         fix="Use a constant-time comparison such as MessageDigest.isEqual for secret bytes."),
    Rule("SRC-DIRECTORY-LISTING", "Directory contents enumerated for a response",
         re.compile(r"(?:Files\s*\.\s*list|Files\s*\.\s*walk|DirectoryStream\s*<|new\s+DirectoryStream)", re.I),
         "LOW", [], [], always_report=True, kind="sink",
         note="Returning filesystem directory contents can disclose files and metadata.",
         fix="Do not expose directory enumeration; use an allowlisted resource index."),
    Rule("SRC-EXCEPTION-SWALLOW", "Broad exception swallowed",
         re.compile(r"catch\s*\(\s*(?:Exception|Throwable|RuntimeException)\b[^)]*\)\s*\{\s*\}", re.I | re.S),
         "MEDIUM", [], [], always_report=True, kind="antipattern",
         note="Swallowing broad exceptions hides security failures and can leave unsafe state active.",
         fix="Handle the specific exception, fail closed, and log without sensitive data."),
    # Reactive Spring Security uses a separate DSL and filter chain.  These
    # patterns intentionally stay scoped to the reactive API names so the
    # servlet rules above do not produce duplicate findings.
    Rule("WEBFLUX-PERMITALL", "WebFlux anyExchange().permitAll()",
         re.compile(r"authorizeExchange\s*\([^)]{0,300}?anyExchange\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)", re.I | re.S),
         "CRITICAL", [], [], always_report=True, kind="antipattern",
         note="The reactive catch-all route is publicly reachable.",
         fix="Require authentication for the catch-all and permit only explicit public endpoints."),
    Rule("WEBFLUX-CSRF-DISABLED", "WebFlux CSRF protection disabled",
         re.compile(r"\.csrf\s*\(\s*(?:ServerHttpSecurity\.CsrfSpec\s*::\s*disable|\w+\s*->\s*\w+\s*\.\s*disable\s*\(\s*\))", re.I),
         "HIGH", [], [], always_report=True, kind="antipattern",
         note="Reactive CSRF protection is disabled; this is safe only for a documented stateless API.",
         fix="Keep CSRF enabled for browser sessions, or document and enforce a stateless token-only API."),
    Rule("WEBFLUX-FN-SENSITIVE-ROUTE", "Sensitive functional WebFlux route",
         re.compile(r"(?:RouterFunctions\s*\.\s*)?route\s*\([^\n]{0,180}?GET\s*\(\s*[\"']/(?:admin|api|actuator|internal)\b", re.I),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="Functional WebFlux routes bypass controller-specific heuristics; verify that this sensitive route is protected by the reactive filter chain.",
         fix="Require authentication/authorization for the route and test it through the WebFlux security chain."),
    Rule("RSOCKET-PERMITALL", "RSocket payload authorization permits all",
         re.compile(r"(?:authorizePayload|RSocketSecurity)[\s\S]{0,300}?(?:anyExchange|anyRequest)\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)", re.I),
         "CRITICAL", [], [], always_report=True, kind="antipattern",
         note="All RSocket payloads are accepted without authorization.",
         fix="Authorize routes explicitly with authorizePayload and require authentication by default."),
    Rule("RSOCKET-NO-PAYLOAD-AUTH", "RSocket security without visible payload authorization",
         re.compile(r"@EnableRSocketSecurity\b", re.I),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="RSocket security is enabled; verify that a PayloadSocketAcceptorInterceptor or authorizePayload policy is configured.",
         fix="Define explicit payload authorization and authentication metadata, then deny unmatched routes."),
    Rule("OAUTH2-REACTIVE-NO-ISSUER", "Reactive JWT decoder without issuer binding",
         re.compile(r"NimbusReactiveJwtDecoder\s*\.\s*withJwkSetUri\s*\(", re.I),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="A remote JWK set alone does not bind tokens to the expected issuer.",
         fix="Prefer JwtDecoders.fromIssuerLocation or validate issuer explicitly alongside the JWK source."),
    Rule("OAUTH2-REACTIVE-JWK-REMOTE", "Reactive JWT decoder trusts a remote JWK URL",
         re.compile(r"NimbusReactiveJwtDecoder\s*\.\s*withJwkSetUri\s*\(\s*[\"']http://", re.I),
         "HIGH", [], [], always_report=True, kind="antipattern",
         note="JWK material is fetched over plaintext HTTP and can be replaced in transit.",
         fix="Use HTTPS with certificate validation and bind the issuer/audience explicitly."),
    Rule("X509-AUTH-CONFIG-REVIEW", "X.509 authentication configuration requires review",
         re.compile(r"\.x509\s*\(\s*(?:Customizer\.withDefaults\s*\(\s*\)|\w+\s*->)", re.I),
         "MEDIUM", [], [], always_report=True, kind="sink",
         note="Verify that client certificates are required, mapped to the intended principal, and backed by a trusted CA.",
         fix="Require client certificates at the TLS layer, use a restricted trust store, and configure an explicit subject principal mapping."),

    # ---- JWT deep checks (jwt_tool attack playbook) -------------------------
    # These complement the existing SpringSecurityCheck-JWT-* rules and focus on
    # code-level construction mistakes that jwt_tool would expose at runtime.

    Rule("JWT-NO-EXPIRY", "JWT built without an expiration claim",
         # Matches .builder() or Jwts.builder() chains that contain .signWith( but
         # no .expiration( / .setExpiration( anywhere on the same statement chain.
         re.compile(
             r"Jwts\s*\.\s*builder\s*\(\s*\)"
             r"(?:(?!\.(?:expiration|setExpiration)\s*\().){0,800}"
             r"\.signWith\s*\(",
             re.I | re.S),
         "MEDIUM", [], [],
         "A JWT is signed and issued without setting an expiration (exp) claim. "
         "Tokens never expire and remain valid indefinitely after theft.",
         always_report=True, kind="antipattern",
         fix="Add .expiration(new Date(System.currentTimeMillis() + TOKEN_TTL_MS)) "
             "before .signWith(). Short-lived tokens (≤15 min) with refresh-token "
             "rotation are the recommended pattern."),

    Rule("JWT-NO-AUDIENCE", "JWT issued without an audience claim",
         re.compile(
             r"Jwts\s*\.\s*builder\s*\(\s*\)"
             r"(?:(?!\.(?:audience|setAudience|claim\s*\(\s*[\x22\x27]aud[\x22\x27])\s*\().){0,800}"
             r"\.signWith\s*\(",
             re.I | re.S),
         "LOW", [], [],
         "A JWT is issued without an audience (aud) claim. Without it, a token "
         "issued for service A can be replayed against service B if both trust the "
         "same key.",
         always_report=True, kind="antipattern",
         fix='Add .audience().add("your-api-id").and() (jjwt 0.12+) or '
             ".claim(\"aud\", \"your-api-id\") before .signWith()."),

    Rule("JWT-NO-SUBJECT-VALIDATION", "JWT parser does not enforce a subject claim",
         re.compile(
             r"Jwts\s*\.\s*(?:parser|parserBuilder)\s*\(\s*\)"
             r"(?:(?!\.requireSubject\s*\().){0,600}"
             r"\.(?:setSigningKey|verifyWith|secretKey)\s*\(",
             re.I | re.S),
         "LOW", [], [],
         "The JWT parser does not call .requireSubject(), so a token with a missing "
         "or empty sub claim is accepted silently. This can mask impersonation.",
         always_report=True, kind="antipattern",
         fix="Call .requireSubject(expectedSub) on the parser builder."),

    Rule("JWT-BLANK-SECRET", "JWT signed with an empty or trivially weak secret",
         # Matches .signWith( with an empty literal, blank-password literal, or
         # new byte[0] as the key material. The optional prefix group covers both
         # the short form (Keys.hmacShaKeyFor) and fully-qualified class paths
         # (io.jsonwebtoken.security.Keys.hmacShaKeyFor) that javac-style imports
         # emit in the source. .getBytes() after the literal is also allowed.
         re.compile(
             r"\.signWith\s*\(\s*"
             r"(?:[A-Za-z0-9_.]+\s*\.\s*hmacShaKeyFor\s*\(\s*)?"
             r"(?:"
             r"[\x22\x27]{2}(?:\.getBytes\s*\(\s*\))?"
             r"|[\x22\x27]\s{1,10}[\x22\x27]"
             r"|new\s+byte\s*\[\s*0\s*\]"
             r"|[\x22\x27](?:secret|password|test|jwt|key|changeme|placeholder)[\x22\x27]"
             r"(?:\.getBytes\s*\(\s*\))?"
             r")",
             re.I),
         "CRITICAL", [], [],
         "JWT is signed with an empty or well-known trivial secret. "
         "Any attacker can forge arbitrary tokens (CVE-2019-20933 / CVE-2020-28637 class).",
         always_report=True, kind="antipattern",
         fix="Generate a cryptographically random key: "
             "Keys.secretKeyFor(SignatureAlgorithm.HS256) or a 256-bit random byte array "
             "stored in a secrets manager, never in source code."),

    Rule("JWT-NULL-SIGNATURE", "JWT parser accepts tokens with a null or empty signature",
         re.compile(
             r"setAllowedAlgorithm[^(]{0,60}(?:NONE|none)|"
             r"ignoreSignature\s*\(\s*\)|"
             r"\.parse\s*\([^)]{0,200}\)\s*\.(?:getBody|getPayload)\s*\(\s*\)"
             r"(?![\s\S]{0,200}\.(?:setSigningKey|verifyWith))",
             re.I | re.S),
         "CRITICAL", [], [],
         "The JWT parser is configured to accept tokens without verifying the signature. "
         "Token forgery requires no secret at all (CVE-2020-28042 class).",
         always_report=True, kind="antipattern",
         fix="Always call .setSigningKey() / .verifyWith() before parsing. "
             "Use parseClaimsJws() (not parseClaimsJwt()) to enforce a signature."),

    Rule("JWT-WEAK-KEY-SIZE", "JWT/crypto key size below recommended minimum",
         # RSA < 2048 bit or EC < 256 bit in KeyPairGenerator.initialize()
         re.compile(
             r"(?:RSA|EC|DSA)[^;\n]{0,40}"
             r"KeyPairGenerator\s*\.\s*getInstance\s*\([^;\n]{0,80}"
             r"\.\s*initialize\s*\(\s*(\d+)"
             r"|KeyPairGenerator\s*\.\s*getInstance\s*\([^)\n]{0,40}"
             r"(?:RSA|DSA)[^;\n]{0,80}\.initialize\(\s*(\d+)",
             re.I),
         "HIGH", [], [],
         "RSA/DSA key sizes below 2048 bit (or EC below 256 bit) are considered weak "
         "and breakable with modern hardware.",
         always_report=True, kind="antipattern",
         fix="Use at least RSA-2048 or EC P-256/P-384. "
             "For new code prefer EC (smaller, faster) or RSA-4096 for long-lived keys."),

    Rule("JWT-JWKS-HTTP", "JWKS endpoint fetched over plain HTTP",
         re.compile(
             r"(?:withJwkSetUri|withPublicKey|JWKSet\s*\.\s*load)\s*\(\s*"
             r"[\x22\x27]http://",
             re.I),
         "HIGH", [], [],
         "The JWK Set is fetched over unencrypted HTTP. An attacker on the network "
         "can substitute their own public key and then forge valid tokens.",
         always_report=True, kind="antipattern",
         fix="Use HTTPS with a valid certificate. "
             "Pin the JWKS URI and set a short cache TTL."),

    # ---- JWT extended checks (3.10) -----------------------------------------

    Rule("JWT-AUDIENCE-VALIDATION", "JWT parser does not verify the audience claim",
         # Fires when a Jwts parser/parserBuilder is used but .requireAudience() or
         # JwtClaimValidator("aud", ...) is absent from the same chain.
         re.compile(
             r"Jwts\s*\.\s*(?:parser|parserBuilder)\s*\(\s*\)"
             r"(?:(?!\.(?:requireAudience|requireAud)\s*\().){0,600}"
             r"\.(?:setSigningKey|verifyWith|secretKey)\s*\(",
             re.I | re.S),
         "MEDIUM", [], [],
         "JWT parser does not enforce audience (aud) validation. "
         "A token issued for service A can be replayed at service B if both share the same key.",
         fix="Call .requireAudience(\"expected-audience\") on the parser builder, "
             "or use a JwtClaimValidator<List<String>>(\"aud\", aud -> aud.contains(\"my-api\")) "
             "as part of a DelegatingOAuth2TokenValidator."),

    Rule("JWT-CLOCK-SKEW", "JWT clock skew tolerance set to more than 5 minutes",
         # JwtTimestampValidator(Duration.ofMinutes(N)) with N > 5, or old-style
         # setAllowedClockSkewSeconds(N) / allowedClockSkewSeconds(N) > 300.
         re.compile(
             r"JwtTimestampValidator\s*\(\s*Duration\s*\.\s*ofMinutes\s*\(\s*([6-9]|\d{2,})\s*\)|"
             r"JwtTimestampValidator\s*\(\s*Duration\s*\.\s*ofHours\s*\(\s*\d+\s*\)|"
             r"(?:setAllowedClockSkewSeconds|allowedClockSkewSeconds)\s*\(\s*([3-9]\d{2,}|\d{4,})\s*\)",
             re.I),
         "LOW", [], [],
         "A clock skew tolerance >5 minutes extends the validity window of expired tokens, "
         "giving attackers more time to replay stolen tokens.",
         always_report=True, kind="antipattern",
         fix="Keep clock skew at or below 5 minutes (Duration.ofMinutes(5) / 300 seconds). "
             "Pair short-lived tokens with refresh-token rotation instead."),

    Rule("JWT-SENSITIVE-CLAIMS", "Sensitive PII or role data embedded directly in JWT payload",
         # Detects .claim("email"/"phone"/"ssn"/"dob"/"address"/"role"/"roles"/"permissions")
         # being set on a builder — these fields land in the (base64-only) payload visible
         # to any token holder without decryption.
         re.compile(
             r"\.claim\s*\(\s*[\x22\x27]"
             r"(?:email|phone|ssn|social.?security|dob|date.?of.?birth|address|"
             r"role|roles|permission|permissions|authorities|groups|salary|credit)"
             r"[\x22\x27]",
             re.I),
         "LOW", [], [],
         "Sensitive data (PII, roles, permissions) is stored in the JWT payload. "
         "JWT payloads are only base64-encoded, not encrypted, so any token holder "
         "can read this data. Use opaque tokens or JWE if sensitive claims are required.",
         always_report=True, kind="sink",
         fix="Store only a stable, non-sensitive subject identifier in the JWT. "
             "Fetch roles/permissions from the authorisation server at request time, "
             "or use JWE (JSON Web Encryption) for sensitive payloads."),

    Rule("JWT-REFRESH-TOKEN-REUSE", "Refresh token stored insecurely or reuse not detected",
         # Flags refresh tokens stored in localStorage (JS interop / Thymeleaf inline),
         # Cookie without explicit Secure+HttpOnly, or direct DB upsert without a
         # rotation/revocation column alongside it.
         re.compile(
             r"localStorage\s*\.\s*setItem\s*\([^)]{0,60}(?:refresh|token)|"
             r"refreshToken\s*[=:]\s*(?:request\s*\.\s*getParameter|"
             r"request\s*\.\s*getHeader|getCookies\s*\(\s*\)[^;]{0,120}\.getValue)"
             r"[^;]{0,200}(?:\.save\s*\(|repository\s*\.\s*save\s*\()",
             re.I | re.S),
         "MEDIUM", [], [],
         "A refresh token appears to be stored in localStorage (XSS-readable) or "
         "persisted without a rotation/revocation strategy. Stolen refresh tokens "
         "allow persistent account takeover.",
         always_report=True, kind="sink",
         fix="Store refresh tokens in HttpOnly Secure cookies (not localStorage). "
             "Implement refresh-token rotation: issue a new refresh token on every use "
             "and invalidate the old one. Detect and revoke token families on reuse."),

    # ---- Rules from CodeQL/Semgrep gap analysis (3.11) ----------------------

    Rule("JWT-PARSE-NO-VERIFY", "JWT parsed with .parse() instead of .parseClaimsJws()",
         # CodeQL: java/missing-jwt-signature-check (CWE-347, severity 7.8, precision high)
         # .setSigningKey()/verifyWith() is set but the chain ends with .parse(...) instead
         # of .parseClaimsJws(...) / .parseClaimsJwt(...). The parse() method silently
         # accepts tokens with an empty signature even when a key is configured.
         re.compile(
             r"Jwts\s*\.\s*(?:parser|parserBuilder)\s*\(\s*\)"
             r"(?:(?!\.parseClaimsJw[st]\s*\().){0,600}"
             r"\.(?:setSigningKey|verifyWith|secretKey)\s*\([^;]{0,200}"
             r"\.parse\s*\(",
             re.I | re.S),
         "CRITICAL", [], [],
         "JwtParser.parse() accepts tokens with an empty or missing signature even when a "
         "signing key is set. Use parseClaimsJws() (or parseClaimsJwt() for unsigned tokens "
         "that you explicitly trust). CWE-347 — CodeQL java/missing-jwt-signature-check.",
         always_report=True, kind="antipattern",
         fix="Replace .parse(token) with .parseClaimsJws(token) to enforce signature "
             "verification. For unsigned tokens that you legitimately need, use "
             "parseClaimsJwt() and ensure the path is only reachable for trusted issuers."),

    Rule("SRC-CRYPTO-STATIC-IV", "Static or hardcoded IV used for symmetric encryption",
         # CWE-329: Not using a random IV with CBC/GCM makes ciphertext deterministic.
         # Detects: new GCMParameterSpec(128, "literal") / new IvParameterSpec("literal")
         # and byte[] iv = {1,2,3,...} followed by IvParameterSpec(iv) is caught by the
         # array-literal branch.
         re.compile(
             # Drop "new" prefix to match FQN (javax.crypto.spec.GCMParameterSpec)
             # Also accept byte[] initialiser (new byte[]{...}) via [\d\]] in char class
             r"GCMParameterSpec\s*\(\s*\d+\s*,\s*(?:"
             r"[\x22\x27][^\x22\x27]{0,64}[\x22\x27]"
             r"|new\s+byte\s*\[\s*[\d\]]"
             r")|"
             r"IvParameterSpec\s*\(\s*(?:"
             r"[\x22\x27][^\x22\x27]{0,64}[\x22\x27]"
             r"|new\s+byte\s*\[\s*[\d\]]"
             r")",
             re.I),
         "HIGH", [], [],
         "A static or hardcoded IV is used for AES-GCM or AES-CBC encryption. "
         "Reusing the same IV with the same key leaks the keystream (GCM) or "
         "allows plaintext recovery (CBC). CWE-329.",
         always_report=True, kind="antipattern",
         fix="Generate a fresh random IV for every encryption operation: "
             "byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv); "
             "new GCMParameterSpec(128, iv). Prepend the IV to the ciphertext for decryption."),

    Rule("SRC-CRYPTO-RSA-NO-OAEP", "RSA encryption without OAEP padding",
         # CWE-780: RSA/ECB/PKCS1Padding is vulnerable to Bleichenbacher (PKCS#1 v1.5).
         # Plain "RSA" defaults to PKCS1Padding on most JCA providers.
         re.compile(
             r'Cipher\s*\.\s*getInstance\s*\(\s*[\x22\x27]'
             r'(?:RSA(?:/ECB/PKCS1Padding)?|RSA/NONE/PKCS1Padding)'
             r'[\x22\x27]',
             re.I),
         "HIGH", [], [],
         "RSA encryption uses PKCS#1 v1.5 padding (or no explicit padding, which defaults "
         "to PKCS#1 v1.5). This is vulnerable to the Bleichenbacher padding oracle attack. "
         "CWE-780.",
         always_report=True, kind="antipattern",
         fix='Use OAEP padding: Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"). '
             "For key wrapping, use AES-GCM key wrapping instead of raw RSA."),

    Rule("SRC-RANDOM-PREDICTABLE-SEED", "SecureRandom seeded with a fixed or constant value",
         # CWE-330: SecureRandom.setSeed(constant) or new SecureRandom(byte[] literal)
         # reduces entropy to zero — the sequence becomes fully predictable.
         re.compile(
             r"(?:new\s+SecureRandom\s*\(\s*(?:"
             r"[\x22\x27][^\x22\x27]{0,64}[\x22\x27]"
             r"|new\s+byte\s*\[\s*[\d\]]"
             r"|\d+[Ll]?\s*\)"
             r")|"
             r"\.setSeed\s*\(\s*(?:"
             r"[\x22\x27][^\x22\x27]{0,64}[\x22\x27]"
             r"|new\s+byte\s*\[\s*[\d\]]"
             r"|\d+[Ll]?\s*\)"
             r"))",
             re.I),
         "HIGH", [], [],
         "SecureRandom is seeded with a fixed constant or byte literal, making the "
         "generated sequence fully predictable. An attacker who knows the seed can "
         "reproduce all outputs. CWE-330.",
         always_report=True, kind="antipattern",
         fix="Never seed SecureRandom explicitly — the JVM seeds it from OS entropy by "
             "default. If you must seed (e.g. for testing), use "
             "SecureRandom.getInstanceStrong() in production code."),

    Rule("SpringSecurityCheck-REGEX-NO-DOTALL",
         "RegexRequestMatcher without case-insensitive flag (auth-bypass via newline)",
         # Semgrep: spring-security-regex-matcher-without-dotall
         # A regex like /admin/.* without Pattern.CASE_INSENSITIVE can be bypassed
         # by injecting a newline before the path (CVE-2022-22978 class).
         re.compile(
             r"new\s+RegexRequestMatcher\s*\(\s*[\x22\x27][^\x22\x27]{1,200}[\x22\x27]"
             r"(?:\s*,\s*null\s*)?\s*\)",
             re.I),
         "HIGH", [], [],
         "RegexRequestMatcher is constructed without the case-insensitive flag. "
         "A path like /Admin%0a bypasses patterns like /admin/.* because the regex "
         "anchor does not span the injected newline. CVE-2022-22978 class.",
         always_report=True, kind="antipattern",
         fix="Pass Pattern.CASE_INSENSITIVE as the second argument to RegexRequestMatcher, "
             "or use AntPathRequestMatcher / MvcRequestMatcher for simpler path patterns."),

    Rule("SpringSecurityCheck-PREAUTH-ON-INTERFACE",
         "@PreAuthorize or @PostAuthorize on an interface method",
         # Semgrep: spring-security-annotation-on-interface
         # Spring AOP proxies intercept calls on concrete classes, not interfaces —
         # annotations on interface methods are silently ignored at runtime.
         re.compile(
             r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\s*\([^)]{0,200}\)"
             r"(?:\s*(?:@\w+(?:\([^)]*\))?\s*)*)?"
             r"\s+(?:public\s+)?(?:abstract\s+)?[\w<>\[\],.?\s]{1,80}\s+\w+\s*\(",
             re.I | re.S),
         "MEDIUM", [[("METHOD_SECURITY_ENABLED", True)]], [],
         "A security annotation (@PreAuthorize/@PostAuthorize/@Secured) appears on what "
         "may be an interface method. Spring Security uses AOP proxies on concrete classes; "
         "annotations on interface methods are silently ignored at runtime, leaving the "
         "method effectively unprotected.",
         always_report=True, kind="sink",
         fix="Move @PreAuthorize/@PostAuthorize to the concrete implementation class. "
             "Enable global method security with @EnableMethodSecurity(proxyTargetClass=true) "
             "to ensure annotations on target classes (not proxy interfaces) are applied."),

    Rule("SRC-SSTI-VIEW-NAME", "Spring MVC view name derived from a request parameter",
         # CWE-094: Returning a view name that contains a request parameter value allows
         # attackers to trigger open-redirect (redirect:http://evil.com) or SSTI
         # (e.g. Groovy template engines evaluate __${{7*7}}__::x).
         # Pattern: a controller method returns a String that contains or is built from
         # request parameter input (getParameter / @RequestParam variable).
         re.compile(
             r"return\s+(?:"
             r"[\x22\x27](?:redirect:|forward:)[^\x22\x27]{0,200}[\x22\x27]\s*\+\s*\w+"
             r"|[\x22\x27]redirect:[\x22\x27]\s*\+\s*\w+"
             r"|[\x22\x27]forward:[\x22\x27]\s*\+\s*\w+"
             r"|\w+\s*\+\s*[\x22\x27](?::|/|\\.)"
             r")",
             re.I),
         "HIGH", [], [],
         "A Spring MVC controller returns a view name constructed by concatenating a "
         "request-controlled variable. This enables open redirect via redirect: prefix "
         "and potential Server-Side Template Injection (SSTI) in some template engines. "
         "CWE-094.",
         always_report=True, kind="sink",
         fix="Never concatenate user input into a view name or redirect target. "
             "Use an allowlist of valid view names or redirect URIs and look up "
             "by a safe key. For redirects, use UriComponentsBuilder with explicit "
             "host/path validation."),
]



# --- 2b) positive hardening measures ---------------------------------------
# Unlike the sink/antipattern rules above, these do not describe a risk that
# then gets judged as guarded or not. The pattern match itself IS the good
# practice - it is reported (kind="hardening" -> always HARDENED/INFO, see
# evaluate()) whether or not anything risky is nearby in the same file. Shown
# with --show-hardened, same as any other HARDENED finding.
HARDENING_RULES: List[Rule] = [
    Rule("HARDEN-BCRYPT-STRENGTH", "BCryptPasswordEncoder with an explicit work factor",
         # Accepts both new BCryptPasswordEncoder(12) and the
         # (BCryptVersion, strength[, SecureRandom]) overload - any digit
         # inside the parens means a strength was set explicitly, not just
         # strength as the very first argument.
         re.compile(r"new\s+BCryptPasswordEncoder\s*\([^)\n]{0,120}\d", re.I),
         "LOW", [], [], kind="hardening",
         note="An explicit BCrypt strength/cost parameter is set instead of relying on the default.",
         fix=""),
    Rule("HARDEN-STRONG-PW-ENCODER", "Modern memory/CPU-hard password encoder in use",
         re.compile(r"\b(?:Argon2PasswordEncoder|SCryptPasswordEncoder|Pbkdf2PasswordEncoder)\b"),
         "LOW", [], [], kind="hardening",
         note="A modern, deliberately slow password encoder (Argon2/SCrypt/PBKDF2) is used instead of a fast general-purpose hash.",
         fix=""),
    Rule("HARDEN-SECURE-RANDOM", "java.security.SecureRandom used for random values",
         re.compile(r"new\s+SecureRandom\s*\("),
         "LOW", [], [], kind="hardening",
         note="A cryptographically strong random source is used instead of java.util.Random.",
         fix=""),
    Rule("HARDEN-CSP-CONFIGURED", "Content-Security-Policy explicitly configured",
         re.compile(r"\.contentSecurityPolicy\s*\(|\bContentSecurityPolicyHeaderWriter\b", re.I),
         "LOW", [], [], kind="hardening",
         note="A Content-Security-Policy is explicitly configured rather than left at the framework default.",
         fix=""),
    Rule("HARDEN-HSTS-CONFIGURED", "HTTP Strict-Transport-Security explicitly configured",
         re.compile(r"\.httpStrictTransportSecurity\s*\(|\bHstsHeaderWriter\b", re.I),
         "LOW", [], [], kind="hardening",
         note="HSTS is explicitly configured, helping enforce HTTPS on returning clients.",
         fix=""),
    Rule("HARDEN-COOKIE-HTTPONLY", "Cookie explicitly marked HttpOnly",
         # .setHttpOnly(true) is specific to javax/jakarta Cookie - safe unscoped.
         # Bare .httpOnly(true) is also a generic fluent-builder shape (unrelated
         # builders use the same method name), so that alternative requires
         # "cookie" to appear earlier on the same statement (matches both the
         # ResponseCookie/-Builder class name and a `cookie`-named variable).
         # No \b before "cookie": it must also match inside a camelCase
         # identifier like ResponseCookie/CookieBuilder, where a word
         # boundary never occurs between "Response" and "Cookie".
         re.compile(r"\.setHttpOnly\s*\(\s*true\s*\)|cookie[^;\n]{0,200}?\.httpOnly\s*\(\s*true\s*\)", re.I),
         "LOW", [], [], kind="hardening",
         note="A cookie is explicitly marked HttpOnly, blocking script access to its value.",
         fix=""),
    Rule("HARDEN-COOKIE-SECURE-FLAG", "Cookie explicitly marked Secure",
         # Same reasoning as HARDEN-COOKIE-HTTPONLY: bare .secure(true) is too
         # generic a builder shape (TLS/HTTP client builders use it too) to
         # trust without "cookie" context nearby.
         # Same camelCase reasoning as HARDEN-COOKIE-HTTPONLY: no \b before "cookie".
         re.compile(r"\.setSecure\s*\(\s*true\s*\)|cookie[^;\n]{0,200}?\.secure\s*\(\s*true\s*\)", re.I),
         "LOW", [], [], kind="hardening",
         note="A cookie is explicitly marked Secure, restricting it to HTTPS transport.",
         fix=""),
    Rule("HARDEN-METHOD-SECURITY", "Method-level authorization in use",
         re.compile(r"@EnableMethodSecurity\b|@(?:PreAuthorize|PostAuthorize)\s*\(", re.I),
         "LOW", [], [], kind="hardening",
         note="Fine-grained method-level authorization (@EnableMethodSecurity/@PreAuthorize/@PostAuthorize) is in use.",
         fix=""),
    Rule("HARDEN-CORS-EXPLICIT-ORIGIN", "CORS allowedOrigins pinned to an explicit HTTPS origin",
         # Covers both the WebMvcConfigurer/CorsRegistry form (.allowedOrigins(...))
         # and the CorsConfiguration form (setAllowedOrigins(...)/addAllowedOrigin(...)).
         re.compile(r"\.allowedOrigins\s*\(\s*[\"']https://|"
                    r"\.setAllowedOrigins\s*\([^)\n]{0,40}[\"']https://|"
                    r"\.addAllowedOrigin\s*\(\s*[\"']https://", re.I),
         "LOW", [], [], kind="hardening",
         note="CORS is restricted to an explicit HTTPS origin rather than a wildcard.",
         fix=""),
    Rule("HARDEN-XXE-DISALLOW-DOCTYPE", "XML parser explicitly disallows DOCTYPE declarations",
         re.compile(r"setFeature\s*\(\s*[\"']http://apache\.org/xml/features/disallow-doctype-decl[\"']\s*,\s*true\s*\)", re.I),
         "LOW", [], [], kind="hardening",
         note="DOCTYPE declarations are explicitly disallowed on this XML parser, the strongest available XXE mitigation.",
         fix=""),
    Rule("HARDEN-PREPARED-STATEMENT", "Parameterized SQL via a literal PreparedStatement query",
         re.compile(r"\.prepareStatement\s*\(\s*[\"']", re.I),
         "LOW", [], [], kind="hardening",
         note="The SQL query text is a literal passed to PreparedStatement, i.e. parameterized rather than built by concatenation.",
         fix=""),
    Rule("HARDEN-BEAN-VALIDATION-CONSTRAINT", "Bean Validation constraint annotation present",
         re.compile(r"@(?:NotNull|NotBlank|NotEmpty|Size|Email|Pattern|Digits|Min|Max|Positive|Negative)\b"),
         "LOW", [], [], kind="hardening",
         note="A Bean Validation constraint annotation enforces a concrete rule on this field/parameter.",
         fix=""),
    Rule("HARDEN-JWT-STRONG-ALG", "JWT uses an asymmetric or modern HMAC algorithm",
         # Flags RS256/RS384/RS512, ES256/ES384/ES512, PS256/PS384/PS512 in signWith() calls
         # and explicit algorithm enum references.
         re.compile(
             r"\.signWith\s*\([^)\n]{0,120}"
             r"(?:RS(?:256|384|512)|ES(?:256|384|512)|PS(?:256|384|512))"
             r"|SignatureAlgorithm\.(?:RS|ES|PS)\d+",
             re.I),
         "LOW", [], [], kind="hardening",
         note="JWT is signed with a strong asymmetric or HMAC-SHA-384/512 algorithm "
              "rather than the weak HS256 default.",
         fix=""),
    Rule("HARDEN-JWT-EXPIRY-SET", "JWT explicitly sets an expiration claim",
         re.compile(r"\.(?:expiration|setExpiration)\s*\(", re.I),
         "LOW", [], [], kind="hardening",
         note="JWT builder sets an expiration (exp) claim, bounding the token lifetime.",
         fix=""),
    Rule("HARDEN-JWT-ISSUER-VALIDATION", "JWT parser validates the issuer claim",
         re.compile(
             r"\.requireIssuer\s*\(|"
             r"JwtValidators\.createDefaultWithIssuer\s*\(|"
             r"new\s+JwtClaimValidator\s*<[^>]{0,30}>\s*\(\s*[\x22\x27]iss[\x22\x27]",
             re.I),
         "LOW", [], [], kind="hardening",
         note="JWT issuer validation is enforced, preventing tokens from foreign issuers "
              "from being accepted.",
         fix=""),
    Rule("HARDEN-JWT-SECRET-FROM-ENV", "JWT secret sourced from environment / config, not hardcoded",
         # Matches @Value injection, System.getenv(), env.getProperty(), and
         # SecretsManager / Vault client patterns - all better than a string literal.
         re.compile(
             r"@Value\s*\(\s*[\x22\x27]\$\{[^}]+\}[\x22\x27]\s*\)\s*"
             r"(?:private\s+)?(?:String|byte\[\]|SecretKey)[^;\n]{0,80}"
             r"(?:secret|key|jwt|sign)"
             r"|System\.getenv\s*\([^)]{0,40}(?:secret|key|jwt|sign)"
             r"|env\.getProperty\s*\([^)]{0,40}(?:secret|key|jwt|sign)"
             r"|secretsManager\.getSecretValue|vault\.read",
             re.I),
         "LOW", [], [], kind="hardening",
         note="The JWT secret/key is loaded from an environment variable, config property, "
              "or secrets manager rather than being hardcoded in source.",
         fix=""),
    Rule("HARDEN-JWT-AUDIENCE-VALIDATION", "JWT parser enforces audience claim",
         re.compile(
             r"\.requireAudience\s*\(|"
             # JwtClaimValidator may have a complex generic like <List<String>> and a
             # fully-qualified class prefix — match on "aud" following the class name
             r"JwtClaimValidator[^(]{0,100}\(\s*[\x22\x27]aud[\x22\x27]",
             re.I),
         "LOW", [], [], kind="hardening",
         note="JWT audience (aud) claim validation is enforced, preventing token replay "
              "from one service to another sharing the same signing key.",
         fix=""),
    Rule("HARDEN-JWT-CLOCK-SKEW", "JWT clock skew tolerance explicitly bounded",
         re.compile(
             # Covers both short form (Duration.ofMinutes) and FQN (java.time.Duration.ofMinutes)
             r"JwtTimestampValidator\s*\([^)]{0,80}Duration\s*\.\s*of(?:Minutes|Seconds)\s*\(",
             re.I),
         "LOW", [], [], kind="hardening",
         note="An explicit clock skew tolerance is configured on the JWT timestamp validator, "
              "bounding the window in which expired tokens remain accepted.",
         fix=""),
    Rule("HARDEN-OAUTH2-PKCE-ENABLED", "OAuth2 PKCE (code_challenge) explicitly enabled",
         re.compile(
             r"PkceParameterNames|code_challenge|"
             r"\.requireProofKey\s*\(\s*true\s*\)|"
             r"OAuth2AuthorizationRequest[^;\n]{0,120}codeChallenge",
             re.I),
         "LOW", [], [], kind="hardening",
         note="PKCE (Proof Key for Code Exchange) is explicitly enabled, "
              "protecting the authorization code grant from interception.",
         fix=""),
    Rule("HARDEN-OAUTH2-STATE-PARAM", "OAuth2 state parameter generated per request",
         re.compile(
             r"\.state\s*\([^)]{0,120}(?:UUID|random|SecureRandom|nonce|csrf)",
             re.I),
         "LOW", [], [], kind="hardening",
         note="A cryptographically random state parameter is generated per OAuth2 request, "
              "protecting the callback from CSRF.",
         fix=""),
    Rule("HARDEN-CRYPTO-GCM-RANDOM-IV", "AES-GCM IV generated with SecureRandom",
         # Positive counterpart of SRC-CRYPTO-STATIC-IV: SecureRandom.nextBytes(iv)
         # followed by GCMParameterSpec confirms the IV is freshly randomised.
         re.compile(
             r"(?:new\s+SecureRandom\s*\(\s*\)|SecureRandom\s*\.\s*getInstanceStrong\s*\(\s*\))[^;\n]{0,200}?\.nextBytes\s*\(|"
             r"SecureRandom[^;\n]{0,120}\.nextBytes\s*\([^)]{0,60}\)"
             r"[^;\n]{0,200}?GCMParameterSpec",
             re.I | re.S),
         "LOW", [], [], kind="hardening",
         note="The GCM IV is generated with SecureRandom.nextBytes(), ensuring a "
              "unique, unpredictable nonce for every encryption operation.",
         fix=""),
    Rule("HARDEN-RSA-OAEP", "RSA encryption uses OAEP padding",
         re.compile(
             r'Cipher\s*\.\s*getInstance\s*\(\s*[\x22\x27]'
             r'RSA/ECB/OAEPWith',
             re.I),
         "LOW", [], [], kind="hardening",
         note="RSA encryption uses OAEP padding (OAEPWithSHA-*/MGF1), "
              "providing semantic security and resistance to padding oracle attacks.",
         fix=""),
]
RULES.extend(HARDENING_RULES)
RULE_BY_ID.update({r.rid: r for r in HARDENING_RULES})

# --- 4) extra config rules (properties/YAML) ------------------------------
# Same format as PROP_RULES:  (rule_id, pattern, severity, note, fix)
MERGE_PROP_RULES: List[Tuple[str, "re.Pattern", str, str, str]] = [
    ("SpringSecurityCheck-PROP-DDL-AUTO",
     re.compile(r"spring\.jpa\.hibernate\.ddl-auto\s*[=:]\s*(?:create|create-drop)\b", re.I),
     "HIGH",
     "The database schema is recreated/dropped automatically (data loss, unexpected migrations).",
     "Use 'validate' in production, or controlled migrations (Flyway/Liquibase)."),
    ("SpringSecurityCheck-PROP-SHOW-SQL",
     re.compile(r"spring\.jpa\.show-sql\s*[=:]\s*true\b", re.I),
     "LOW",
     "SQL output enabled - can write sensitive data into logs.",
     "Disable in production profiles."),
    ("SpringSecurityCheck-PROP-COOKIE-HTTPONLY",
     re.compile(r"server\.servlet\.session\.cookie\.http-only\s*[=:]\s*false\b", re.I),
     "MEDIUM",
     "Session cookie without HttpOnly - readable via JavaScript (XSS theft).",
     "Set server.servlet.session.cookie.http-only=true."),
    ("SpringSecurityCheck-PROP-COOKIE-SECURE",
     re.compile(r"server\.servlet\.session\.cookie\.secure\s*[=:]\s*false\b", re.I),
     "MEDIUM",
     "Session cookie without the Secure flag - also transmitted over HTTP.",
     "Set server.servlet.session.cookie.secure=true."),
    # sprig SPR-CONFIG-001: detect sensitive Actuator endpoints even WITHOUT '*'.
    # (SpringSecurityCheck-PROP-ACTUATOR-ALL only catches the wildcard case.) The YAML branch is
    # deliberately limited to actuator-unique tokens to avoid false positives on
    # an unrelated 'include:' key.
    ("SpringSecurityCheck-PROP-ACTUATOR-SENSITIVE",
     re.compile(r"exposure\.include\s*[=:].*\b(?:env|heapdump|threaddump|shutdown|beans|"
                r"configprops|loggers|mappings|httptrace|httpexchanges)\b|"
                r"^\s*include\s*:\s*.*\b(?:heapdump|threaddump|shutdown|configprops|"
                r"httptrace|httpexchanges)\b", re.I),
     "HIGH",
     "Sensitive Actuator endpoint exposed explicitly (env/heapdump/threaddump/shutdown/...).",
     "Include only non-sensitive endpoints (health, info); remove or authenticate sensitive ones."),
]

# --- register rules --------------------------------------------------------
RULES.extend(MERGE_SRC_RULES)
PROP_RULES.extend(MERGE_PROP_RULES)
RULE_BY_ID.update({r.rid: r for r in MERGE_SRC_RULES})


# --- 3) build supply-chain hygiene for build files ------------------------
# jspringguard.py so far only checks build files for vulnerable dependency
# versions (DEP_RULES). These rules add hygiene aspects that are version-
# independent.
#  (rule_id, pattern, severity, status, note, fix)
BUILD_HYGIENE_RULES: List[Tuple[str, "re.Pattern", str, str, str, str]] = [
    ("BUILD-HTTP-REPO",
     re.compile(r"<url>\s*http://(?!localhost|127\.0\.0\.1)|"
                r"\burl\s*(?:=|\()?\s*[\"']?http://(?!localhost|127\.0\.0\.1)|"
                r"maven\s*\(\s*[\"']http://(?!localhost|127\.0\.0\.1)", re.I),
     "HIGH", "ANTIPATTERN",
     "Build/wrapper uses an unencrypted HTTP repository (MITM/artifact tampering).",
     "Use HTTPS and a trusted repository host."),
    ("BUILD-INSECURE-PROTOCOL",
     re.compile(r"allowInsecureProtocol\s*=\s*true", re.I),
     "HIGH", "ANTIPATTERN",
     "Gradle explicitly allows an insecure repository protocol.",
     "Remove allowInsecureProtocol and switch the repository to HTTPS."),
    ("BUILD-MAVENLOCAL",
     re.compile(r"\bmavenLocal\s*\(\s*\)"),
     "MEDIUM", "REVIEW",
     "mavenLocal() can pull in tampered/non-reproducible artifacts in CI.",
     "In reproducible CI builds, use only controlled remote repositories."),
    ("BUILD-JCENTER",
     re.compile(r"\bjcenter\s*\(\s*\)"),
     "MEDIUM", "ANTIPATTERN",
     "The deprecated JCenter repository is used.",
     "Migrate to Maven Central or a controlled internal repository."),
    ("BUILD-DYNAMIC-VERSION",
     re.compile(r"[\"'][\w.\-]+:[\w.\-]+:(?:\+|[^\"']*\.\+|latest\.(?:release|integration))[\"']|"
                r"<version>\s*(?:LATEST|RELEASE)\s*</version>", re.I),
     "HIGH", "ANTIPATTERN",
     "Dynamic dependency/plugin version - not reproducible, supply-chain risk.",
     "Pin a concrete, vetted version."),
    ("BUILD-SNAPSHOT-VERSION",
     re.compile(r"[\"'][\w.\-]+:[\w.\-]+:[^\"']*-SNAPSHOT[\"']|<version>\s*[^<]*-SNAPSHOT\s*</version>"),
     "MEDIUM", "ANTIPATTERN",
     "SNAPSHOT version found - mutable, undesirable in production.",
     "Use only immutable release versions in production."),
    ("BUILD-WRAPPER-HTTP",
     re.compile(r"distributionUrl\s*=\s*http://", re.I),
     "HIGH", "ANTIPATTERN",
     "The Gradle wrapper downloads its distribution over HTTP.",
     "Use an HTTPS URL from a trusted host."),
]


def analyze_boot_combinations(path: str, root: str, source_text: str = "") -> List[Finding]:
    """Direct Maven dependencies only; absence is REVIEW, never proof of exposure.

    Independently implemented from the Spring advisory, inspired by BootShield's
    dependency-combination checks. No project code or Maven plugins are executed.
    """
    if os.path.basename(path) != "pom.xml":
        return []
    from xml.parsers import expat
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []
    parser = expat.ParserCreate(namespace_separator="}")
    stack: List[str] = []
    deps: List[dict] = []
    current: dict = {}
    def start(name, attrs):
        nonlocal current
        stack.append(name.split("}")[-1])
        if stack == ["project", "dependencies", "dependency"]:
            current = {"line": parser.CurrentLineNumber}
        if len(stack) == 4 and stack[:3] == ["project", "dependencies", "dependency"]:
            current[stack[-1]] = ""
            if stack[-1] == "artifactId":
                current["line"] = parser.CurrentLineNumber
    def chars(data):
        if len(stack) == 4 and stack[:3] == ["project", "dependencies", "dependency"]:
            current[stack[-1]] = current.get(stack[-1], "") + data
    def end(name):
        if stack == ["project", "dependencies", "dependency"]:
            deps.append({k: v.strip() if isinstance(v, str) else v for k, v in current.items()})
        stack.pop()
    def reject_doctype(*args):
        raise ValueError("DTD not supported")
    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = reject_doctype
    try:
        parser.Parse(content, True)
    except (expat.ExpatError, ValueError):
        return []
    deps = [d for d in deps if d.get("scope", "compile") != "test"]
    boot = {d.get("artifactId"): d for d in deps if d.get("groupId") == "org.springframework.boot"}
    security = ("spring-boot-starter-security" in boot or any(
        d.get("groupId") == "org.springframework.security" and
        d.get("artifactId") in {"spring-security-web", "spring-security-config"} for d in deps))
    rel = os.path.relpath(path, root) if root else path
    lines = content.splitlines()
    findings: List[Finding] = []
    def add(rid, dep, severity, note, fix):
        line = dep["line"]
        code = lines[line - 1].strip()
        if SUPPRESS_MARKER.search(lines[line - 1]):
            return
        findings.append(Finding(file=rel, line=line, rule_id=rid, rule_name=rid,
            severity=severity, status="REVIEW", code=code, note=note, fix=fix,
            fingerprint=fingerprint(rel, rid, code), context=context_lines(lines, line)))
    actuator = boot.get("spring-boot-actuator-autoconfigure")
    if actuator and "spring-boot-health" not in boot:
        props, managed = maven_resolution_context(path, content)
        version = actuator.get("version") or managed.get("org.springframework.boot:spring-boot-actuator-autoconfigure", "")
        for _ in range(8):
            resolved = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group()), version)
            if resolved == version:
                break
            version = resolved
        exact = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:\.RELEASE)?", version)
        affected = bool(exact and (4, 0, 0) <= tuple(map(int, exact.groups())) <= (4, 0, 5))
        if affected or not exact:
            add("BOOT-ACTUATOR-WITHOUT-HEALTH", actuator, "HIGH" if affected else "MEDIUM",
                "Potential CVE-2026-40976 dependency combination; version: " + (version or "unresolved") +
                ". Affected: 4.0.0-4.0.5. Requires a servlet application relying on the default security chain "
                "and no spring-boot-health at runtime. Transitive dependencies, active profiles and custom "
                "security configuration are not resolved; verify all prerequisites. "
                "https://spring.io/security/cve-2026-40976/",
                "For affected versions upgrade Spring Boot to 4.0.6 or later; inspect the effective dependency tree and SecurityFilterChain.")
    devtools = boot.get("spring-boot-devtools")
    if devtools:
        add("BOOT-DEVTOOLS-PRESENT", devtools, "LOW" if devtools.get("optional") == "true" else "MEDIUM",
            "DevTools is directly declared. This does not prove production inclusion or remote restart exposure; "
            "optional only controls downstream dependency propagation.",
            "Verify DevTools is excluded from the production archive and remote restart is disabled.")
    actuator = actuator or boot.get("spring-boot-starter-actuator")
    if actuator and not security:
        add("BOOT-ACTUATOR-WITHOUT-SECURITY", actuator, "MEDIUM",
            "Actuator declared without a direct Spring Security web/config dependency. Authentication may be "
            "provided transitively or externally; endpoint exposure is not established by this POM.",
            "Inspect effective runtime dependencies, authenticate management endpoints and limit exposure.")
    data_rest = next((d for d in deps if
        (d.get("groupId") == "org.springframework.data" and d.get("artifactId") in
         {"spring-data-rest-core", "spring-data-rest-webmvc"}) or
        (d.get("groupId") == "org.springframework.boot" and d.get("artifactId") == "spring-boot-starter-data-rest")), None)
    if data_rest and not security:
        clean_source = _structure_mask(strip_comments(source_text))
        exported_repository = bool(
            re.search(r"@RepositoryRestResource\b(?!\s*\([^)]*\bexported\s*=\s*false)",
                      clean_source, re.I)
            or re.search(r"\b(?:extends|:)\s*(?:[\w.]+\.)?"
                         r"(?:CrudRepository|JpaRepository|PagingAndSortingRepository|"
                         r"Repository)\s*<", clean_source))
        add("COMBO-DATA-REST-WITHOUT-SECURITY", data_rest,
            "HIGH" if exported_repository else "MEDIUM",
            "Spring Data REST dependency without direct Spring Security web/config dependency. "
            "Repositories may expose CRUD endpoints automatically. Verify exported repositories, "
            "effective runtime dependencies, gateway restrictions and application authorization. "
            + ("Export-capable Spring Data repository found in module source." if exported_repository else
               "No export-capable repository was recognized; export and runtime accessibility are not proven."),
            "Restrict repository export and apply authorization to Data REST endpoints; verify the effective security chain.")
    web = next((boot[k] for k in ("spring-boot-starter-web", "spring-boot-starter-webmvc", "spring-boot-starter-webflux") if k in boot), None)
    if web and not security and not actuator and not data_rest and re.search(r"@(?:RestController|EnableWebSecurity)\b", _structure_mask(strip_comments(source_text))):
        add("BOOT-WEB-WITHOUT-SECURITY", web, "MEDIUM",
            "Web starter plus @RestController/@EnableWebSecurity in module source, without direct Spring Security dependency. This is a review hint; public endpoints "
            "or other authentication mechanisms may be intentional.",
            "Verify the application's authentication and authorization design and effective dependency tree.")
    return findings


def analyze_build_hygiene(path: str, root: str) -> List["Finding"]:
    """Checks a build file line by line for supply-chain hygiene (version-independent)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    rel = os.path.relpath(path, root) if root else path
    out: List[Finding] = []
    for idx, raw in enumerate(lines, start=1):
        if SUPPRESS_MARKER.search(raw):
            continue
        for rid, pat, severity, status, note, fix in BUILD_HYGIENE_RULES:
            if pat.search(raw):
                snippet = raw.strip()[:200]
                out.append(Finding(
                    file=rel, line=idx, rule_id=rid, rule_name=rid,
                    severity=severity, status=status, code=snippet,
                    note=note, fix=fix, fingerprint=fingerprint(rel, rid, snippet),
                    context=context_lines([l.rstrip("\n") for l in lines], idx),
                ))
    return out


# --- 5) CodeQL detection techniques, in pure Python -----------------------
# No CodeQL CLI/DB is used. The detection logic of the Spring CodeQL queries
# runs natively in Python. Mapping (CodeQL query -> Python rule):
#
#   java/spring/csrf-disabled               -> SpringSecurityCheck-CSRF-DISABLED          (existing)
#   java/spring/permit-all-any-request      -> SpringSecurityCheck-ANY-REQUEST-PERMIT     (existing)
#   java/spring/plaintext-password-encoder  -> SpringSecurityCheck-NOOP-ENCODER           (existing)
#   java/spring/crossorigin-permissive      -> SpringSecurityCheck-CORS-WILDCARD /
#                                              SpringSecurityCheck-CROSS-ORIGIN-BROAD /
#                                              SRC-CROSSORIGIN-BARE       (existing + merge)
#   java/spring/frameoptions-disabled       -> SpringSecurityCheck-HEADERS-DISABLED (existing)
#   java/spring/actuator-permit-all         -> SpringSecurityCheck-PERMIT-ALL-BROAD  (existing)
#   java/spring/missing-method-security     -> SpringSecurityCheck-NO-METHOD-SECURITY     (existing)
#   java/spring/spel-injection-from-request -> SRC-SPEL-REQUEST          (NEW, below)
#
# Only the single taint query is new: it correlates a SOURCE
# (@RequestParam/@PathVariable/@RequestBody/@RequestHeader) with the SINK
# parseExpression(...) WITHIN THE SAME METHOD. That is the CodeQL "source ->
# sink" technique, here method-scoped (rather than full data flow) in Python.

_REQ_SOURCE_ANNOT_RE = re.compile(r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader)\b")
_SPEL_SINK_DYN_RE = re.compile(r"parseExpression\s*\(\s*(?![\"'])")
_METHOD_SIG_RE = re.compile(
    r"\b[A-Za-z_$][\w$<>\[\].,\s]*\s+[A-Za-z_$][\w$]*\s*\([^;{]*\)\s*(?:throws[^{;]*)?\{")


def _method_body_end(text: str, brace_pos: int) -> int:
    """Index of the closing brace matching the '{' at brace_pos (or end of text)."""
    depth = 0
    for i in range(brace_pos, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def analyze_spel_from_request(rel: str, text: str, context_radius: int = CONTEXT_RADIUS) -> List["Finding"]:
    """CodeQL technique java/spring/spel-injection-from-request in Python:
    a request-bound method parameter + a dynamic parseExpression() in the same
    method."""
    out: List[Finding] = []
    source_lines = text.splitlines()
    for m in _METHOD_SIG_RE.finditer(text):
        brace = m.end() - 1  # position of '{'
        if brace < 0 or brace >= len(text) or text[brace] != "{":
            continue
        end = _method_body_end(text, brace)
        header = text[m.start():brace]          # signature incl. parameter list
        body = text[brace:end + 1]
        sink = _SPEL_SINK_DYN_RE.search(body)
        if _REQ_SOURCE_ANNOT_RE.search(header) and sink:
            pos = brace + sink.start()
            line = text.count("\n", 0, pos) + 1
            snippet = (text[pos:pos + 100].splitlines() or [""])[0].strip()
            out.append(Finding(
                file=rel, line=line, rule_id="SRC-SPEL-REQUEST",
                rule_name="SpEL injection from request input",
                severity="CRITICAL", status="TAINT", code=snippet,
                note="A request parameter (@RequestParam/@PathVariable/@RequestBody/@RequestHeader) "
                     "flows into parseExpression() of the same method - SpEL injection/RCE.",
                fix="Do not parse user-influenced strings as SpEL; use SimpleEvaluationContext "
                    "or fixed expressions.",
                fingerprint=fingerprint(rel, "SRC-SPEL-REQUEST", snippet),
                context=context_lines(source_lines, line, context_radius)))
    return out


# Same file-wide-scope reasoning as SRC-SPEL-REQUEST above: a per-line Rule
# cannot see a variable declared on one line (e.g. "DirContext ctx") and used
# on a later line ("ctx.search(...)"), so LDAP injection is detected the same
# way - across the whole file text, not line by line.
_LDAP_TYPE_RE = re.compile(r"\b(?:DirContext|LdapTemplate)\b")
_LDAP_SEARCH_CONCAT_RE = re.compile(r"\.search\s*\([^;]{0,200}[\"']\s*\+")


def analyze_ldap_injection(rel: str, text: str, context_radius: int = CONTEXT_RADIUS) -> List["Finding"]:
    """Flags an LDAP search filter built via string concatenation, where a
    DirContext/LdapTemplate type is mentioned earlier in the same file
    (heuristic, file-scoped rather than true data flow)."""
    out: List[Finding] = []
    source_lines = text.splitlines()
    for m in _LDAP_SEARCH_CONCAT_RE.finditer(text):
        window = text[max(0, m.start() - 300):m.start()]
        if not _LDAP_TYPE_RE.search(window):
            continue
        line = text.count("\n", 0, m.start()) + 1
        snippet = (text[m.start():m.start() + 100].splitlines() or [""])[0].strip()
        out.append(Finding(
            file=rel, line=line, rule_id="SRC-LDAP-INJECTION",
            rule_name="Possible LDAP injection (filter built by concatenation)",
            severity="HIGH", status="TAINT", code=snippet,
            note="An LDAP search filter is assembled via string concatenation - externally "
                 "influenced input can inject filter syntax (LDAP injection, auth bypass).",
            fix="Escape special LDAP filter characters (e.g. via "
                "org.springframework.ldap.support.LdapEncoder) or use parameterized filters.",
            fingerprint=fingerprint(rel, "SRC-LDAP-INJECTION", snippet),
                context=context_lines(source_lines, line, context_radius)))
    return out


# Log-injection / Log4Shell-class attack point: a method parameter (any
# parameter, annotated or not - Spring MVC implicitly binds simple-typed
# parameters to request params even without @RequestParam) flows directly,
# bare, into a logger call in the SAME method. This is the actual code-level
# trigger point for Log4Shell-class bugs (the vulnerable *library* is already
# caught by DEP-LOG4J-CORE/OSV; this rule finds the reachable sink even when
# the library itself happens to be patched, or for other loggers).
_METHOD_PARAM_RE = re.compile(
    r"(?:\(|,)\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*"
    r"[\w$][\w$.<>\[\],\s]*?\s+([A-Za-z_$][\w$]*)\s*(?=,|\))")
_LOG_CALL_BARE_ARG_RE = re.compile(
    r"\b(?:logger|log|LOGGER|LOG)\s*\.\s*(?:trace|debug|info|warn|error|fatal)"
    r"\s*\(\s*([A-Za-z_$][\w$]*)\s*\)")


def analyze_log_injection(rel: str, text: str, context_radius: int = CONTEXT_RADIUS) -> List["Finding"]:
    """Flags a logger call whose sole, bare argument is a method parameter -
    the parameter reaches the log sink unmodified and unformatted, which is
    exactly the Log4Shell attack shape (and log-forging in general)."""
    out: List[Finding] = []
    source_lines = text.splitlines()
    for m in _METHOD_SIG_RE.finditer(text):
        brace = m.end() - 1
        if brace < 0 or brace >= len(text) or text[brace] != "{":
            continue
        end = _method_body_end(text, brace)
        header = text[m.start():brace]
        body = text[brace:end + 1]
        params = set(_METHOD_PARAM_RE.findall(header))
        if not params:
            continue
        for lm in _LOG_CALL_BARE_ARG_RE.finditer(body):
            if lm.group(1) not in params:
                continue
            pos = brace + lm.start()
            line = text.count("\n", 0, pos) + 1
            snippet = (text[pos:pos + 100].splitlines() or [""])[0].strip()
            out.append(Finding(
                file=rel, line=line, rule_id="SRC-LOG-INJECTION",
                rule_name="Unsanitized request input logged directly (Log4Shell-class sink)",
                severity="HIGH", status="TAINT", code=snippet,
                note=f"Method parameter `{lm.group(1)}` is passed bare into a logger call "
                     "in the same method - this is the exact code-level trigger shape for "
                     "Log4Shell-class bugs (a vulnerable logging library evaluates "
                     "attacker-controlled lookup syntax in the logged string) and enables "
                     "log forging/injection regardless of the logging library's own patch "
                     "status.",
                fix="Never log raw, unvalidated request input directly; use a parameterized "
                    "logging call (e.g. logger.info(\"token={}\", sanitize(token))) and/or strip "
                    "control characters and lookup-like syntax (${...}) before logging.",
                fingerprint=fingerprint(rel, "SRC-LOG-INJECTION", snippet),
                context=context_lines(source_lines, line, context_radius)))
    return out


# Same reasoning again: the single most common real-world SQL-injection shape
# builds the query string via concatenation on one line and executes a bare
# variable on a LATER line -
#     String sql = "select * from users where username = '" + username + "'";
#     ResultSet rs = statement.executeQuery(sql);
# SRC-SQLI-CONCAT (a per-line Rule) only sees the second line, whose argument
# is just "sql" with no "+" in sight, so it never fires on this - the most
# common - shape. This is a real, confirmed gap (found scanning JoyChou93/
# java-sec-code's SQLI.java): the demo's main SQLi example was invisible to
# the per-line rule. Fixed the same way as SRC-SPEL-REQUEST/LDAP: correlate
# across lines within one method.
_SQL_VAR_ASSIGN_CONCAT_RE = re.compile(
    r"\b(?:String|StringBuilder|StringBuffer|var)\s+(\w+)\s*=\s*[^;]*[\"'][^\"']*[\"']\s*\+[^;]*;")
_SQL_EXEC_CALL_RE = re.compile(
    r"\b(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery|"
    r"prepareStatement|prepareCall)\s*\(\s*(\w+)\s*[,)]")


def analyze_sqli_var_concat(rel: str, text: str, context_radius: int = CONTEXT_RADIUS) -> List["Finding"]:
    """Flags String sql = "..." + var; ... executeQuery(sql) - a variable built
    via concatenation earlier in the SAME METHOD and later passed bare into a
    JDBC/JPA execute-style call. Method-scoped correlation, not full data flow;
    a PreparedStatement built from a literal-only string (no '+') is correctly
    not flagged, since the assignment step requires concatenation."""
    out: List[Finding] = []
    source_lines = text.splitlines()
    for m in _METHOD_SIG_RE.finditer(text):
        brace = m.end() - 1
        if brace < 0 or brace >= len(text) or text[brace] != "{":
            continue
        end = _method_body_end(text, brace)
        body = text[brace:end + 1]

        concat_vars = {am.group(1) for am in _SQL_VAR_ASSIGN_CONCAT_RE.finditer(body)}
        if not concat_vars:
            continue
        for em in _SQL_EXEC_CALL_RE.finditer(body):
            if em.group(1) not in concat_vars:
                continue
            pos = brace + em.start()
            line = text.count("\n", 0, pos) + 1
            snippet = (text[pos:pos + 100].splitlines() or [""])[0].strip()
            out.append(Finding(
                file=rel, line=line, rule_id="SRC-SQLI-VAR-CONCAT",
                rule_name="Possible SQL injection (query variable built by concatenation)",
                severity="CRITICAL", status="TAINT", code=snippet,
                note="The query variable passed here was assembled via string concatenation "
                     "earlier in this method - classic SQL injection, just split across lines "
                     "so a same-line pattern would miss it.",
                fix="Use a parameterized query (PreparedStatement with bind parameters via "
                    "setString/setInt/... or JPA/MyBatis query parameters) instead of "
                    "concatenating values into the SQL string.",
                fingerprint=fingerprint(rel, "SRC-SQLI-VAR-CONCAT", snippet),
                context=context_lines(source_lines, line, context_radius)))
    return out


# Found scanning JoyChou93/java-sec-code's Cors.java: reflecting the request's
# own Origin header back as the CORS allow-origin value is worse than a static
# wildcard (it bypasses "no '*' with credentials"), and none of the existing
# ==========================================================================
#  END MERGE BLOCK
# ==========================================================================


# Additional method-local web checks. Deliberately heuristic, not full taint analysis.
EXTRA_RULE_META = {
    "SRC-XSS-WRITER": ("MEDIUM", "Dynamic servlet writer output; inspect HTML escaping"),
    "SRC-XSS-RESPONSE-ENTITY": ("MEDIUM", "Dynamic String in ResponseEntity; inspect response content type and encoding"),
    "SRC-XSS-RESPONSE-BODY": ("MEDIUM", "Dynamic HTML response body without recognized output encoding"),
    "TPL-XSS-TH-UTEXT": ("MEDIUM", "Thymeleaf unescaped dynamic text"),
    "SRC-REQUEST-BODY-NO-VALID": ("MEDIUM", "Request-body DTO parameter without @Valid or @Validated"),
    "COMBO-DATA-REST-WITHOUT-SECURITY": ("MEDIUM", "Spring Data REST without direct Spring Security dependency (HIGH with repository evidence)"),
    "BOOT-WEB-WITHOUT-SECURITY": ("MEDIUM", "Web dependency plus controller/security annotation without direct Spring Security (review)"),
    "BOOT-ACTUATOR-WITHOUT-HEALTH": ("HIGH", "Potential affected Actuator/Health combination; unresolved versions MEDIUM"),
    "BOOT-ACTUATOR-WITHOUT-SECURITY": ("MEDIUM", "Actuator without direct Spring Security (review)"),
    "BOOT-DEVTOOLS-PRESENT": ("MEDIUM", "DevTools production packaging review; optional dependencies LOW"),
    "SRC-SPEL-REQUEST": ("CRITICAL", "Request input in SpEL expression parsing"),
    "SRC-LDAP-INJECTION": ("HIGH", "Concatenated LDAP search filter"),
    "SRC-LOG-INJECTION": ("HIGH", "Request input in log output"),
    "SRC-SQLI-VAR-CONCAT": ("CRITICAL", "Concatenated SQL variable passed to query"),
    "HARDEN-REQUEST-BODY-VALID": ("INFO", "Request-body DTO parameter validated with @Valid/@Validated"),
}


def rule_catalog() -> Dict[str, Tuple[str, str]]:
    catalog = {r.rid: (r.severity, r.name) for r in RULES}
    catalog.update({rid: (sev, note) for rid, _, sev, note, _ in PROP_RULES})
    catalog.update({"DEP-" + r.artifact.upper(): (r.severity, r.note) for r in DEP_RULES})
    catalog["DEP-UNRESOLVED"] = ("MEDIUM", "Dependency assessment incomplete: exact coordinates/version unresolved")
    catalog.update({rid: (sev, note) for rid, _, sev, _, note, _ in BUILD_HYGIENE_RULES})
    catalog.update(EXTRA_RULE_META)
    catalog["OSV-<advisory-id>"] = ("DYNAMIC", "One rule per returned OSV advisory; severity comes from advisory data")
    return catalog


def parse_rule_patterns(values: Optional[Sequence[str]]) -> List[str]:
    """Expand repeatable, comma-separated rule globs into one normalized list."""
    return [part.strip().upper() for value in (values or [])
            for part in value.split(",") if part.strip()]


def rule_selected(rule_id: str, includes: Sequence[str], excludes: Sequence[str]) -> bool:
    """Apply case-insensitive shell globs to a rule ID; exclusion wins."""
    normalized = rule_id.upper()
    included = not includes or any(fnmatch.fnmatchcase(normalized, pattern)
                                   for pattern in includes)
    excluded = any(fnmatch.fnmatchcase(normalized, pattern) for pattern in excludes)
    return included and not excluded


def rule_help_uri(rid: str) -> str:
    if rid.startswith("OSV-"):
        from urllib.parse import quote
        return "https://osv.dev/vulnerability/" + quote(rid[4:], safe="")
    if rid == "BOOT-ACTUATOR-WITHOUT-HEALTH":
        return "https://spring.io/security/cve-2026-40976/"
    if rid.startswith("DPOP-"):
        return "https://www.rfc-editor.org/rfc/rfc9449.html"
    if rid == "OAUTH2-ISSUER-MIXUP":
        return "https://www.rfc-editor.org/rfc/rfc9700.html"
    if rid in {"JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED", "JWT-KEY-ISSUER-NOT-BOUND",
               "JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES", "JWE-ZIP-ENABLED"}:
        return "https://www.rfc-editor.org/rfc/rfc8725.html"
    if rid == "SRC-REQUEST-BODY-NO-VALID":
        return "https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-validation.html"
    if rid == "TPL-XSS-TH-UTEXT":
        return "https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#unescaped-text"
    if "XSS" in rid:
        return "https://cwe.mitre.org/data/definitions/79.html"
    if "DATA-REST" in rid:
        return "https://docs.spring.io/spring-data/rest/reference/security.html"
    # Existing rule documentation lives with the standalone project.
    return REPO_URL


def finding_suppressed(raw_lines: Sequence[str], finding: Finding) -> bool:
    # Allow a suppression marker on the declaration's preceding line even
    # when the finding is a few lines into the method body.
    candidates = list(raw_lines[max(0, finding.line - 3):finding.line])
    stripped_lines = strip_comments("\n".join(raw_lines)).splitlines()
    method = enclosing_method(parse_methods(stripped_lines), finding.line)
    if method:
        candidates.extend(raw_lines[max(0, method.start - 4):method.start])
    for line in candidates:
        m = SUPPRESS_MARKER.search(line)
        if m and (not m.group(1) or finding.rule_id.upper() in
                  {rid.strip().upper() for rid in m.group(1).split(",")}):
            return True
    return False


def _structure_mask(text: str) -> str:
    # Keep offsets/newlines stable while hiding delimiters in string literals.
    return re.sub(r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: re.sub(r"[^\n]", " ", m.group()), text)


def _closing(text: str, pos: int, left: str = "(", right: str = ")") -> int:
    depth = 0
    for i in range(pos, len(text)):
        if text[i] == left:
            depth += 1
        elif text[i] == right:
            depth -= 1
            if depth == 0:
                return i
    return -1


_WEB_METHOD_TAIL = re.compile(
    r"\s*(?:throws\s+[\w.,\s]+)?(?:\s*:\s*[\w<>?.]+)?\s*\{")


def _web_methods(text: str):
    masked = _structure_mask(text)
    for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(", masked):
        if m.group(1) in {"if", "for", "while", "switch", "catch", "synchronized"}:
            continue
        opening = masked.index("(", m.start())
        closing = _closing(masked, opening)
        if closing < 0:
            continue
        tail = _WEB_METHOD_TAIL.match(masked, closing + 1)
        if not tail:
            continue
        begin = tail.end() - 1
        finish = _closing(masked, begin, "{", "}")
        if finish < 0:
            continue
        header_start = max(masked.rfind(";", 0, m.start()), masked.rfind("}", 0, m.start()),
                           masked.rfind("{", 0, m.start())) + 1
        header = text[header_start:opening]
        if "@" == text[max(0, m.start()-1):m.start()] or not re.search(r"\b(?:[\w<>?\[\]]+\s+|fun\s+)" + re.escape(m.group(1)) + r"\s*$", header):
            continue
        yield header_start, opening, closing, begin, finish


def _parameter_parts(text: str):
    mask = _structure_mask(text)
    start = 0
    depth = 0
    for i, char in enumerate(mask):
        if char in "(<[{":
            depth += 1
        elif char in ")>]}":
            depth -= 1
        elif char == "," and depth == 0:
            yield start, text[start:i]
            start = i + 1
    yield start, text[start:]


@dataclass
class FlowStatement:
    text: str
    offset: int
    target: Optional[str]
    expression: str


@dataclass
class FlowMethodAst:
    start: int
    body_start: int
    body_end: int
    sources: Dict[str, List[str]]
    statements: List[FlowStatement]


def _flow_statements(body: str) -> List[FlowStatement]:
    """Build assignment/call statement nodes while respecting nested calls."""
    masked = _structure_mask(body)
    starts = [0]
    paren = bracket = 0
    for index, char in enumerate(masked):
        if char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == ";" and paren == 0 and bracket == 0:
            starts.append(index + 1)
    nodes: List[FlowStatement] = []
    for begin, end in zip(starts, starts[1:] + [len(body)]):
        raw = body[begin:end]
        if not raw.strip():
            continue
        assignment = re.search(r"(?<![=!<>])=(?!=)", _structure_mask(raw))
        target: Optional[str] = None
        expression = ""
        if assignment:
            left = raw[:assignment.start()]
            names = re.findall(r"[A-Za-z_$][\w$]*", left)
            if names:
                target = names[-1]
                expression = raw[assignment.end():].rstrip("; ")
        nodes.append(FlowStatement(raw, begin, target, expression))
    return nodes


def build_flow_ast(text: str, method_bounds=None) -> List[FlowMethodAst]:
    """Create a compact method AST for parameters, assignments and calls.

    This is a dependency-free Java/Kotlin subset rather than a compiler AST.
    It preserves method and statement boundaries and is used only for
    conservative intraprocedural data flow; unsupported syntax stays with the
    established heuristic analyzers.
    """
    methods: List[FlowMethodAst] = []
    for start, opening, closing, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        params = text[opening + 1:closing]
        sources: Dict[str, List[str]] = {}
        for _, param in _parameter_parts(params):
            annotation = re.search(
                r"@(?:[\w]+\.)*(RequestParam|PathVariable|RequestBody|RequestHeader)\b",
                param)
            if not annotation:
                continue
            without_annotations = re.sub(
                r"@(?:[\w]+\.)*\w+(?:\s*\([^)]*\))?", "", param).strip()
            variable = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\[\])?\s*$",
                                 without_annotations)
            if variable:
                sources[variable.group(1)] = ["@" + annotation.group(1), variable.group(1)]
        body = text[body_start + 1:body_end]
        methods.append(FlowMethodAst(start, body_start, body_end, sources,
                                     _flow_statements(body)))
    return methods


def _flow_sanitizers(expression: str, inherited: Sequence[Set[str]]) -> Set[str]:
    direct: Set[str] = set()
    stripped = expression.strip()
    if _encoded_expression(stripped, ""):
        direct.add("html")
    ldap = re.match(r"(?:LdapEncoder\.(?:filterEncode|nameEncode)|encodeFilter)\s*\(", stripped)
    if ldap and _closing(_structure_mask(stripped), ldap.end() - 1) == len(stripped) - 1:
        direct.add("ldap")
    if re.search(r"replace(?:All)?\s*\([^)]*(?:\\r|\\n|\\p\{Cntrl\})", expression):
        direct.add("log")
    if not inherited:
        return direct
    common = set.intersection(*(set(value) for value in inherited))
    return direct | common


def analyze_structured_dataflow(rel: str, text: str, context_radius: int = CONTEXT_RADIUS, method_bounds=None) -> List[Finding]:
    """Propagate request taint through assignment AST nodes to security sinks."""
    out: List[Finding] = []
    lines = text.splitlines()
    identifier = re.compile(r"\b[A-Za-z_$][\w$]*\b")
    source_call = re.compile(r"\b(getParameter|getHeader|getQueryString|getReader|readLine)\s*\(")
    for method in build_flow_ast(text, method_bounds):
        paths = dict(method.sources)
        sanitizers: Dict[str, Set[str]] = {name: set() for name in paths}
        body_offset = method.body_start + 1
        for statement in method.statements:
            expr = statement.expression
            expr_ids = [name for name in identifier.findall(expr) if name in paths]
            call_source = source_call.search(expr)
            if statement.target and (expr_ids or call_source):
                inherited = [sanitizers.get(name, set()) for name in expr_ids]
                new_path = ((paths[expr_ids[0]] if expr_ids else
                             [call_source.group(1) + "()"])
                            + [statement.target])
                if statement.target in paths:
                    # Multiple possible assignments are merged conservatively:
                    # a sanitizer survives only if every path has it.
                    sanitizers[statement.target] &= _flow_sanitizers(expr, inherited)
                else:
                    sanitizers[statement.target] = _flow_sanitizers(expr, inherited)
                paths[statement.target] = new_path
            masked = _structure_mask(statement.text)
            for call in re.finditer(r"\b((?:[A-Za-z_$][\w$]*\s*\.\s*)*"
                                    r"[A-Za-z_$][\w$]*)\s*\(", masked):
                opening = call.end() - 1
                closing = _closing(masked, opening)
                if closing < 0:
                    continue
                callee = re.sub(r"\s+", "", call.group(1))
                leaf = callee.rsplit(".", 1)[-1]
                argument = statement.text[opening + 1:closing]
                arg_ids = [name for name in identifier.findall(argument) if name in paths]
                direct_source = source_call.search(argument)
                if not arg_ids and not direct_source:
                    continue
                source_path = (paths[arg_ids[0]] if arg_ids else
                               [direct_source.group(1) + "()"])
                sink: Optional[Tuple[str, str, str]] = None
                if leaf == "parseExpression":
                    sink = ("SRC-SPEL-REQUEST", "CRITICAL", "spel")
                elif leaf in {"executeQuery", "executeUpdate", "execute", "createQuery",
                              "createNativeQuery", "prepareStatement", "prepareCall"}:
                    sink = ("SRC-SQLI-VAR-CONCAT", "CRITICAL", "sql")
                elif leaf == "search" and re.search(r"DirContext|LdapTemplate|\bldap\w*\s*\.",
                                                    text[method.start:method.body_end], re.I):
                    sink = ("SRC-LDAP-INJECTION", "HIGH", "ldap")
                elif leaf in {"trace", "debug", "info", "warn", "error", "fatal"} and re.search(
                        r"(?:^|\.)(?:logger|log|LOGGER|LOG)\.", callee):
                    sink = ("SRC-LOG-INJECTION", "HIGH", "log")
                elif leaf in {"write", "print", "println"} and "getWriter" in statement.text[:call.start()]:
                    sink = ("SRC-XSS-WRITER", "HIGH", "html")
                elif leaf in {"ok", "body"} and "ResponseEntity" in statement.text[:call.start()]:
                    sink = ("SRC-XSS-RESPONSE-ENTITY", "MEDIUM", "html")
                if not sink:
                    continue
                rid, severity, sanitizer_kind = sink
                if arg_ids and all(sanitizer_kind in sanitizers.get(name, set()) for name in arg_ids):
                    continue
                position = body_offset + statement.offset + call.start()
                line = text.count("\n", 0, position) + 1
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else statement.text.strip()[:200]
                flow = source_path + [callee + "()"]
                out.append(Finding(
                    file=rel, line=line, rule_id=rid,
                    rule_name=EXTRA_RULE_META.get(rid, (severity, rid))[1],
                    severity=severity, status="TAINT", code=code,
                    note="Structured intraprocedural data flow: " + " -> ".join(flow) +
                         ". Verify framework semantics and sanitizer suitability.",
                    fix=("Do not pass request-controlled data to this sink; use parameterization "
                         "or the context-appropriate encoder."),
                    flow=flow, fingerprint=fingerprint(rel, rid, code),
                    context=context_lines(lines, line, context_radius)))
    return out


_JOSE_URL_SOURCES = {
    "JWT-JKU-INJECTION": re.compile(
        r"(?:getHeader|getClaim)\s*\(\s*[\x22\x27]jku[\x22\x27]\s*\)|"
        r"(?:jwt|token|header|headers|jwsHeader|signedJWT)[^;\n]{0,100}"
        r"\.get\s*\(\s*[\x22\x27]jku[\x22\x27]\s*\)|"
        r"\.getJWKURL\s*\(\s*\)|\.getJwkUrl\s*\(\s*\)", re.I),
    "JWT-X5U-INJECTION": re.compile(
        r"(?:getHeader|getClaim)\s*\(\s*[\x22\x27]x5u[\x22\x27]\s*\)|"
        r"(?:jwt|token|header|headers|jwsHeader|signedJWT)[^;\n]{0,100}"
        r"\.get\s*\(\s*[\x22\x27]x5u[\x22\x27]\s*\)|"
        r"\.getX509CertURL\s*\(\s*\)|\.getX5u\s*\(\s*\)", re.I),
}

_JOSE_REMOTE_SINK = re.compile(
    r"JWKSet\s*\.\s*load\s*\(|new\s+RemoteJWKSet\s*[<(]|"
    r"\.(?:withJwkSetUri|jwkSetUri|setJwkSetUri)\s*\(|"
    r"new\s+URL\s*\(|URI\s*\.\s*create\s*\(|"
    r"\.(?:openConnection|openStream|retrieveResource)\s*\(|"
    r"(?:restTemplate|webClient|httpClient)\s*\.\s*"
    r"(?:getForObject|getForEntity|exchange|get|send)\s*\(|"
    r"(?:generateCertificate|X509CertChainUtils\s*\.\s*parse)\s*\(", re.I)


def analyze_jose_header_url_injection(rel: str, text: str,
                                      context_radius: int = CONTEXT_RADIUS,
                                      method_bounds=None,
                                      enabled: Optional[Set[str]] = None) -> List[Finding]:
    """Track JOSE jku/x5u header URLs into remote key/certificate loaders.

    The analysis is intentionally intraprocedural.  A header URL is tainted at
    extraction, propagated through simple assignments, and reported only when
    it reaches a network/JWKS/certificate-loading sink in the same method.
    """
    out: List[Finding] = []
    lines = text.splitlines()
    identifier = re.compile(r"\b[A-Za-z_$][\w$]*\b")
    allowed = set(_JOSE_URL_SOURCES) if enabled is None else set(enabled)
    for start, _, _, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        body = text[body_start + 1:body_end]
        tainted: Dict[str, Tuple[str, List[str]]] = {}
        body_offset = body_start + 1
        for statement in _flow_statements(body):
            expression = statement.expression or statement.text
            direct = [(rid, pattern.search(expression))
                      for rid, pattern in _JOSE_URL_SOURCES.items() if rid in allowed]
            direct = [(rid, match) for rid, match in direct if match]
            inherited = [(name, tainted[name]) for name in identifier.findall(expression)
                         if name in tainted]
            if statement.target:
                if direct:
                    rid = direct[0][0]
                    tainted[statement.target] = (rid, [rid.split("-")[1].lower(), statement.target])
                elif inherited:
                    _, (rid, path) = inherited[0]
                    tainted[statement.target] = (rid, path + [statement.target])

            sink = _JOSE_REMOTE_SINK.search(statement.text)
            if not sink:
                continue
            candidates: List[Tuple[str, List[str]]] = []
            for rid, _ in direct:
                candidates.append((rid, [rid.split("-")[1].lower()]))
            for name in identifier.findall(statement.text):
                if name in tainted:
                    rid, path = tainted[name]
                    candidates.append((rid, path))
            seen: Set[str] = set()
            for rid, path in candidates:
                if rid in seen or rid not in allowed:
                    continue
                seen.add(rid)
                position = body_offset + statement.offset + sink.start()
                line = text.count("\n", 0, position) + 1
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else statement.text.strip()[:200]
                header = "jku" if rid == "JWT-JKU-INJECTION" else "x5u"
                flow = path + [sink.group(0).strip()]
                out.append(Finding(
                    file=rel, line=line, rule_id=rid,
                    rule_name=RULE_BY_ID[rid].name,
                    severity="CRITICAL", status="TAINT", code=code,
                    note=f"Attacker-controlled JWT `{header}` header URL reaches a remote "
                         "key/certificate-loading sink: " + " -> ".join(flow) + ".",
                    fix=FIX_JOSE_REMOTE_KEYS, flow=flow,
                    fingerprint=fingerprint(rel, rid, code),
                    context=context_lines(lines, line, context_radius)))
    return out


_IDOR_ID_NAME = re.compile(r"(?:^|_)(?:id|userId|accountId|orderId|customerId|documentId)$", re.I)
_IDOR_REPOSITORY_SINK = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:Repository|Repo|Dao)|(?:repository|repo|dao))\s*\.\s*"
    r"(findById|getById|getReferenceById|deleteById|existsById|findOneById)\s*\(", re.I)
_IDOR_AUTHZ_EVIDENCE = re.compile(
    r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b|"
    r"\b(?:Authentication|Principal|SecurityContextHolder|AuthorizationManager)\b|"
    r"\b(?:getAuthentication|getPrincipal|getAuthorities|hasPermission|checkPermission|"
    r"currentUser|currentTenant|authenticatedUser|authenticatedTenant)\s*\(|"
    r"\b(?:find|get|delete|exists)By\w*(?:Owner|Tenant|Organization|Principal|Username)\w*\s*\(",
    re.I)


def analyze_authz_idor_dataflow(rel: str, text: str,
                                context_radius: int = CONTEXT_RADIUS,
                                method_bounds=None) -> List[Finding]:
    """Find @PathVariable identifiers that reach a bare repository ID lookup."""
    out: List[Finding] = []
    lines = text.splitlines()
    identifier = re.compile(r"\b[A-Za-z_$][\w$]*\b")
    for start, opening, closing, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        signature = text[start:body_start]
        params = text[opening + 1:closing]
        body = text[body_start + 1:body_end]
        method_scope = signature + body
        if _IDOR_AUTHZ_EVIDENCE.search(method_scope):
            continue
        paths: Dict[str, List[str]] = {}
        for _, param in _parameter_parts(params):
            annotation = re.search(r"@(?:[\w]+\.)*PathVariable\b(?:\s*\(([^)]*)\))?", param)
            if not annotation:
                continue
            plain = re.sub(r"@(?:[\w]+\.)*\w+(?:\s*\([^)]*\))?", "", param).strip()
            variable = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\[\])?\s*$", plain)
            route_name = annotation.group(1) or ""
            if not variable:
                continue
            name = variable.group(1)
            if not (_IDOR_ID_NAME.search(name) or
                    re.search(r"[\x22\x27](?:id|userId|accountId|orderId|customerId|documentId)[\x22\x27]",
                              route_name, re.I)):
                continue
            paths[name] = ["@PathVariable", name]
        if not paths:
            continue
        body_offset = body_start + 1
        for statement in _flow_statements(body):
            expr_ids = [name for name in identifier.findall(statement.expression) if name in paths]
            if statement.target and expr_ids:
                paths[statement.target] = paths[expr_ids[0]] + [statement.target]
            for sink in _IDOR_REPOSITORY_SINK.finditer(statement.text):
                opening_pos = sink.end() - 1
                closing_pos = _closing(_structure_mask(statement.text), opening_pos)
                if closing_pos < 0:
                    continue
                argument = statement.text[opening_pos + 1:closing_pos]
                arg_ids = [name for name in identifier.findall(argument) if name in paths]
                if not arg_ids:
                    continue
                position = body_offset + statement.offset + sink.start()
                line = text.count("\n", 0, position) + 1
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else statement.text.strip()[:200]
                flow = paths[arg_ids[0]] + [sink.group(2) + "()"]
                out.append(Finding(
                    file=rel, line=line, rule_id="AUTHZ-IDOR-DATAFLOW",
                    rule_name=RULE_BY_ID["AUTHZ-IDOR-DATAFLOW"].name,
                    severity="HIGH", status="REVIEW", code=code,
                    note="Request-controlled object ID reaches a bare repository lookup: "
                         + " -> ".join(flow) + ". No owner/tenant/principal or method-security "
                           "evidence is visible in this method; verify service-level authorization.",
                    fix=FIX_IDOR_AUTHZ, flow=flow,
                    fingerprint=fingerprint(rel, "AUTHZ-IDOR-DATAFLOW", code),
                    context=context_lines(lines, line, context_radius)))
    return out


_JOSE_EMBEDDED_SOURCES = {
    "JWT-EMBEDDED-JWK-TRUST": re.compile(
        r"(?:getHeader|getClaim)\s*\(\s*[\x22\x27]jwk[\x22\x27]\s*\)|"
        r"(?:jwt|token|header|headers|jwsHeader|signedJWT)[^;\n]{0,100}"
        r"\.get\s*\(\s*[\x22\x27]jwk[\x22\x27]\s*\)|\.getJWK\s*\(\s*\)", re.I),
    "JWT-X5C-TRUST": re.compile(
        r"(?:getHeader|getClaim)\s*\(\s*[\x22\x27]x5c[\x22\x27]\s*\)|"
        r"(?:jwt|token|header|headers|jwsHeader|signedJWT)[^;\n]{0,100}"
        r"\.get\s*\(\s*[\x22\x27]x5c[\x22\x27]\s*\)|"
        r"\.getX509CertChain\s*\(\s*\)", re.I),
}
_JOSE_KEY_SINK = re.compile(
    r"(?:JWK|RSAKey|ECKey)\s*\.\s*parse\s*\(|"
    r"\.(?:toPublicKey|toRSAKey|toECKey)\s*\(|"
    r"KeyFactory[^;\n]{0,100}\.generatePublic\s*\(|"
    r"\.(?:setSigningKey|verifyWith|createVerifier)\s*\(|"
    r"new\s+(?:RSASSAVerifier|ECDSAVerifier|MACVerifier)\s*\(|"
    r"createJWSVerifier\s*\(|X509CertChainUtils\s*\.\s*parse\s*\(|"
    r"generateCertificate\s*\(", re.I)
_X5C_CHAIN_VALIDATION = re.compile(
    r"\b(?:CertPathValidator|TrustManagerFactory|PKIXParameters|PKIXBuilderParameters|"
    r"checkServerTrusted|validateCertPath|certificateValidator)\b", re.I)


def analyze_embedded_jose_key_trust(rel: str, text: str,
                                    context_radius: int = CONTEXT_RADIUS,
                                    method_bounds=None,
                                    enabled: Optional[Set[str]] = None) -> List[Finding]:
    """Track embedded jwk/x5c header material into signature/key sinks."""
    out: List[Finding] = []
    lines = text.splitlines()
    identifiers = re.compile(r"\b[A-Za-z_$][\w$]*\b")
    allowed = set(_JOSE_EMBEDDED_SOURCES) if enabled is None else set(enabled)
    for _, _, _, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        body = text[body_start + 1:body_end]
        x5c_validated = bool(_X5C_CHAIN_VALIDATION.search(body))
        tainted: Dict[str, Tuple[str, List[str]]] = {}
        body_offset = body_start + 1
        for statement in _flow_statements(body):
            expression = statement.expression or statement.text
            direct = [(rid, pattern.search(expression))
                      for rid, pattern in _JOSE_EMBEDDED_SOURCES.items() if rid in allowed]
            direct = [(rid, match) for rid, match in direct if match]
            inherited = [(name, tainted[name]) for name in identifiers.findall(expression)
                         if name in tainted]
            if statement.target:
                if direct:
                    rid = direct[0][0]
                    claim = "jwk" if rid == "JWT-EMBEDDED-JWK-TRUST" else "x5c"
                    tainted[statement.target] = (rid, [claim, statement.target])
                elif inherited:
                    _, (rid, path) = inherited[0]
                    tainted[statement.target] = (rid, path + [statement.target])
            sink = _JOSE_KEY_SINK.search(statement.text)
            if not sink:
                continue
            candidates: List[Tuple[str, List[str]]] = []
            for rid, _ in direct:
                candidates.append((rid, ["jwk" if rid.endswith("JWK-TRUST") else "x5c"]))
            for name in identifiers.findall(statement.text):
                if name in tainted:
                    candidates.append(tainted[name])
            seen: Set[str] = set()
            for rid, path in candidates:
                if rid in seen or rid not in allowed or (rid == "JWT-X5C-TRUST" and x5c_validated):
                    continue
                seen.add(rid)
                position = body_offset + statement.offset + sink.start()
                line = text.count("\n", 0, position) + 1
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else statement.text.strip()[:200]
                flow = path + [sink.group(0).strip()]
                out.append(Finding(
                    file=rel, line=line, rule_id=rid, rule_name=RULE_BY_ID[rid].name,
                    severity="CRITICAL", status="TAINT", code=code,
                    note="Attacker-controlled JOSE header key material reaches signature/key "
                         "construction without a configured trust anchor: " + " -> ".join(flow) + ".",
                    fix=FIX_EMBEDDED_JOSE_KEY, flow=flow,
                    fingerprint=fingerprint(rel, rid, code),
                    context=context_lines(lines, line, context_radius)))
    return out


_AUTHZ_MATCHER = re.compile(
    r"\b(requestMatchers|antMatchers)\s*\((?P<args>[^)]{1,400})\)\s*\.\s*"
    r"(?P<decision>permitAll|denyAll|anonymous|authenticated|fullyAuthenticated|rememberMe|"
    r"hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|access)\s*\(",
    re.I | re.S)
_AUTHZ_ANY_REQUEST = re.compile(
    r"\banyRequest\s*\(\s*\)\s*\.\s*"
    r"(?P<decision>permitAll|denyAll|anonymous|authenticated|fullyAuthenticated|rememberMe|"
    r"hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|access)\s*\(",
    re.I)


def _matcher_covers(earlier: str, later: str) -> bool:
    if earlier in {"/**", "**", "/"}:
        return True
    if earlier == later:
        return True
    if earlier.endswith("/**"):
        return later.startswith(earlier[:-3].rstrip("/"))
    if earlier.endswith("/*"):
        prefix = earlier[:-2].rstrip("/") + "/"
        remainder = later[len(prefix):] if later.startswith(prefix) else ""
        return bool(remainder and "/" not in remainder.strip("/"))
    return False


def analyze_authz_matcher_order(rel: str, text: str,
                                context_radius: int = CONTEXT_RADIUS) -> List[Finding]:
    """Find first-match-wins authorization rules shadowed by earlier permitAll."""
    entries: List[Tuple[int, str, str]] = []
    for match in _AUTHZ_MATCHER.finditer(text):
        paths = re.findall(r"[\x22\x27](/[^\x22\x27]*)[\x22\x27]", match.group("args"))
        for path in paths or ["<dynamic>"]:
            entries.append((match.start(), path, match.group("decision")))
    for match in _AUTHZ_ANY_REQUEST.finditer(text):
        entries.append((match.start(), "/**", match.group("decision")))
    entries.sort()
    lines = text.splitlines()
    out: List[Finding] = []
    seen: Set[Tuple[int, str]] = set()
    for index, (position, path, decision) in enumerate(entries):
        if decision.lower() != "permitall" or path == "<dynamic>":
            continue
        for later_position, later_path, later_decision in entries[index + 1:]:
            if later_decision.lower() == "permitall" or later_path == "<dynamic>":
                continue
            if not _matcher_covers(path, later_path):
                continue
            line = text.count("\n", 0, position) + 1
            later_line = text.count("\n", 0, later_position) + 1
            if (line, path) in seen:
                break
            seen.add((line, path))
            code = lines[line - 1].strip() if 1 <= line <= len(lines) else path
            severity = "CRITICAL" if path in {"/**", "**", "/"} else "HIGH"
            out.append(Finding(
                file=rel, line=line, rule_id="AUTHZ-MATCHER-ORDER",
                rule_name=RULE_BY_ID["AUTHZ-MATCHER-ORDER"].name,
                severity=severity, status="ANTIPATTERN", code=code,
                note=f"Earlier `{path}.permitAll()` shadows the later restrictive "
                     f"`{later_path}` matcher at line {later_line}; Spring Security uses the first match.",
                fix=FIX_AUTHZ_ORDER,
                fingerprint=fingerprint(rel, "AUTHZ-MATCHER-ORDER", code),
                context=context_lines(lines, line, context_radius)))
            break
    return out


@dataclass
class SecurityChainSummary:
    position: int
    line: int
    order: int
    patterns: List[str]
    catch_all: bool
    code: str


def _security_filter_chains(text: str, method_bounds=None) -> List[SecurityChainSummary]:
    """Extract SecurityFilterChain method order and top-level securityMatcher scope."""
    lines = text.splitlines()
    chains: List[SecurityChainSummary] = []
    for start, _, _, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        header = text[start:body_start]
        if not re.search(r"\bSecurityFilterChain\b", header):
            continue
        body = text[body_start + 1:body_end]
        order_match = re.search(r"@Order\s*\(\s*(\d+)\s*\)", header)
        order = int(order_match.group(1)) if order_match else 1000
        patterns: List[str] = []
        for matcher in re.finditer(r"\.(?:securityMatcher|requestMatcher)\s*\(([^)]{0,300})\)", body, re.S):
            patterns.extend(re.findall(r"[\x22\x27](/[^\x22\x27]*)[\x22\x27]", matcher.group(1)))
        catch_all = not patterns or any(path in {"/**", "**", "/"} for path in patterns)
        line = text.count("\n", 0, start) + 1
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else "SecurityFilterChain"
        chains.append(SecurityChainSummary(start, line, order, patterns, catch_all, code))
    return chains


def analyze_security_filter_chains(rel: str, text: str,
                                   context_radius: int = CONTEXT_RADIUS,
                                   method_bounds=None,
                                   enabled: Optional[Set[str]] = None) -> List[Finding]:
    """Check multiple filter-chain order and the presence of a catch-all fallback."""
    allowed = ({"AUTHZ-SECURITYFILTERCHAIN-ORDER", "AUTHZ-FILTERCHAIN-NO-FALLBACK"}
               if enabled is None else enabled)
    lines = text.splitlines()
    chains = _security_filter_chains(text, method_bounds)
    out: List[Finding] = []
    ordered = sorted(chains, key=lambda chain: (chain.order, chain.position))
    if "AUTHZ-SECURITYFILTERCHAIN-ORDER" in allowed:
        for index, earlier in enumerate(ordered):
            for later in ordered[index + 1:]:
                covered = earlier.catch_all or any(
                    _matcher_covers(first, second)
                    for first in earlier.patterns for second in later.patterns)
                if not covered:
                    continue
                later_scope = ", ".join(later.patterns) or "all requests"
                earlier_scope = ", ".join(earlier.patterns) or "all requests"
                out.append(Finding(
                    file=rel, line=earlier.line,
                    rule_id="AUTHZ-SECURITYFILTERCHAIN-ORDER",
                    rule_name=RULE_BY_ID["AUTHZ-SECURITYFILTERCHAIN-ORDER"].name,
                    severity="CRITICAL" if earlier.catch_all else "HIGH",
                    status="ANTIPATTERN", code=earlier.code,
                    note=f"SecurityFilterChain order {earlier.order} ({earlier_scope}) can match "
                         f"before order {later.order} ({later_scope}) at line {later.line}.",
                    fix=FIX_FILTER_CHAINS,
                    fingerprint=fingerprint(rel, "AUTHZ-SECURITYFILTERCHAIN-ORDER", earlier.code),
                    context=context_lines(lines, earlier.line, context_radius)))
                break
    if ("AUTHZ-FILTERCHAIN-NO-FALLBACK" in allowed and chains and
            not any(chain.catch_all for chain in chains)):
        first = min(chains, key=lambda chain: chain.position)
        scopes = sorted({path for chain in chains for path in chain.patterns})
        out.append(Finding(
            file=rel, line=first.line, rule_id="AUTHZ-FILTERCHAIN-NO-FALLBACK",
            rule_name=RULE_BY_ID["AUTHZ-FILTERCHAIN-NO-FALLBACK"].name,
            severity="HIGH", status="REVIEW", code=first.code,
            note="Every user-defined SecurityFilterChain is scoped (" + ", ".join(scopes) +
                 "), but no catch-all fallback chain is visible. Verify unmatched endpoints are protected.",
            fix=FIX_FILTER_CHAINS,
            fingerprint=fingerprint(rel, "AUTHZ-FILTERCHAIN-NO-FALLBACK", first.code),
            context=context_lines(lines, first.line, context_radius)))
    return out


_ID_TOKEN_SOURCE = re.compile(
    r"\.getIdToken\s*\(\s*\)|\bOidcIdToken\b|\b(?:idToken|id_token)\b", re.I)
_BEARER_SINK = re.compile(
    r"\.setBearerAuth\s*\(|new\s+BearerTokenAuthenticationToken\s*\(|"
    r"(?:\.header|\.set|\.add)\s*\(\s*(?:HttpHeaders\s*\.\s*AUTHORIZATION|"
    r"[\x22\x27]Authorization[\x22\x27])|[\x22\x27]Bearer\s+[\x22\x27]\s*\+", re.I)


def analyze_idtoken_as_access_token(rel: str, text: str,
                                    context_radius: int = CONTEXT_RADIUS,
                                    method_bounds=None) -> List[Finding]:
    """Track OIDC ID-token values into outbound/API Bearer-token sinks."""
    out: List[Finding] = []
    lines = text.splitlines()
    identifiers = re.compile(r"\b[A-Za-z_$][\w$]*\b")
    for _, opening, closing, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        params = text[opening + 1:closing]
        body = text[body_start + 1:body_end]
        tainted: Dict[str, List[str]] = {}
        for _, param in _parameter_parts(params):
            variable = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\[\])?\s*$", param.strip())
            if variable and re.search(r"(?:idToken|id_token|OidcIdToken)", param, re.I):
                tainted[variable.group(1)] = ["OIDC id_token", variable.group(1)]
        body_offset = body_start + 1
        for statement in _flow_statements(body):
            expression = statement.expression or statement.text
            inherited = [name for name in identifiers.findall(expression) if name in tainted]
            direct = _ID_TOKEN_SOURCE.search(expression)
            if statement.target:
                if direct:
                    tainted[statement.target] = ["OIDC id_token", statement.target]
                elif inherited:
                    tainted[statement.target] = tainted[inherited[0]] + [statement.target]
            sink = _BEARER_SINK.search(statement.text)
            if not sink:
                continue
            used = [name for name in identifiers.findall(statement.text) if name in tainted]
            if not used and not _ID_TOKEN_SOURCE.search(statement.text):
                continue
            flow = (tainted[used[0]] if used else ["OIDC id_token"]) + [sink.group(0).strip()]
            position = body_offset + statement.offset + sink.start()
            line = text.count("\n", 0, position) + 1
            code = lines[line - 1].strip() if 1 <= line <= len(lines) else statement.text.strip()[:200]
            out.append(Finding(
                file=rel, line=line, rule_id="OIDC-IDTOKEN-AS-ACCESS-TOKEN",
                rule_name=RULE_BY_ID["OIDC-IDTOKEN-AS-ACCESS-TOKEN"].name,
                severity="HIGH", status="TAINT", code=code,
                note="An OIDC ID token reaches a Bearer-token/API authorization sink: "
                     + " -> ".join(flow) + ".",
                fix=FIX_TOKEN_PURPOSE, flow=flow,
                fingerprint=fingerprint(rel, "OIDC-IDTOKEN-AS-ACCESS-TOKEN", code),
                context=context_lines(lines, line, context_radius)))
    return out


_JWT_PARSE_FOR_AUTH = re.compile(
    r"parseClaimsJws\s*\(|parseSignedClaims\s*\(|(?:jwtDecoder|decoder)\s*\.\s*decode\s*\(|"
    r"JWT\s*\.\s*decode\s*\(|SignedJWT\s*\.\s*parse\s*\(", re.I)
_JWT_AUTH_SINK = re.compile(
    r"new\s+(?:JwtAuthenticationToken|UsernamePasswordAuthenticationToken|PreAuthenticatedAuthenticationToken)\s*\(|"
    r"SecurityContextHolder[^;\n]{0,200}setAuthentication\s*\(|"
    r"\.setAuthorities\s*\(", re.I)
_TOKEN_PURPOSE_CHECK = re.compile(
    r"(?:getType|getHeader\s*\(\s*[\x22\x27]typ|getClaimAsString\s*\(\s*[\x22\x27]token_use|"
    r"getClaim\s*\(\s*[\x22\x27](?:token_use|token_type)|[\x22\x27](?:access|at\+jwt)[\x22\x27])",
    re.I)


def analyze_token_semantics(rel: str, text: str,
                            context_radius: int = CONTEXT_RADIUS,
                            method_bounds=None,
                            enabled: Optional[Set[str]] = None) -> List[Finding]:
    """Review custom OIDC audience and JWT purpose validation."""
    out: List[Finding] = []
    lines = text.splitlines()
    allowed = {"OIDC-AZP-NOT-VALIDATED", "JWT-TOKEN-TYPE-CONFUSION"} if enabled is None else enabled
    for start, _, _, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        scope = text[start:body_end]
        if "OIDC-AZP-NOT-VALIDATED" in allowed:
            oidc = re.search(r"\b(?:OidcIdToken|OidcUser|OidcIdTokenValidator)\b|\.getIdToken\s*\(", scope)
            audience = re.search(r"\.getAudience\s*\(\)|JwtClaimValidator[^;\n]{0,160}[\x22\x27]aud[\x22\x27]|"
                                 r"getClaim[^;\n]{0,80}[\x22\x27]aud[\x22\x27]", scope, re.I)
            azp = re.search(r"[\x22\x27]azp[\x22\x27]|getAuthorizedParty|getClaimAsString\s*\([^)]*azp", scope, re.I)
            if oidc and audience and not azp:
                position = start + audience.start()
                line = text.count("\n", 0, position) + 1
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else "audience validation"
                out.append(Finding(
                    file=rel, line=line, rule_id="OIDC-AZP-NOT-VALIDATED",
                    rule_name=RULE_BY_ID["OIDC-AZP-NOT-VALIDATED"].name,
                    severity="MEDIUM", status="REVIEW", code=code,
                    note="Custom OIDC audience validation is visible, but no azp validation is visible. "
                         "When an ID token has multiple audiences, azp must identify this client.",
                    fix=FIX_TOKEN_PURPOSE,
                    fingerprint=fingerprint(rel, "OIDC-AZP-NOT-VALIDATED", code),
                    context=context_lines(lines, line, context_radius)))
        if "JWT-TOKEN-TYPE-CONFUSION" in allowed:
            parser = _JWT_PARSE_FOR_AUTH.search(scope)
            sink = _JWT_AUTH_SINK.search(scope)
            if parser and sink and not _TOKEN_PURPOSE_CHECK.search(scope):
                position = start + sink.start()
                line = text.count("\n", 0, position) + 1
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else "Authentication"
                out.append(Finding(
                    file=rel, line=line, rule_id="JWT-TOKEN-TYPE-CONFUSION",
                    rule_name=RULE_BY_ID["JWT-TOKEN-TYPE-CONFUSION"].name,
                    severity="HIGH", status="REVIEW", code=code,
                    note="A custom JWT parsing path constructs Authentication without visible "
                         "typ/token_use validation; an ID/refresh token may be confused with an access token.",
                    fix=FIX_TOKEN_PURPOSE,
                    fingerprint=fingerprint(rel, "JWT-TOKEN-TYPE-CONFUSION", code),
                    context=context_lines(lines, line, context_radius)))
    return out


_NESTED_JWE = re.compile(r"EncryptedJWT\s*\.\s*parse\s*\(|JWEObject\s*\.\s*parse\s*\(|\.decrypt\s*\(", re.I)
_NESTED_CLAIMS_USE = re.compile(
    r"\.getJWTClaimsSet\s*\(|JWTClaimsSet\s*\.\s*parse\s*\(|"
    r"\.getPayload\s*\(\s*\)[^;\n]{0,100}\.(?:toJSONObject|toString)\s*\(|"
    r"SignedJWT\s*\.\s*parse\s*\(", re.I)
_INNER_JWS_VERIFY = re.compile(
    r"(?:inner|signed|nested|jws)[A-Za-z0-9_$]*\s*\.\s*verify\s*\(|"
    r"JwtDecoder[^;\n]{0,120}\.decode\s*\(|DefaultJWTProcessor[^;\n]{0,120}\.process\s*\(", re.I)
_CUSTOM_KEY_RESOLVER = re.compile(
    r"\b(?:SigningKeyResolver|SigningKeyResolverAdapter|JWTClaimsSetAwareJWSKeySelector|"
    r"JWSKeySelector|setSigningKeyResolver|selectJWSKeys)\b", re.I)
_KEY_ID_USE = re.compile(r"getKeyID\s*\(|getHeader\s*\([^)]*[\x22\x27]kid|get\s*\([^)]*[\x22\x27]kid", re.I)
_ISSUER_KEY_BINDING = re.compile(
    r"requireIssuer|createDefaultWithIssuer|getIssuer\s*\(|[\x22\x27]iss[\x22\x27]|"
    r"issuer[^;\n]{0,100}(?:key|jwk)|(?:key|jwk)[^;\n]{0,100}issuer", re.I)


def analyze_jwt_advanced_semantics(rel: str, text: str,
                                   context_radius: int = CONTEXT_RADIUS,
                                   method_bounds=None,
                                   enabled: Optional[Set[str]] = None) -> List[Finding]:
    """Nested-JWT signature, issuer-key binding, and signing-key separation checks."""
    allowed = ({"JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED", "JWT-KEY-ISSUER-NOT-BOUND",
                "JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES"} if enabled is None else enabled)
    out: List[Finding] = []
    lines = text.splitlines()
    signing_keys: Dict[str, List[Tuple[str, int, str]]] = {}
    for start, opening, _, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        header = text[start:body_start]
        body = text[body_start + 1:body_end]
        scope = text[start:body_end]
        if "JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED" in allowed:
            decrypt = _NESTED_JWE.search(scope)
            claims = _NESTED_CLAIMS_USE.search(scope)
            if decrypt and claims and not _INNER_JWS_VERIFY.search(scope):
                position = start + claims.start()
                line = text.count("\n", 0, position) + 1
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else claims.group(0)
                out.append(Finding(
                    file=rel, line=line,
                    rule_id="JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED",
                    rule_name=RULE_BY_ID["JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED"].name,
                    severity="CRITICAL", status="REVIEW", code=code,
                    note="A JWE/nested token is decrypted and its inner claims are consumed, "
                         "but inner JWS verification is not visible in the method.",
                    fix=FIX_NESTED_JWT,
                    fingerprint=fingerprint(rel, "JWT-NESTED-INNER-SIGNATURE-NOT-VALIDATED", code),
                    context=context_lines(lines, line, context_radius)))
        if ("JWT-KEY-ISSUER-NOT-BOUND" in allowed and _CUSTOM_KEY_RESOLVER.search(scope)
                and _KEY_ID_USE.search(scope) and not _ISSUER_KEY_BINDING.search(scope)):
            match = _CUSTOM_KEY_RESOLVER.search(scope)
            position = start + (match.start() if match else 0)
            line = text.count("\n", 0, position) + 1
            code = lines[line - 1].strip() if 1 <= line <= len(lines) else "key resolver"
            out.append(Finding(
                file=rel, line=line, rule_id="JWT-KEY-ISSUER-NOT-BOUND",
                rule_name=RULE_BY_ID["JWT-KEY-ISSUER-NOT-BOUND"].name,
                severity="HIGH", status="REVIEW", code=code,
                note="Custom key selection uses kid without a visible issuer-to-key-set binding. "
                     "A key from another trusted issuer may validate a substituted token.",
                fix=FIX_EMBEDDED_JOSE_KEY,
                fingerprint=fingerprint(rel, "JWT-KEY-ISSUER-NOT-BOUND", code),
                context=context_lines(lines, line, context_radius)))
        if "JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES" in allowed:
            name_match = re.search(r"([A-Za-z_$][\w$]*)\s*$", text[start:opening])
            method_name = name_match.group(1) if name_match else ""
            token_type = None
            if re.search(r"access", method_name + header, re.I):
                token_type = "access"
            elif re.search(r"refresh", method_name + header, re.I):
                token_type = "refresh"
            elif re.search(r"(?:idToken|identityToken)", method_name + header, re.I):
                token_type = "id"
            if token_type:
                for sign in re.finditer(r"\.signWith\s*\(\s*([A-Za-z_$][\w$]*)", body):
                    key = sign.group(1)
                    position = body_start + 1 + sign.start()
                    line = text.count("\n", 0, position) + 1
                    code = lines[line - 1].strip() if 1 <= line <= len(lines) else sign.group(0)
                    signing_keys.setdefault(key, []).append((token_type, line, code))
    if "JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES" in allowed:
        for key, uses in signing_keys.items():
            types = sorted({token_type for token_type, _, _ in uses})
            if len(types) < 2:
                continue
            _, line, code = uses[0]
            out.append(Finding(
                file=rel, line=line, rule_id="JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES",
                rule_name=RULE_BY_ID["JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES"].name,
                severity="HIGH", status="REVIEW", code=code,
                note=f"Signing key `{key}` is reused for token types: {', '.join(types)}. "
                     "Use distinct keys and mutually exclusive validation profiles.",
                fix=FIX_TOKEN_PURPOSE,
                fingerprint=fingerprint(rel, "JWT-SAME-KEY-FOR-MULTIPLE-TOKEN-TYPES", code),
                context=context_lines(lines, line, context_radius)))
    return out


_OAUTH_CALLBACK = re.compile(
    r"@(?:Get|Post)Mapping\s*\([^)]*(?:callback|login/oauth2/code)|"
    r"OAuth2AuthorizationResponse|authorizationCode\s*\(|exchangeAuthorizationCode", re.I)
_OAUTH_ISSUER_BINDING = re.compile(
    r"(?:authorizationResponse|getAuthorizationResponse)[^;\n]{0,100}getIssuer\s*\(|"
    r"[\x22\x27]iss[\x22\x27]|issuer[^;\n]{0,100}state|state[^;\n]{0,100}issuer", re.I)


def analyze_oauth_issuer_mixup(loaded: Dict[str, Tuple[List[str], List[Method]]],
                               raw_map: Dict[str, List[str]], root: str,
                               props_files: Sequence[str],
                               context_radius: int = CONTEXT_RADIUS) -> List[Finding]:
    """Review custom callbacks when two or more OAuth/OIDC issuers are configured."""
    issuer_ids: Set[str] = set()
    for _, (lines, _) in loaded.items():
        source = "\n".join(lines)
        issuer_ids.update(re.findall(r"\.issuerUri\s*\(\s*[\x22\x27]([^\x22\x27]+)", source, re.I))
    for path in props_files:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                content = strip_comments(handle.read())
        except OSError:
            continue
        issuer_ids.update(re.findall(
            r"spring\.security\.oauth2\.client\.provider\.([\w-]+)\.issuer-uri\s*[=:]", content, re.I))
    if len(issuer_ids) < 2:
        return []
    out: List[Finding] = []
    for path, (lines, _) in loaded.items():
        source = "\n".join(lines)
        callback = _OAUTH_CALLBACK.search(source)
        if not callback or _OAUTH_ISSUER_BINDING.search(source):
            continue
        line = source.count("\n", 0, callback.start()) + 1
        rel = os.path.relpath(path, root) if root else path
        raw_lines = raw_map.get(path, source.splitlines())
        code = raw_lines[line - 1].strip() if 1 <= line <= len(raw_lines) else callback.group(0)
        finding = Finding(
            file=rel, line=line, rule_id="OAUTH2-ISSUER-MIXUP",
            rule_name=RULE_BY_ID["OAUTH2-ISSUER-MIXUP"].name,
            severity="HIGH", status="REVIEW", code=code,
            note=f"Custom OAuth callback with {len(issuer_ids)} configured issuers has no visible "
                 "binding to the issuer selected for the authorization request.",
            fix="Store the selected issuer with the authorization request and require the callback "
                "issuer to match before exchanging the code.",
            fingerprint=fingerprint(rel, "OAUTH2-ISSUER-MIXUP", code),
            context=context_lines(raw_lines, line, context_radius))
        if not finding_suppressed(raw_lines, finding):
            out.append(finding)
    return out


_DPOP_EVIDENCE = re.compile(r"\bDPoP\b|dpop", re.I)
_DPOP_JTI = re.compile(r"[\x22\x27]jti[\x22\x27]|getJWTID\s*\(", re.I)
_DPOP_REPLAY = re.compile(r"putIfAbsent|replay(?:Cache|Store|Check)|jti(?:Cache|Store)|containsKey|markAsUsed", re.I)
_DPOP_HTM = re.compile(r"[\x22\x27]htm[\x22\x27]|getHttpMethod|validateHtm", re.I)
_DPOP_HTU = re.compile(r"[\x22\x27]htu[\x22\x27]|getHttpUri|validateHtu", re.I)
_DPOP_ATH = re.compile(r"[\x22\x27]ath[\x22\x27]|accessTokenHash|validateAth", re.I)
_DPOP_NONCE_FEATURE = re.compile(r"DPoP-Nonce|use_dpop_nonce|nonceRequired|requireNonce", re.I)
_DPOP_NONCE_CHECK = re.compile(r"getClaim[^;\n]{0,80}[\x22\x27]nonce|validateNonce|expectedNonce", re.I)


def analyze_dpop_validation(rel: str, text: str,
                            context_radius: int = CONTEXT_RADIUS,
                            method_bounds=None,
                            enabled: Optional[Set[str]] = None) -> List[Finding]:
    """Check validation components only in code that visibly processes DPoP proofs."""
    all_rules = {"DPOP-JTI-NOT-REPLAY-CHECKED", "DPOP-HTM-HTU-NOT-VALIDATED",
                 "DPOP-IAT-WINDOW-TOO-LARGE", "DPOP-ATH-NOT-VALIDATED",
                 "DPOP-NONCE-NOT-VALIDATED"}
    allowed = all_rules if enabled is None else enabled
    out: List[Finding] = []
    lines = text.splitlines()

    def add(rid: str, line: int, code: str, note: str, severity: str = "HIGH",
            status: str = "REVIEW") -> None:
        out.append(Finding(
            file=rel, line=line, rule_id=rid, rule_name=RULE_BY_ID[rid].name,
            severity=severity, status=status, code=code, note=note, fix=FIX_DPOP,
            fingerprint=fingerprint(rel, rid, code),
            context=context_lines(lines, line, context_radius)))

    for start, _, _, _, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        scope = text[start:body_end]
        evidence = _DPOP_EVIDENCE.search(scope)
        if not evidence:
            continue
        position = start + evidence.start()
        line = text.count("\n", 0, position) + 1
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else evidence.group(0)
        if ("DPOP-JTI-NOT-REPLAY-CHECKED" in allowed and
                not (_DPOP_JTI.search(scope) and _DPOP_REPLAY.search(scope))):
            add("DPOP-JTI-NOT-REPLAY-CHECKED", line, code,
                "DPoP proof processing lacks both jti extraction and a visible atomic replay-cache check.")
        if ("DPOP-HTM-HTU-NOT-VALIDATED" in allowed and
                not (_DPOP_HTM.search(scope) and _DPOP_HTU.search(scope))):
            add("DPOP-HTM-HTU-NOT-VALIDATED", line, code,
                "DPoP proof processing does not visibly validate both htm and htu against the request.")
        if "DPOP-IAT-WINDOW-TOO-LARGE" in allowed:
            windows = []
            windows.extend(int(value) * 60 for value in re.findall(
                r"Duration\s*\.\s*ofMinutes\s*\(\s*(\d+)\s*\)", scope))
            windows.extend(int(value) for value in re.findall(
                r"Duration\s*\.\s*ofSeconds\s*\(\s*(\d+)\s*\)", scope))
            if any(value > 300 for value in windows):
                add("DPOP-IAT-WINDOW-TOO-LARGE", line, code,
                    "DPoP proof iat/max-age acceptance window exceeds five minutes.",
                    "MEDIUM", "ANTIPATTERN")
        if ("DPOP-ATH-NOT-VALIDATED" in allowed and
                re.search(r"accessToken|Bearer", scope, re.I) and not _DPOP_ATH.search(scope)):
            add("DPOP-ATH-NOT-VALIDATED", line, code,
                "DPoP proof is processed with an access token, but ath validation is not visible.")
        if ("DPOP-NONCE-NOT-VALIDATED" in allowed and _DPOP_NONCE_FEATURE.search(scope)
                and not _DPOP_NONCE_CHECK.search(scope)):
            add("DPOP-NONCE-NOT-VALIDATED", line, code,
                "DPoP nonce support is enabled/emitted, but proof nonce validation is not visible.")
    return out


_REFRESH_FLOW = re.compile(r"\brefresh[_A-Z]?token\b|/refresh\b|refreshToken", re.I)
_ACCESS_ISSUE = re.compile(r"generateAccessToken|createAccessToken|issueAccessToken|accessToken\s*=|Jwts\s*\.\s*builder", re.I)
_REFRESH_ROTATION = re.compile(
    r"rotate(?:RefreshToken)?|generateRefreshToken|createRefreshToken|newRefreshToken|"
    r"refreshTokenRepository\s*\.\s*(?:delete|save)|revoke[^;\n]{0,80}refresh|"
    r"invalidate[^;\n]{0,80}refresh|replace[^;\n]{0,80}refresh", re.I)


def analyze_refresh_rotation(rel: str, text: str,
                             context_radius: int = CONTEXT_RADIUS,
                             method_bounds=None) -> List[Finding]:
    """Find refresh flows that issue access tokens without rotating refresh tokens."""
    out: List[Finding] = []
    lines = text.splitlines()
    for start, _, _, body_start, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        scope = text[start:body_end]
        refresh = _REFRESH_FLOW.search(scope)
        issue = _ACCESS_ISSUE.search(scope)
        if not refresh or not issue or _REFRESH_ROTATION.search(scope):
            continue
        position = start + issue.start()
        line = text.count("\n", 0, position) + 1
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else "refresh"
        out.append(Finding(
            file=rel, line=line, rule_id="REFRESH-TOKEN-NO-ROTATION",
            rule_name=RULE_BY_ID["REFRESH-TOKEN-NO-ROTATION"].name,
            severity="HIGH", status="REVIEW", code=code,
            note="This refresh flow issues a new access token but no refresh-token replacement "
                 "or old-token revocation is visible in the method.",
            fix=FIX_REFRESH_LIFECYCLE,
            fingerprint=fingerprint(rel, "REFRESH-TOKEN-NO-ROTATION", code),
            context=context_lines(lines, line, context_radius)))
    return out


_PKCS12_CONTEXT = re.compile(r"KeyStore\s*\.\s*getInstance\s*\(\s*[\x22\x27](?:PKCS12|PKCS#12)[\x22\x27]", re.I)
_EMPTY_KEYSTORE_PASSWORD = re.compile(
    r"\.(?:load|store)\s*\([^;\n]{0,240},\s*(?:null|new\s+char\s*\[\s*0\s*\]|"
    r"new\s+char\s*\[\s*\]\s*\{\s*\}|[\x22\x27][\x22\x27]\s*\.\s*toCharArray\s*\(\s*\))\s*\)",
    re.I)


def analyze_pkcs12_empty_password(rel: str, text: str,
                                  context_radius: int = CONTEXT_RADIUS,
                                  method_bounds=None) -> List[Finding]:
    out: List[Finding] = []
    lines = text.splitlines()
    for start, _, _, _, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        scope = text[start:body_end]
        if not _PKCS12_CONTEXT.search(scope):
            continue
        empty = _EMPTY_KEYSTORE_PASSWORD.search(scope)
        if not empty:
            continue
        position = start + empty.start()
        line = text.count("\n", 0, position) + 1
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else empty.group(0)
        out.append(Finding(
            file=rel, line=line, rule_id="CERT-EMPTY-PKCS12-PASSWORD",
            rule_name=RULE_BY_ID["CERT-EMPTY-PKCS12-PASSWORD"].name,
            severity="HIGH", status="ANTIPATTERN", code=code,
            note="PKCS12 keystore load/store uses a null or empty password.",
            fix=RULE_BY_ID["CERT-EMPTY-PKCS12-PASSWORD"].fix,
            fingerprint=fingerprint(rel, "CERT-EMPTY-PKCS12-PASSWORD", code),
            context=context_lines(lines, line, context_radius)))
    return out


_RESET_EVIDENCE = re.compile(r"resetPassword|forgotPassword|passwordReset|ResetToken|reset[_-]?token", re.I)
_RESET_GENERATION = re.compile(r"(?:generate|create|new)[A-Za-z0-9_$]*(?:Reset)?Token|resetToken\s*=|ResetToken\s*\(", re.I)
_RESET_EXPIRY = re.compile(r"expir|expires|validUntil|ttl|timeToLive|Duration\s*\.|\.plus(?:Seconds|Minutes|Hours)\s*\(", re.I)
_RESET_PREDICTABLE = re.compile(
    r"Math\s*\.\s*random\s*\(|new\s+Random\s*\(|System\s*\.\s*(?:currentTimeMillis|nanoTime)\s*\(|"
    r"(?:username|email|userId)[^;\n]{0,120}(?:hashCode|digest|encode)|AtomicLong|incrementAndGet", re.I)
_PASSWORD_CHANGE = re.compile(r"setPassword\s*\(|updatePassword\s*\(|changePassword\s*\(|passwordEncoder\s*\.\s*encode", re.I)
_RESET_CONSUME = re.compile(r"findByToken|validateResetToken|verifyResetToken|getResetToken|resetTokenRepository", re.I)
_RESET_INVALIDATE = re.compile(r"(?:delete|remove|revoke|consume|markUsed|invalidate)[^;\n]{0,100}(?:reset|token)|"
                               r"(?:reset|token)[^;\n]{0,100}(?:setUsed|usedAt|consumedAt)", re.I)


def analyze_password_reset(rel: str, text: str,
                           context_radius: int = CONTEXT_RADIUS,
                           method_bounds=None,
                           enabled: Optional[Set[str]] = None) -> List[Finding]:
    all_rules = {"PASSWORD-RESET-NO-EXPIRY", "PASSWORD-RESET-TOKEN-REUSE",
                 "PASSWORD-RESET-PREDICTABLE-TOKEN"}
    allowed = all_rules if enabled is None else enabled
    out: List[Finding] = []
    lines = text.splitlines()
    for start, _, _, _, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        scope = text[start:body_end]
        evidence = _RESET_EVIDENCE.search(scope)
        if not evidence:
            continue
        line = text.count("\n", 0, start + evidence.start()) + 1
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else evidence.group(0)
        if ("PASSWORD-RESET-PREDICTABLE-TOKEN" in allowed and
                _RESET_GENERATION.search(scope) and _RESET_PREDICTABLE.search(scope)):
            out.append(Finding(
                file=rel, line=line, rule_id="PASSWORD-RESET-PREDICTABLE-TOKEN",
                rule_name=RULE_BY_ID["PASSWORD-RESET-PREDICTABLE-TOKEN"].name,
                severity="CRITICAL", status="ANTIPATTERN", code=code,
                note="Password-reset token generation uses a predictable time value or non-cryptographic RNG.",
                fix=FIX_PASSWORD_RESET,
                fingerprint=fingerprint(rel, "PASSWORD-RESET-PREDICTABLE-TOKEN", code),
                context=context_lines(lines, line, context_radius)))
        if ("PASSWORD-RESET-NO-EXPIRY" in allowed and _RESET_GENERATION.search(scope)
                and not _RESET_EXPIRY.search(scope)):
            out.append(Finding(
                file=rel, line=line, rule_id="PASSWORD-RESET-NO-EXPIRY",
                rule_name=RULE_BY_ID["PASSWORD-RESET-NO-EXPIRY"].name,
                severity="HIGH", status="REVIEW", code=code,
                note="Reset-token generation/storage is visible, but no expiry or TTL is visible in the method.",
                fix=FIX_PASSWORD_RESET,
                fingerprint=fingerprint(rel, "PASSWORD-RESET-NO-EXPIRY", code),
                context=context_lines(lines, line, context_radius)))
        if ("PASSWORD-RESET-TOKEN-REUSE" in allowed and _RESET_CONSUME.search(scope)
                and _PASSWORD_CHANGE.search(scope) and not _RESET_INVALIDATE.search(scope)):
            out.append(Finding(
                file=rel, line=line, rule_id="PASSWORD-RESET-TOKEN-REUSE",
                rule_name=RULE_BY_ID["PASSWORD-RESET-TOKEN-REUSE"].name,
                severity="HIGH", status="REVIEW", code=code,
                note="Password reset consumes a token and changes a password without visible atomic "
                     "delete/revoke/used-state handling.",
                fix=FIX_PASSWORD_RESET,
                fingerprint=fingerprint(rel, "PASSWORD-RESET-TOKEN-REUSE", code),
                context=context_lines(lines, line, context_radius)))
    return out


_CUSTOM_LOGIN = re.compile(
    r"@PostMapping\s*\([^)]*[\x22\x27][^\x22\x27]*(?:login|authenticate|signin)|"
    r"\b(?:login|authenticate|signIn)\s*\([^;{]*(?:password|credential)[^;{]*\)\s*(?:throws[^\{]*)?\{",
    re.I)
_LOGIN_THROTTLE = re.compile(
    r"RateLimiter|rateLimit|throttl|loginAttempt|failedAttempt|accountLock|lockout|"
    r"Bucket4j|resilience4j|tooManyRequests|TOO_MANY_REQUESTS", re.I)
_MFA_EVIDENCE = re.compile(r"\b(?:MFA|2FA|TOTP|OTP|secondFactor|multiFactor)\b", re.I)
_MFA_FAIL_OPEN = re.compile(
    r"catch\s*\([^)]*\)\s*\{(?:(?!\}).){0,500}(?:return\s+true\s*;|"
    r"(?:skip|bypass|continueWithout)[A-Za-z0-9_$]*\s*\()|"
    r"exceptionally\s*\([^)]*->\s*(?:true|Boolean\.TRUE)", re.I | re.S)


def analyze_auth_resilience(rel: str, text: str,
                            context_radius: int = CONTEXT_RADIUS,
                            method_bounds=None,
                            enabled: Optional[Set[str]] = None) -> List[Finding]:
    allowed = {"AUTH-LOGIN-NO-RATE-LIMIT", "MFA-FAIL-OPEN"} if enabled is None else enabled
    out: List[Finding] = []
    lines = text.splitlines()
    for start, _, _, _, body_end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        scope = text[start:body_end]
        if ("AUTH-LOGIN-NO-RATE-LIMIT" in allowed and _CUSTOM_LOGIN.search(scope)
                and not _LOGIN_THROTTLE.search(scope)):
            match = _CUSTOM_LOGIN.search(scope)
            position = start + (match.start() if match else 0)
            line = text.count("\n", 0, position) + 1
            code = lines[line - 1].strip() if 1 <= line <= len(lines) else "login"
            out.append(Finding(
                file=rel, line=line, rule_id="AUTH-LOGIN-NO-RATE-LIMIT",
                rule_name=RULE_BY_ID["AUTH-LOGIN-NO-RATE-LIMIT"].name,
                severity="MEDIUM", status="REVIEW", code=code,
                note="Custom credential endpoint has no visible throttling, failed-attempt counter, or lockout. "
                     "Verify equivalent protection at the gateway if intentionally external.",
                fix=RULE_BY_ID["AUTH-LOGIN-NO-RATE-LIMIT"].fix,
                fingerprint=fingerprint(rel, "AUTH-LOGIN-NO-RATE-LIMIT", code),
                context=context_lines(lines, line, context_radius)))
        if "MFA-FAIL-OPEN" in allowed and _MFA_EVIDENCE.search(scope):
            fail_open = _MFA_FAIL_OPEN.search(scope)
            if fail_open:
                position = start + fail_open.start()
                line = text.count("\n", 0, position) + 1
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else fail_open.group(0)[:200]
                out.append(Finding(
                    file=rel, line=line, rule_id="MFA-FAIL-OPEN",
                    rule_name=RULE_BY_ID["MFA-FAIL-OPEN"].name,
                    severity="CRITICAL", status="ANTIPATTERN", code=code,
                    note="MFA/TOTP/OTP exception handling returns success or invokes an explicit bypass path.",
                    fix=RULE_BY_ID["MFA-FAIL-OPEN"].fix,
                    fingerprint=fingerprint(rel, "MFA-FAIL-OPEN", code),
                    context=context_lines(lines, line, context_radius)))
    return out


def analyze_certificate_text_file(path: str, root: str,
                                  context_radius: int = CONTEXT_RADIUS) -> List[Finding]:
    """Scan PEM/key text files without attempting to parse or expose key bytes."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read(2 * 1024 * 1024)
    except OSError:
        return []
    match = re.search(r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH)\s+)?PRIVATE KEY-----", text, re.I)
    if not match:
        return []
    lines = text.splitlines()
    line = text.count("\n", 0, match.start()) + 1
    rel = os.path.relpath(path, root) if root else path
    code = lines[line - 1].strip() if 1 <= line <= len(lines) else "private key header"
    return [Finding(
        file=rel, line=line, rule_id="CERT-PRIVATE-KEY-COMMITTED",
        rule_name=RULE_BY_ID["CERT-PRIVATE-KEY-COMMITTED"].name,
        severity="CRITICAL", status="ANTIPATTERN", code=code,
        note="A private-key PEM header is present in a scanned .pem/.key file. Rotate the key.",
        fix=RULE_BY_ID["CERT-PRIVATE-KEY-COMMITTED"].fix,
        fingerprint=fingerprint(rel, "CERT-PRIVATE-KEY-COMMITTED", code),
        context=context_lines(lines, line, context_radius))]


def _group_loaded_by_module(loaded: Dict[str, Tuple[List[str], List[Method]]],
                            root: str, build_files: Sequence[str]) -> Dict[str, List[Tuple[str, str]]]:
    """Group loaded source text by the nearest build-file directory."""
    module_dirs = sorted({os.path.abspath(os.path.dirname(path)) for path in build_files},
                         key=len, reverse=True)
    grouped: Dict[str, List[Tuple[str, str]]] = {}
    for path, (lines, _) in loaded.items():
        absolute = os.path.abspath(path)
        module = os.path.abspath(root)
        for directory in module_dirs:
            try:
                if os.path.commonpath((absolute, directory)) == directory:
                    module = directory
                    break
            except ValueError:
                continue
        grouped.setdefault(module, []).append((path, "\n".join(lines)))
    return grouped


@dataclass
class ProjectMethodSummary:
    path: str
    rel: str
    class_name: str
    name: str
    line: int
    start: int
    params: List[str]
    body: str
    body_offset: int
    body_end: int
    header: str
    tainted_tenants: Dict[str, List[str]] = field(default_factory=dict)
    tainted_objects: Dict[str, List[str]] = field(default_factory=dict)


_TENANT_NAME = re.compile(r"(?:tenant|organization|organisation|workspace|company|realm)(?:Id|ID|_id)?$", re.I)
_TENANT_REQUEST_SOURCE = re.compile(
    r"(?:getParameter|getHeader)\s*\(\s*[\x22\x27]"
    r"(?:tenant|tenantId|organizationId|organisationId|workspaceId|companyId|realm)"
    r"[\x22\x27]\s*\)", re.I)
_OBJECT_REQUEST_SOURCE = re.compile(
    r"(?:getParameter|getHeader)\s*\(\s*[\x22\x27]"
    r"(?:id|userId|accountId|orderId|customerId|documentId)"
    r"[\x22\x27]\s*\)", re.I)
_TENANT_REPOSITORY_CALL = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:Repository|Repo|Dao)|(?:repository|repo|dao))\s*\.\s*"
    r"((?:find|get|delete|remove|exists|save|update|count)[A-Za-z0-9_$]*)\s*\(", re.I)
_TENANT_AUTH_BINDING = re.compile(
    r"\b(?:currentTenant|authenticatedTenant|principalTenant|tenantFromAuthentication|"
    r"getTenantFromPrincipal|TenantContext)\b|"
    r"SecurityContextHolder|Authentication\b|Principal\b|"
    r"getPrincipal\s*\(|getAuthentication\s*\(|@PreAuthorize\b", re.I)


def _owner_class_name(text: str, position: int) -> str:
    """Return the innermost class/object containing a source position."""
    masked = _structure_mask(text)
    owners: List[Tuple[int, int, str]] = []
    for match in re.finditer(r"\b(?:class|interface|record|object)\s+([A-Za-z_$][\w$]*)[^\{]*\{",
                             masked):
        opening = masked.find("{", match.start(), match.end())
        closing = _closing(masked, opening, "{", "}") if opening >= 0 else -1
        if opening <= position <= closing:
            owners.append((opening, closing, match.group(1)))
    return max(owners, key=lambda item: item[0])[2] if owners else "<top-level>"


def _project_method_summaries(loaded: Dict[str, Tuple[List[str], List[Method]]],
                              root: str) -> List[ProjectMethodSummary]:
    summaries: List[ProjectMethodSummary] = []
    for path, (source_lines, _) in loaded.items():
        if not path.endswith((".java", ".kt")):
            continue
        text = "\n".join(source_lines)
        for start, opening, closing, body_start, body_end in _web_methods(text):
            name_match = re.search(r"([A-Za-z_$][\w$]*)\s*$", text[start:opening])
            if not name_match:
                continue
            params_text = text[opening + 1:closing]
            params: List[str] = []
            taint: Dict[str, List[str]] = {}
            object_taint: Dict[str, List[str]] = {}
            for _, param in _parameter_parts(params_text):
                variable = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\[\])?\s*$", param.strip())
                if not variable:
                    continue
                name = variable.group(1)
                params.append(name)
                if (_TENANT_NAME.search(name) and
                        re.search(r"@(?:[\w]+\.)*(?:PathVariable|RequestParam|RequestHeader|ModelAttribute)\b",
                                  param)):
                    taint[name] = ["request tenant", name]
                elif (_IDOR_ID_NAME.search(name) and
                      re.search(r"@(?:[\w]+\.)*(?:PathVariable|RequestParam|RequestHeader|ModelAttribute)\b",
                                param)):
                    object_taint[name] = ["request object id", name]
            line = text.count("\n", 0, start + name_match.start(1)) + 1
            summaries.append(ProjectMethodSummary(
                path=path, rel=os.path.relpath(path, root) if root else path,
                class_name=_owner_class_name(text, start),
                name=name_match.group(1), line=line, start=start, params=params,
                body=text[body_start + 1:body_end], body_offset=body_start + 1,
                body_end=body_end, header=text[start:body_start],
                tainted_tenants=taint, tainted_objects=object_taint))
    return summaries


def analyze_interprocedural_tenant_dataflow(
        loaded: Dict[str, Tuple[List[str], List[Method]]], raw_map: Dict[str, List[str]],
        root: str, context_radius: int = CONTEXT_RADIUS,
        enabled: Optional[Set[str]] = None) -> List[Finding]:
    """Propagate request tenant/object IDs across calls and flag unbound access."""
    allowed = ({"AUTHZ-TENANT-DATAFLOW", "AUTHZ-IDOR-DATAFLOW"}
               if enabled is None else enabled)
    methods = _project_method_summaries(loaded, root)
    by_name: Dict[str, List[ProjectMethodSummary]] = {}
    identifiers = re.compile(r"\b[A-Za-z_$][\w$]*\b")
    for method in methods:
        by_name.setdefault(method.name, []).append(method)

    # A small fixed point propagates request tenant scope and object identifiers
    # through assignments and controller -> service -> repository helper calls.
    for _ in range(8):
        changed = False
        for method in methods:
            for statement in _flow_statements(method.body):
                expression = statement.expression or statement.text
                expression_names = identifiers.findall(expression)
                inherited_tenants = [name for name in expression_names
                                     if name in method.tainted_tenants]
                inherited_objects = [name for name in expression_names
                                     if name in method.tainted_objects]
                if statement.target:
                    if _TENANT_REQUEST_SOURCE.search(expression) or inherited_tenants:
                        path = (["request tenant"] if not inherited_tenants
                                else method.tainted_tenants[inherited_tenants[0]]) + [statement.target]
                        if method.tainted_tenants.get(statement.target) != path:
                            method.tainted_tenants[statement.target] = path
                            changed = True
                    if _OBJECT_REQUEST_SOURCE.search(expression) or inherited_objects:
                        path = (["request object id"] if not inherited_objects
                                else method.tainted_objects[inherited_objects[0]]) + [statement.target]
                        if method.tainted_objects.get(statement.target) != path:
                            method.tainted_objects[statement.target] = path
                            changed = True
                masked = _structure_mask(statement.text)
                for call in re.finditer(r"\b(?:[A-Za-z_$][\w$]*\s*\.\s*)*"
                                        r"([A-Za-z_$][\w$]*)\s*\(", masked):
                    callee_name = call.group(1)
                    if callee_name not in by_name:
                        continue
                    opening = call.end() - 1
                    closing = _closing(masked, opening)
                    if closing < 0:
                        continue
                    args = [part.strip() for _, part in _parameter_parts(
                        statement.text[opening + 1:closing])]
                    for callee in by_name[callee_name]:
                        if callee is method:
                            continue
                        if len(callee.params) != len(args):
                            continue
                        for index, argument in enumerate(args):
                            target = callee.params[index]
                            argument_names = identifiers.findall(argument)
                            tenant_vars = [name for name in argument_names
                                           if name in method.tainted_tenants]
                            object_vars = [name for name in argument_names
                                           if name in method.tainted_objects]
                            if tenant_vars:
                                path = (method.tainted_tenants[tenant_vars[0]] +
                                        [callee.name + "()", target])
                                if callee.tainted_tenants.get(target) != path:
                                    callee.tainted_tenants[target] = path
                                    changed = True
                            if object_vars:
                                path = (method.tainted_objects[object_vars[0]] +
                                        [callee.name + "()", target])
                                if callee.tainted_objects.get(target) != path:
                                    callee.tainted_objects[target] = path
                                    changed = True
        if not changed:
            break

    out: List[Finding] = []
    for method in methods:
        method_scope = method.header + method.body
        has_auth_binding = bool(_TENANT_AUTH_BINDING.search(method_scope) or
                                _IDOR_AUTHZ_EVIDENCE.search(method_scope))
        if has_auth_binding:
            continue
        masked = _structure_mask(method.body)
        for sink in _TENANT_REPOSITORY_CALL.finditer(masked):
            opening = sink.end() - 1
            closing = _closing(masked, opening)
            if closing < 0:
                continue
            argument = method.body[opening + 1:closing]
            argument_names = identifiers.findall(argument)
            tenant_args = [name for name in argument_names
                           if name in method.tainted_tenants]
            position = method.body_offset + sink.start()
            source_text = "\n".join(loaded[method.path][0])
            line = source_text.count("\n", 0, position) + 1
            raw_lines = raw_map.get(method.path, source_text.splitlines())
            code = raw_lines[line - 1].strip() if 1 <= line <= len(raw_lines) else sink.group(0)
            if "AUTHZ-TENANT-DATAFLOW" in allowed and method.tainted_tenants:
                source_name = (tenant_args[0] if tenant_args
                               else next(iter(method.tainted_tenants)))
                path = method.tainted_tenants[source_name] + [sink.group(2) + "()"]
                detail = ("Request-controlled tenant scope reaches the repository call"
                          if tenant_args else
                          "Request tenant context is dropped before an unscoped repository call")
                finding = Finding(
                    file=method.rel, line=line, rule_id="AUTHZ-TENANT-DATAFLOW",
                    rule_name=RULE_BY_ID["AUTHZ-TENANT-DATAFLOW"].name,
                    severity="HIGH", status="TAINT", code=code,
                    note=detail + " without visible binding to the authenticated principal: "
                         + " -> ".join(path) + ".",
                    fix=FIX_TENANT_AUTHZ, flow=path,
                    fingerprint=fingerprint(method.rel, "AUTHZ-TENANT-DATAFLOW", code),
                    context=context_lines(raw_lines, line, context_radius))
                if not finding_suppressed(raw_lines, finding):
                    out.append(finding)
            object_args = [name for name in argument_names
                           if name in method.tainted_objects]
            if "AUTHZ-IDOR-DATAFLOW" in allowed and object_args:
                path = method.tainted_objects[object_args[0]] + [sink.group(2) + "()"]
                finding = Finding(
                    file=method.rel, line=line, rule_id="AUTHZ-IDOR-DATAFLOW",
                    rule_name=RULE_BY_ID["AUTHZ-IDOR-DATAFLOW"].name,
                    severity="HIGH", status="TAINT", code=code,
                    note="Request-controlled object ID crosses a method boundary and reaches "
                         "a repository lookup without visible owner, tenant, principal, or "
                         "method-security binding: " + " -> ".join(path) + ".",
                    fix=FIX_IDOR_AUTHZ, flow=path,
                    fingerprint=fingerprint(method.rel, "AUTHZ-IDOR-DATAFLOW", code),
                    context=context_lines(raw_lines, line, context_radius))
                if not finding_suppressed(raw_lines, finding):
                    out.append(finding)
    return out


_COVERAGE_MAPPING = re.compile(
    r"@(?:[\w]+\.)*(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|"
    r"RequestMapping)\b(?:\s*\(([^)]*)\))?", re.I | re.S)
_COVERAGE_CONSUMER = re.compile(
    r"@(?:[\w]+\.)*(KafkaListener|RabbitListener|JmsListener)\b(?:\s*\(([^)]*)\))?",
    re.I | re.S)
_COVERAGE_SCHEDULED = re.compile(
    r"@(?:[\w]+\.)*Scheduled\b(?:\s*\(([^)]*)\))?", re.I | re.S)
_COVERAGE_METHOD_AUTHZ_ANNOTATION = re.compile(
    r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b", re.I)
_COVERAGE_PROGRAMMATIC_AUTHZ = re.compile(
    r"\b(?:hasRole|hasAuthority|hasPermission|checkPermission|AuthorizationManager)\s*\(", re.I)
_COVERAGE_AUTHN = re.compile(
    r"@AuthenticationPrincipal\b|\b(?:Authentication|Principal|SecurityContextHolder)\b|"
    r"\b(?:getAuthentication|getPrincipal|authenticatedUser|currentUser)\s*\(", re.I)
_COVERAGE_VALIDATION = re.compile(
    r"@(?:Valid|Validated|NotNull|NotBlank|NotEmpty|Size|Pattern|Min|Max|Positive|Email)\b|"
    r"\b(?:validator\.validate|validateRequest|validatePayload|validationService)\s*\(", re.I)
_COVERAGE_RATE_LIMIT = re.compile(
    r"\b(?:RateLimiter|rateLimit|throttl|loginAttempt|failedAttempt|accountLock|lockout|"
    r"bucket\.tryConsume|resilience4j)\b", re.I)
_COVERAGE_AUDIT = re.compile(
    r"\b(?:AuditEvent|AuditEventRepository|auditService|securityAudit|auditLogger|"
    r"recordAudit|recordSecurityEvent|publishAuditEvent)\b", re.I)
_COVERAGE_TENANT_BINDING = re.compile(
    r"\b(?:currentTenant|authenticatedTenant|tenantFromAuthentication|TenantContext|"
    r"findBy\w*Tenant|deleteBy\w*Tenant|existsBy\w*Tenant|OwnerId|PrincipalId)\b", re.I)
_COVERAGE_SENSITIVE_SINK = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:Repository|Repo|Dao)|(?:repository|repo|dao))\s*\.\s*"
    r"((?:find|get|save|delete|remove|update|exists|count)[A-Za-z0-9_$]*)\s*\(|"
    r"\b(?:entityManager|jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*"
    r"(find|persist|merge|remove|update|query)\s*\(", re.I)
_COVERAGE_MUTATING_SINK = re.compile(
    r"\b(?:save|delete|remove|update|persist|merge)[A-Za-z0-9_$]*\s*\(", re.I)
_COVERAGE_ABUSE_ROUTE = re.compile(
    r"(?:login|sign[-_]?in|authenticate|token|password[^/]*(?:reset|forgot)|mfa|otp)", re.I)


@dataclass
class CoverageRoutePolicy:
    file: str
    module: str
    position: int
    line: int
    pattern: str
    decision: str
    http_method: str = "ANY"


def _coverage_annotation_paths(arguments: str) -> List[str]:
    paths = re.findall(r"[\x22\x27](/[^\x22\x27]*)[\x22\x27]", arguments or "")
    return paths or [""]


def _coverage_join_route(prefix: str, suffix: str) -> str:
    joined = "/".join(part.strip("/") for part in (prefix, suffix) if part.strip("/"))
    return "/" + joined if joined else "/"


def _coverage_class_prefix(text: str, method: ProjectMethodSummary) -> str:
    """Extract the nearest class-level @RequestMapping prefix."""
    masked = _structure_mask(text)
    candidates: List[Tuple[int, int]] = []
    for match in re.finditer(
            r"\b(?:class|interface|record|object)\s+" + re.escape(method.class_name) +
            r"\b[^\{]*\{", masked):
        opening = masked.find("{", match.start(), match.end())
        closing = _closing(masked, opening, "{", "}") if opening >= 0 else -1
        if opening <= method.start <= closing:
            candidates.append((match.start(), opening))
    if not candidates:
        return ""
    class_start, _ = max(candidates)
    annotation_start = max(masked.rfind("}", 0, class_start),
                           masked.rfind(";", 0, class_start), 0)
    preamble = text[annotation_start:class_start]
    mappings = list(re.finditer(
        r"@(?:[\w]+\.)*RequestMapping\b(?:\s*\(([^)]*)\))?", preamble, re.I | re.S))
    if not mappings:
        return ""
    paths = _coverage_annotation_paths(mappings[-1].group(1) or "")
    return paths[0] if paths else ""


def _coverage_http_methods(annotation: str, arguments: str) -> List[str]:
    fixed = {
        "getmapping": "GET", "postmapping": "POST", "putmapping": "PUT",
        "patchmapping": "PATCH", "deletemapping": "DELETE",
    }
    if annotation.lower() in fixed:
        return [fixed[annotation.lower()]]
    explicit = re.findall(r"RequestMethod\s*\.\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)",
                          arguments or "", re.I)
    return [method.upper() for method in explicit] or ["ANY"]


def _coverage_pattern_matches(pattern: str, route: str) -> bool:
    if pattern in {"/**", "**"}:
        return True
    if pattern.endswith("/**") and route == pattern[:-3]:
        return True
    token = re.escape(pattern)
    token = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", token)
    token = token.replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return bool(re.fullmatch(token, route))


def _coverage_module_map(
        loaded: Dict[str, Tuple[List[str], List[Method]]], root: str,
        build_files: Sequence[str]) -> Dict[str, str]:
    module_map: Dict[str, str] = {}
    for module, sources in _group_loaded_by_module(loaded, root, build_files).items():
        for path, _ in sources:
            module_map[path] = module
    return module_map


def _coverage_route_policies(loaded, root, module_map):
    """Retain chain boundaries, order, matcher order, permissions and conditions."""
    policies = []
    for path, (lines, _) in loaded.items():
        text = '\n'.join(lines)
        rel = os.path.relpath(path, root) if root else path
        bounds = [(start, body, end) for start, _, _, body, end in _web_methods(text)
                  if re.search(r'\bSecurityFilterChain\b', text[start:body])]
        # Also support legacy configure(HttpSecurity) sources conservatively.
        if not bounds:
            bounds = [(0, -1, len(text))]
        class_head = text[:text.find('{')] if '{' in text else ''
        for chain_start, body, end in bounds:
            header = text[chain_start:body] if body >= 0 else class_head
            scope = text[body+1:end]
            order = re.search(r'@Order\s*\(\s*(\d+)\s*\)', header)
            order_value = int(order.group(1)) if order else 2147483647
            chain_patterns = []
            dynamic_scope = False
            for matcher in re.finditer(r'\.(?:securityMatchers?|requestMatcher)\s*\(([^)]*)\)', scope):
                values = re.findall(r'''["'](/[^"']*)["']''', matcher.group(1))
                chain_patterns.extend(values)
                if not values: dynamic_scope = True
            conditions = _coverage_conditions(class_head + '\n' + header)
            matches = sorted(list(_AUTHZ_MATCHER.finditer(scope)) +
                             list(_AUTHZ_ANY_REQUEST.finditer(scope)), key=lambda m: m.start())
            for match in matches:
                args = match.groupdict().get('args')
                patterns = re.findall(r'''["'](/[^"']*)["']''', args) if args is not None else ['/**']
                # A dynamic earlier matcher can change the first-match result.
                if not patterns: patterns = ['<dynamic>']
                verbs = re.findall(r'HttpMethod\s*\.\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)', args or '')
                decision_open = body+1+match.end()-1
                decision_end = _closing(text, decision_open)
                decision_text = text[body+1+match.start():decision_end+1] if decision_end >= 0 else match.group(0)
                for pattern in patterns:
                    for verb in verbs or ['ANY']:
                        position = body+1+match.start()
                        item = CoverageRoutePolicy(rel, module_map.get(path, os.path.abspath(root)),
                            position, text.count('\n', 0, position)+1, pattern,
                            match.group('decision'), verb)
                        item.chain = (rel, chain_start)
                        item.order = order_value
                        item.chain_patterns = chain_patterns
                        item.dynamic_scope = dynamic_scope
                        item.conditions = conditions
                        item.permissions = _coverage_permissions(decision_text, item.decision.lower())
                        item.expression = decision_text
                        policies.append(item)
    return policies


def _coverage_policy_for_route(policies, route, http_method='ANY', module=''):
    selected = _coverage_selected_policies(policies, route, http_method, module)
    if not selected:
        return 'unknown', ['No statically resolvable SecurityFilterChain rule matched the route']
    evidence = [f'{p.http_method} {getattr(p, "expression", p.pattern + "." + p.decision + "()")} at '
                f'{p.file}:{p.line}' + (' [' + '; '.join(p.conditions) + ']'
                    if getattr(p, 'conditions', []) else '') for p in selected]
    decisions = {p.decision.lower() for p in selected}
    ambiguous = len(selected) > 1 or any(p.pattern == '<dynamic>' or
                                       getattr(p, 'dynamic_scope', False) for p in selected)
    if ambiguous or len(decisions) != 1:
        return 'unknown', ['Ambiguous chain order, activation, or dynamic matcher'] + evidence
    return next(iter(decisions)), evidence


def _coverage_method_key(method: ProjectMethodSummary) -> str:
    return f"{method.rel}:{method.class_name}.{method.name}:{method.line}"


def _coverage_method_label(method: ProjectMethodSummary) -> str:
    return f"{method.class_name}.{method.name}()"


def _coverage_reachable_methods(entry, methods, module_map=None):
    return _coverage_graph(entry, methods, module_map)[0]


def _coverage_entry_methods(
        methods: Sequence[ProjectMethodSummary],
        loaded: Dict[str, Tuple[List[str], List[Method]]]) -> List[Tuple[ProjectMethodSummary, str, str, str]]:
    """Return (method, kind, HTTP method, route/consumer label) entry points."""
    entries: List[Tuple[ProjectMethodSummary, str, str, str]] = []
    for method in methods:
        text = "\n".join(loaded[method.path][0])
        prefix = _coverage_class_prefix(text, method)
        for mapping in _COVERAGE_MAPPING.finditer(method.header):
            annotation, arguments = mapping.group(1), mapping.group(2) or ""
            for http_method in _coverage_http_methods(annotation, arguments):
                for route in _coverage_annotation_paths(arguments):
                    entries.append((method, "HTTP", http_method,
                                    _coverage_join_route(prefix, route)))
        for listener in _COVERAGE_CONSUMER.finditer(method.header):
            values = re.findall(r"[\x22\x27]([^\x22\x27]+)[\x22\x27]",
                                listener.group(2) or "")
            destination = values[0] if values else "<dynamic destination>"
            entries.append((method, listener.group(1), "", destination))
        if _COVERAGE_SCHEDULED.search(method.header):
            schedule = _COVERAGE_SCHEDULED.search(method.header)
            entries.append((method, "Scheduled", "", (schedule.group(1) or "<dynamic schedule>").strip()))
    return entries


def _coverage_finding(
        entry: CoverageEntry, method: ProjectMethodSummary, rid: str, severity: str,
        note: str, raw_map: Dict[str, List[str]], context_radius: int) -> Finding:
    raw_lines = raw_map.get(method.path, [])
    code = raw_lines[method.line - 1].strip() if 1 <= method.line <= len(raw_lines) else method.header.strip()[:200]
    return Finding(
        file=method.rel, line=method.line, rule_id=rid,
        rule_name=RULE_BY_ID[rid].name, severity=severity, status="COVERAGE",
        code=code, method=method.name, note=note, fix=RULE_BY_ID[rid].fix,
        flow=entry.flow, fingerprint=fingerprint(method.rel, rid, entry.entrypoint + code),
        context=context_lines(raw_lines, method.line, context_radius))


def _analyze_security_coverage_base(
        loaded: Dict[str, Tuple[List[str], List[Method]]], raw_map: Dict[str, List[str]],
        root: str, context_radius: int = CONTEXT_RADIUS,
        enabled: Optional[Set[str]] = None,
        build_files: Sequence[str] = ()) -> Tuple[List[CoverageEntry], List[Finding]]:
    """Build a control matrix and emit findings for uncovered processing paths."""
    coverage_rule_ids = {
        "SECURITY-CONTROL-COVERAGE-GAP", "AUTHZ-SENSITIVE-SINK-UNCOVERED",
        "AUTHZ-PARTIALLY-PROTECTED-SERVICE", "TENANT-CONTEXT-LOST",
        "VALIDATION-COVERAGE-GAP", "RATE-LIMIT-COVERAGE-GAP", "AUDIT-COVERAGE-GAP"}
    allowed = coverage_rule_ids if enabled is None else coverage_rule_ids & enabled
    methods = _project_method_summaries(loaded, root)
    module_map = _coverage_module_map(loaded, root, build_files)
    policies = _coverage_route_policies(loaded, root, module_map)
    method_security_by_module: Dict[str, bool] = {}
    for path, (lines, _) in loaded.items():
        module = module_map.get(path, os.path.abspath(root))
        method_security_by_module[module] = (
            method_security_by_module.get(module, False) or
            bool(_METHOD_SECURITY_ENABLE.search("\n".join(lines))))
    entries: List[CoverageEntry] = []
    findings: List[Finding] = []
    reached_by_entry: Dict[str, Set[str]] = {}

    for entry_method, kind, http_method, target in _coverage_entry_methods(methods, loaded):
        entry_module = module_map.get(entry_method.path, os.path.abspath(root))
        reached = _coverage_reachable_methods(entry_method, methods, module_map)
        reached_by_entry_key = f"{_coverage_method_key(entry_method)}|{kind}|{http_method}|{target}"
        reached_by_entry[reached_by_entry_key] = set(reached)
        scopes = [method.header + "\n" + method.body for method, _ in reached.values()]
        combined = "\n".join(scopes)
        sink_items: List[Tuple[ProjectMethodSummary, str, List[str]]] = []
        for method, path in reached.values():
            for sink in _COVERAGE_SENSITIVE_SINK.finditer(method.body):
                sink_name = (sink.group(2) or sink.group(3) or "sensitive operation") + "()"
                sink_items.append((method, sink_name, path))
        sink_methods = {
            _coverage_method_key(method): method for method, _, _ in sink_items}
        sink_scopes = [method.header + "\n" + method.body
                       for method in sink_methods.values()]
        sensitive = bool(sink_items)
        mutating = (http_method in {"POST", "PUT", "PATCH", "DELETE"} or
                    bool(_COVERAGE_MUTATING_SINK.search(combined)))
        entry_scope = entry_method.header + "\n" + entry_method.body
        def active_method_authz(scope: str) -> bool:
            return bool(
                _COVERAGE_PROGRAMMATIC_AUTHZ.search(_structure_mask(scope)) or
                (_COVERAGE_METHOD_AUTHZ_ANNOTATION.search(scope) and
                 method_security_by_module.get(entry_module, False)))
        has_method_authz = (active_method_authz(entry_scope) or
                            bool(sink_scopes and all(active_method_authz(scope)
                                                     for scope in sink_scopes)))
        has_authn = bool(
            _COVERAGE_AUTHN.search(entry_scope) or
            (sink_scopes and all(_COVERAGE_AUTHN.search(scope) for scope in sink_scopes)))
        permit_all = bool(re.search(r"@PermitAll\b", entry_scope))

        policy, policy_evidence = ("not_required", ["Non-HTTP entry point"])
        if kind == "HTTP":
            policy, policy_evidence = _coverage_policy_for_route(
                policies, target, http_method, entry_module)

        controls: Dict[str, str] = {}
        evidence: Dict[str, List[str]] = {}
        if kind == "Scheduled":
            controls["authentication"] = "NOT_REQUIRED"
            evidence["authentication"] = ["Scheduled jobs have no interactive caller"]
        elif not sensitive:
            controls["authentication"] = "NOT_REQUIRED"
            evidence["authentication"] = ["No authentication-sensitive sink was identified"]
        elif has_authn or has_method_authz:
            controls["authentication"] = "COVERED"
            evidence["authentication"] = ["Principal/authentication or method-security evidence is present"]
        elif kind != "HTTP":
            controls["authentication"] = "UNKNOWN"
            evidence["authentication"] = ["Broker authentication is external to the scanned source"]
        elif policy == "denyall":
            controls["authentication"] = "NOT_REQUIRED"
            evidence["authentication"] = policy_evidence + ["The route is denied before processing"]
        elif policy in {"permitall", "anonymous"} or permit_all:
            controls["authentication"] = "MISSING" if sensitive else "NOT_REQUIRED"
            evidence["authentication"] = policy_evidence
        elif policy in {"authenticated", "fullyauthenticated", "rememberme",
                        "hasrole", "hasanyrole", "hasauthority",
                        "hasanyauthority", "access"}:
            controls["authentication"] = "COVERED"
            evidence["authentication"] = policy_evidence
        else:
            controls["authentication"] = "UNKNOWN"
            evidence["authentication"] = policy_evidence

        if not sensitive or kind == "Scheduled":
            controls["authorization"] = "NOT_REQUIRED"
            evidence["authorization"] = ["No authorization-sensitive sink was identified"]
        elif policy == "denyall":
            controls["authorization"] = "COVERED"
            evidence["authorization"] = policy_evidence + ["The route is explicitly denied"]
        elif has_method_authz:
            controls["authorization"] = "COVERED"
            evidence["authorization"] = ["Method-level authorization is present on the reachable path"]
        elif policy in {"hasrole", "hasanyrole", "hasauthority", "hasanyauthority", "access"}:
            controls["authorization"] = "COVERED"
            evidence["authorization"] = policy_evidence
        elif policy == "unknown":
            controls["authorization"] = "UNKNOWN"
            evidence["authorization"] = policy_evidence
        else:
            controls["authorization"] = "MISSING"
            evidence["authorization"] = policy_evidence + ["Sensitive sink requires an explicit authorization decision"]

        tenant_required = bool(_TENANT_NAME.search(target) or
                               re.search(r"\b(?:tenant|organization|workspace|realm)(?:Id|ID|_id)?\b",
                                         entry_scope, re.I))
        if not tenant_required:
            controls["tenant"] = "NOT_REQUIRED"
            evidence["tenant"] = ["No tenant-scoped input was identified"]
        elif (_COVERAGE_TENANT_BINDING.search(entry_scope) or
              (sink_scopes and all(_COVERAGE_TENANT_BINDING.search(scope)
                                   for scope in sink_scopes))):
            controls["tenant"] = "COVERED"
            evidence["tenant"] = ["Authenticated tenant/owner binding is visible on the path"]
        else:
            controls["tenant"] = "MISSING"
            evidence["tenant"] = ["Tenant-scoped input has no authenticated-tenant binding"]

        validation_required = bool(re.search(r"@RequestBody\b", entry_scope) or
                                   kind in {"KafkaListener", "RabbitListener", "JmsListener"})
        if not validation_required:
            controls["validation"] = "NOT_REQUIRED"
            evidence["validation"] = ["No structured request/message payload was identified"]
        elif (_COVERAGE_VALIDATION.search(entry_scope) or
              (sink_scopes and all(_COVERAGE_VALIDATION.search(scope)
                                   for scope in sink_scopes))):
            controls["validation"] = "COVERED"
            evidence["validation"] = ["Bean or programmatic validation is visible on the path"]
        else:
            controls["validation"] = "MISSING"
            evidence["validation"] = ["External payload reaches processing without visible validation"]

        abuse_sensitive = bool(_COVERAGE_ABUSE_ROUTE.search(target + " " + entry_method.name))
        if not abuse_sensitive:
            controls["rate_limit"] = "NOT_REQUIRED"
            evidence["rate_limit"] = ["Entry point is not classified as authentication/token abuse-sensitive"]
        elif (_COVERAGE_RATE_LIMIT.search(entry_scope) or
              (sink_scopes and all(_COVERAGE_RATE_LIMIT.search(scope)
                                   for scope in sink_scopes))):
            controls["rate_limit"] = "COVERED"
            evidence["rate_limit"] = ["Rate-limit, throttling, or lockout evidence is present"]
        else:
            controls["rate_limit"] = "MISSING"
            evidence["rate_limit"] = ["Abuse-sensitive entry point has no visible throttling or lockout"]

        audit_required = sensitive and mutating
        if not audit_required:
            controls["audit"] = "NOT_REQUIRED"
            evidence["audit"] = ["No sensitive state change was identified"]
        elif (_COVERAGE_AUDIT.search(entry_scope) or
              (sink_scopes and all(_COVERAGE_AUDIT.search(scope)
                                   for scope in sink_scopes))):
            controls["audit"] = "COVERED"
            evidence["audit"] = ["Structured security audit evidence is present"]
        else:
            controls["audit"] = "MISSING"
            evidence["audit"] = ["Sensitive state change has no visible structured audit event"]

        if sink_items:
            terminal_method, _, terminal_path = max(sink_items, key=lambda item: len(item[2]))
            flow = terminal_path
        else:
            terminal_method = entry_method
            flow = [_coverage_method_label(entry_method)]
        entrypoint = (f"{http_method} {target}" if kind == "HTTP"
                      else f"{kind} {target}")
        coverage = CoverageEntry(
            entrypoint=entrypoint, kind=kind, file=entry_method.rel,
            line=entry_method.line, method=entry_method.name,
            http_method=http_method, route=target if kind == "HTTP" else "",
            controls=controls, evidence=evidence, flow=flow,
            sensitive_sinks=sorted({item[1] for item in sink_items}))
        entries.append(coverage)

        missing_map = {
            "authorization": ("AUTHZ-SENSITIVE-SINK-UNCOVERED", "HIGH"),
            "tenant": ("TENANT-CONTEXT-LOST", "HIGH"),
            "validation": ("VALIDATION-COVERAGE-GAP", "MEDIUM"),
            "rate_limit": ("RATE-LIMIT-COVERAGE-GAP", "HIGH"),
            "audit": ("AUDIT-COVERAGE-GAP", "MEDIUM"),
        }
        for control, (rid, severity) in missing_map.items():
            if controls.get(control) != "MISSING" or rid not in allowed:
                continue
            note = (f"{entrypoint} has missing {control.replace('_', ' ')} coverage. "
                    f"Path: {' -> '.join(flow)}. " + " ".join(evidence[control]))
            findings.append(_coverage_finding(
                coverage, terminal_method, rid, severity, note, raw_map, context_radius))
        unresolved = [name for name, status in controls.items() if status == "UNKNOWN"]
        if controls.get("authentication") == "MISSING":
            unresolved.insert(0, "authentication (missing)")
        if unresolved and "SECURITY-CONTROL-COVERAGE-GAP" in allowed:
            note = (f"{entrypoint} has unresolved control coverage: {', '.join(unresolved)}. "
                    f"Path: {' -> '.join(flow)}.")
            findings.append(_coverage_finding(
                coverage, entry_method, "SECURITY-CONTROL-COVERAGE-GAP",
                "HIGH" if controls.get("authentication") == "MISSING" else "MEDIUM",
                note, raw_map, context_radius))

    # A service protected only by some callers is a fragile trust boundary.
    authz_by_method: Dict[str, List[Tuple[CoverageEntry, str]]] = {}
    entry_lookup = {
        f"{_coverage_method_key(method)}|{kind}|{http_method}|{target}": coverage
        for (method, kind, http_method, target), coverage in zip(
            _coverage_entry_methods(methods, loaded), entries)}
    entry_method_keys = {
        _coverage_method_key(method)
        for method, _, _, _ in _coverage_entry_methods(methods, loaded)}
    for key, reached_keys in reached_by_entry.items():
        coverage = entry_lookup.get(key)
        if not coverage:
            continue
        for method_key in reached_keys:
            authz_by_method.setdefault(method_key, []).append(
                (coverage, coverage.controls.get("authorization", "UNKNOWN")))
    method_lookup = {_coverage_method_key(method): method for method in methods}
    if "AUTHZ-PARTIALLY-PROTECTED-SERVICE" in allowed:
        for method_key, callers in authz_by_method.items():
            states = {state for _, state in callers}
            if "COVERED" not in states or "MISSING" not in states:
                continue
            method = method_lookup[method_key]
            if method_key in entry_method_keys:
                continue
            affected = sorted({coverage.entrypoint for coverage, _ in callers})
            exemplar = next(coverage for coverage, state in callers if state == "MISSING")
            note = (f"{_coverage_method_label(method)} is reached from both authorized and "
                    f"unauthorized entry points: {', '.join(affected)}.")
            findings.append(_coverage_finding(
                exemplar, method, "AUTHZ-PARTIALLY-PROTECTED-SERVICE", "HIGH",
                note, raw_map, context_radius))

    return sorted(entries, key=lambda item: (item.kind, item.entrypoint, item.file, item.line)), findings


_METHOD_SECURITY_ENABLE = re.compile(
    r"@EnableMethodSecurity\b|@EnableGlobalMethodSecurity\s*\([^)]*prePostEnabled\s*=\s*true",
    re.I)
_PREPOST_ANNOTATION = re.compile(r"@(?:PreAuthorize|PostAuthorize)\b", re.I)


def analyze_preauthorize_without_method_security(
        loaded: Dict[str, Tuple[List[str], List[Method]]], raw_map: Dict[str, List[str]],
        root: str, build_files: Sequence[str],
        context_radius: int = CONTEXT_RADIUS) -> List[Finding]:
    """Correlate method-security annotations with module-level enablement."""
    out: List[Finding] = []
    for files in _group_loaded_by_module(loaded, root, build_files).values():
        if any(_METHOD_SECURITY_ENABLE.search(source) for _, source in files):
            continue
        for path, source in files:
            for match in _PREPOST_ANNOTATION.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                rel = os.path.relpath(path, root) if root else path
                raw_lines = raw_map.get(path, source.splitlines())
                code = raw_lines[line - 1].strip() if 1 <= line <= len(raw_lines) else match.group(0)
                finding = Finding(
                    file=rel, line=line,
                    rule_id="AUTHZ-PREAUTHORIZE-WITHOUT-METHODSECURITY",
                    rule_name=RULE_BY_ID["AUTHZ-PREAUTHORIZE-WITHOUT-METHODSECURITY"].name,
                    severity="HIGH", status="ANTIPATTERN", code=code,
                    note="Method authorization annotation found, but neither @EnableMethodSecurity "
                         "nor legacy prePostEnabled=true is present in this module; the annotation may be ignored.",
                    fix=FIX_METHOD_SEC,
                    fingerprint=fingerprint(rel, "AUTHZ-PREAUTHORIZE-WITHOUT-METHODSECURITY", code),
                    context=context_lines(raw_lines, line, context_radius))
                if not finding_suppressed(raw_lines, finding):
                    out.append(finding)
    return out


_LOGOUT_ENTRY = re.compile(
    r"\.logout\s*\(|@(?:Post|Delete)Mapping\s*\([^)]*[\x22\x27][^\x22\x27]*logout|"
    r"\b(?:logout|signOut)\s*\([^;{]*\)\s*(?:throws[^\{]*)?\{", re.I)
_REFRESH_REVOKE = re.compile(
    r"(?:refreshToken\w*|refreshTokens?|tokenFamily)[^;\n]{0,120}"
    r"\.(?:delete|deleteAll|revoke|invalidate|blacklist|remove)\s*\(|"
    r"(?:delete|revoke|invalidate|blacklist|remove)[^;\n]{0,100}refresh", re.I)


def analyze_refresh_logout_revocation(
        loaded: Dict[str, Tuple[List[str], List[Method]]], raw_map: Dict[str, List[str]],
        root: str, build_files: Sequence[str],
        context_radius: int = CONTEXT_RADIUS) -> List[Finding]:
    """Find modules with refresh tokens and logout but no visible revocation."""
    out: List[Finding] = []
    for files in _group_loaded_by_module(loaded, root, build_files).values():
        combined = "\n".join(source for _, source in files)
        if not _REFRESH_FLOW.search(combined) or _REFRESH_REVOKE.search(combined):
            continue
        for path, source in files:
            match = _LOGOUT_ENTRY.search(source)
            if not match:
                continue
            line = source.count("\n", 0, match.start()) + 1
            rel = os.path.relpath(path, root) if root else path
            raw_lines = raw_map.get(path, source.splitlines())
            code = raw_lines[line - 1].strip() if 1 <= line <= len(raw_lines) else match.group(0)
            finding = Finding(
                file=rel, line=line, rule_id="REFRESH-TOKEN-NO-REVOKE-ON-LOGOUT",
                rule_name=RULE_BY_ID["REFRESH-TOKEN-NO-REVOKE-ON-LOGOUT"].name,
                severity="HIGH", status="REVIEW", code=code,
                note="This module handles refresh tokens and logout, but no refresh-token "
                     "delete/revoke/invalidate operation is visible.",
                fix=FIX_REFRESH_LIFECYCLE,
                fingerprint=fingerprint(rel, "REFRESH-TOKEN-NO-REVOKE-ON-LOGOUT", code),
                context=context_lines(raw_lines, line, context_radius))
            if not finding_suppressed(raw_lines, finding):
                out.append(finding)
            break
    return out


_CSRF_DISABLED_RE = re.compile(
    r"\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|"
    r"\.csrf\s*\(\s*(?:(?:c|csrf)\s*->\s*(?:c|csrf)\s*\.\s*disable\s*\(\s*\)|"
    r"AbstractHttpConfigurer\s*::\s*disable)\s*\)", re.I)
_JWT_COOKIE_RE = re.compile(
    r"@CookieValue\s*\([^)]*(?:jwt|access[_-]?token|auth[_-]?token|bearer|refresh[_-]?token)|"
    r"@CookieValue\b[^;\n]{0,160}\b(?:jwt|accessToken|authToken|refreshToken)\b|"
    r"(?:new\s+Cookie|ResponseCookie\s*\.\s*from|\.getCookie)\s*\(\s*"
    r"[\x22\x27](?:jwt|access[_-]?token|auth[_-]?token|bearer|refresh[_-]?token)[\x22\x27]|"
    r"getCookies\s*\(\s*\)[\s\S]{0,500}?\b(?:jwt|accessToken|authToken|refreshToken)\b",
    re.I)


def analyze_csrf_disabled_jwt_cookie(loaded: Dict[str, Tuple[List[str], List[Method]]],
                                     raw_map: Dict[str, List[str]], root: str,
                                     build_files: Sequence[str],
                                     context_radius: int = CONTEXT_RADIUS) -> List[Finding]:
    """Correlate JWT auth cookies and disabled CSRF within the same build module."""
    module_dirs = sorted({os.path.abspath(os.path.dirname(path)) for path in build_files},
                         key=len, reverse=True)

    def module_for(path: str) -> str:
        absolute = os.path.abspath(path)
        for directory in module_dirs:
            try:
                if os.path.commonpath((absolute, directory)) == directory:
                    return directory
            except ValueError:
                pass
        return os.path.abspath(root)

    grouped: Dict[str, List[Tuple[str, str]]] = {}
    for path, (lines, _) in loaded.items():
        grouped.setdefault(module_for(path), []).append((path, "\n".join(lines)))

    out: List[Finding] = []
    for files in grouped.values():
        cookie_evidence: Optional[Tuple[str, int]] = None
        for path, source in files:
            match = _JWT_COOKIE_RE.search(source)
            if match:
                cookie_evidence = (path, source.count("\n", 0, match.start()) + 1)
                break
        if not cookie_evidence:
            continue
        cookie_path, cookie_line = cookie_evidence
        cookie_rel = os.path.relpath(cookie_path, root) if root else cookie_path
        for path, source in files:
            for match in _CSRF_DISABLED_RE.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                rel = os.path.relpath(path, root) if root else path
                raw_lines = raw_map.get(path, source.splitlines())
                code = raw_lines[line - 1].strip() if 1 <= line <= len(raw_lines) else match.group(0)
                flow = [f"JWT auth cookie ({cookie_rel}:{cookie_line})", "CSRF disabled"]
                finding = Finding(
                    file=rel, line=line,
                    rule_id="SpringSecurityCheck-CSRF-DISABLED-JWT-COOKIE",
                    rule_name=RULE_BY_ID["SpringSecurityCheck-CSRF-DISABLED-JWT-COOKIE"].name,
                    severity="CRITICAL", status="ANTIPATTERN", code=code,
                    note="JWT authentication appears to use a cookie in the same module while "
                         "CSRF is disabled. Browsers attach the cookie automatically, so a "
                         "cross-site request can execute authenticated actions.",
                    fix=FIX_CSRF_JWT_COOKIE, flow=flow,
                    fingerprint=fingerprint(rel, "SpringSecurityCheck-CSRF-DISABLED-JWT-COOKIE", code),
                    context=context_lines(raw_lines, line, context_radius))
                if not finding_suppressed(raw_lines, finding):
                    out.append(finding)
    return out


def dedupe_findings(findings: Sequence[Finding]) -> List[Finding]:
    """Collapse overlapping heuristic/structured findings at the same sink."""
    by_sink: Dict[Tuple[str, int, str], Finding] = {}
    order: List[Tuple[str, int, str]] = []
    for finding in findings:
        key = (finding.file, finding.line, finding.rule_id,
               finding.fingerprint if finding.rule_id.startswith(("DEP-", "OSV-")) else "")
        if key not in by_sink:
            order.append(key)
            by_sink[key] = finding
        elif finding.flow and not by_sink[key].flow:
            by_sink[key] = finding
    return [by_sink[key] for key in order]


def analyze_web_source(rel: str, text: str, context_radius: int = CONTEXT_RADIUS, method_bounds=None) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()
    def add(rid, pos, note, fix, severity="MEDIUM"):
        line = text.count("\n", 0, pos) + 1
        code = lines[line - 1].strip()
        findings.append(Finding(file=rel, line=line, rule_id=rid,
            rule_name=EXTRA_RULE_META[rid][1], severity=severity, status="REVIEW",
            code=code, note=note, fix=fix, fingerprint=fingerprint(rel, rid, code),
            context=context_lines(lines, line, context_radius)))
    def add_hardened(rid, pos, note):
        # Positive counterpart to add(): the construct at `pos` IS the good
        # practice, so it is always HARDENED/INFO (shown via --show-hardened),
        # never a REVIEW/VULNERABLE finding.
        line = text.count("\n", 0, pos) + 1
        code = lines[line - 1].strip()
        findings.append(Finding(file=rel, line=line, rule_id=rid,
            rule_name=EXTRA_RULE_META[rid][1], severity="INFO", status="HARDENED",
            code=code, note=note, fix="", fingerprint=fingerprint(rel, rid, code),
            context=context_lines(lines, line, context_radius)))
    for start, op, close, begin, end in (
            _web_methods(text) if method_bounds is None else method_bounds):
        signature = text[start:begin]
        params = text[op + 1:close]
        body = text[begin + 1:end]
        method_name_m = re.search(r"([A-Za-z_$][\w$]*)\s*$", text[start:op])
        method_name = method_name_m.group(1) if method_name_m else "?"
        for offset, param in _parameter_parts(params):
            request_body = re.search(r"@(?:[\w]+\.)*RequestBody\b", param)
            if not request_body:
                continue
            has_valid = bool(re.search(r"@(?:[\w]+\.)*(?:Valid|Validated)\b", param))
            plain = re.sub(r"@(?:[\w]+\.)*\w+(?:\s*\([^)]*\))?", "", param).strip()
            if re.search(r"\b(?:String|int|long|boolean|double|float|byte|short|char|Integer|Long|Boolean|Double|Float|Byte|Short|Character|Map|List|Set|Collection)\b", plain):
                continue
            type_and_name = plain.rsplit(None, 1)
            detail = f" Parameter `{type_and_name[1]}` of type `{type_and_name[0]}`" if len(type_and_name) == 2 else ""
            detail += f" in `{method_name}(...)`."
            if has_valid:
                add_hardened("HARDEN-REQUEST-BODY-VALID", op + 1 + offset + request_body.start(),
                    "DTO request parameter has Bean Validation enforced via @Valid/@Validated." + detail)
                continue
            add("SRC-REQUEST-BODY-NO-VALID", op + 1 + offset + request_body.start(),
                "DTO request parameter has no @Valid/@Validated on this parameter." + detail +
                " Bean constraints may not run; manual validation and actual DTO constraints "
                "are not resolved.",
                "Annotate the DTO parameter with @Valid or @Validated and configure a Bean Validation provider.")
        # Track string parameters and local string assignments, not arbitrary DTOs.
        string_names = set(re.findall(r"\bString\s+(\w+)|\b(\w+)\s*:\s*String\b", params + "\n" + body))
        strings = {name for pair in string_names for name in pair if name}
        html_response = bool(re.search(r'text/html|TEXT_HTML', signature + body))
        non_html_response = bool(re.search(r'application/json|APPLICATION_JSON|text/plain|TEXT_PLAIN', signature + body)) and not html_response
        sinks = []
        masked_body = _structure_mask(body)
        for match in re.finditer(r"\.getWriter\s*\(\s*\)\s*\.\s*(?:write|print|println)\s*\(", body):
            sinks.append((match, "SRC-XSS-WRITER"))
        for match in re.finditer(r"\bResponseEntity\s*\.\s*ok\s*\(", body):
            sinks.append((match, "SRC-XSS-RESPONSE-ENTITY"))
        # Support ResponseEntity.ok().contentType(TEXT_HTML).body(value).
        for match in re.finditer(r"\bResponseEntity\s*\.\s*ok\s*\(\s*\)[^;]*?\.body\s*\(", body):
            sinks.append((match, "SRC-XSS-RESPONSE-ENTITY"))
        for match, rid in sinks:
            opening = match.end() - 1
            closing = _closing(masked_body, opening)
            if closing < 0:
                continue
            expr = body[opening + 1:closing].strip()
            if not expr or not _structure_mask(expr).strip() or non_html_response:
                continue
            if _encoded_expression(expr, body[:match.start()]):
                continue
            if rid == "SRC-XSS-RESPONSE-ENTITY" and not (re.search(r'"|getParameter\s*\(', expr) or any(re.search(r"\b" + re.escape(n) + r"\b", expr) for n in strings)):
                continue
            add(rid, begin + 1 + match.start(),
                "Dynamic response output without recognized HTML encoding. Verify content type and whether input is attacker-controlled; "
                "a response sink alone does not prove XSS.",
                "Use context-appropriate HTML encoding, or return a structured JSON DTO with the correct content type.",
                "HIGH" if html_response else "MEDIUM")
        if html_response and ("@ResponseBody" in signature or "@RestController" in text[:start]):
            for match in re.finditer(r"\breturn\s+([^;]+);", body):
                expr = match.group(1).strip()
                if "ResponseEntity" in expr or not _structure_mask(expr).strip() or _encoded_expression(expr, body[:match.start()]):
                    continue
                if not (re.search(r'"|getParameter\s*\(', expr) or any(re.search(r"\b" + re.escape(n) + r"\b", expr) for n in strings)):
                    continue
                add("SRC-XSS-RESPONSE-BODY", begin + 1 + match.start(),
                    "Dynamic HTML response body; untrusted values require HTML output encoding. Data flow is not proven.",
                    "Encode untrusted text for its HTML context or render through an escaping template.", "HIGH")
    return findings


def _encoded_expression(expr: str, preceding: str) -> bool:
    encoder = r"(?:HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml[34]?|Encode\.forHtml(?:Content)?)"
    def entire_encoded(value):
        m = re.match(encoder + r"\s*\(", value.strip())
        return bool(m and _closing(_structure_mask(value.strip()), m.end() - 1) == len(value.strip()) - 1)
    if entire_encoded(expr):
        return True
    if re.fullmatch(r"\w+", expr):
        assignments = list(re.finditer(r"\b" + re.escape(expr) + r"\s*(\+?=)\s*([^;]+);", preceding))
        # Every reaching assignment must be encoded. Trusting only the last
        # textual assignment misses unsafe conditional branches.
        if assignments:
            return all(m.group(1) == "=" and entire_encoded(m.group(2))
                       for m in assignments)
    return False


def analyze_template(rel: str, text: str, context_radius: int = CONTEXT_RADIUS) -> List[Finding]:
    clean = re.sub(r"<!--[\s\S]*?-->", lambda m: re.sub(r"[^\n]", " ", m.group()), text)
    findings = []
    source_lines = text.splitlines()
    for m in re.finditer(r'''\b(?:th:utext|data-th-utext)\s*=\s*(["'])([\s\S]*?)\1''', clean):
        if not re.search(r"[$*#]\{|\[\[|\[\(", m.group(2)):
            continue
        line = clean.count("\n", 0, m.start()) + 1
        code = source_lines[line - 1].strip()
        rid = "TPL-XSS-TH-UTEXT"
        findings.append(Finding(file=rel, line=line, rule_id=rid, rule_name=EXTRA_RULE_META[rid][1],
            severity="MEDIUM", status="REVIEW", code=code,
            note="Dynamic unescaped template output. Verify trust/sanitization of the model value; this is not proof of exploitability.",
            fix="Use th:text for ordinary text; sanitize intentionally supported HTML with an appropriate allowlist.",
            fingerprint=fingerprint(rel, rid, code), context=context_lines(source_lines, line, context_radius)))
    return findings



# Necessary literals for the built-in patterns; never sufficient to report a finding.
_RULE_LITERAL_HINTS = {'ANTI-ACCESS-ALL': ('ACCESS_EXTERNAL_',),
 'ANTI-DOCTYPE-ON': ('disallow-doctype-decl',),
 'ANTI-EXPAND-ENTITIES-ON': ('setExpand',),
 'ANTI-EXT-ENTITIES-ON': ('external-',
                          'IS_SUPPORTING_EXTERNAL_ENTITIES',
                          'setProcessExternalEntities'),
 'ANTI-SPRING-DTD-ON': ('setSupportDtd',),
 'ANTI-STAX-DTD-ON': ('SUPPORT_DTD', 'supportDTD'),
 'ANTI-XINCLUDE-ON': ('setXIncludeAware',),
 'DESER-XMLDECODER': ('XMLDecoder',),
 'DESER-XSTREAM': ('XStream', 'fromXML'),
 'HARDEN-BCRYPT-STRENGTH': ('BCryptPasswordEncoder',),
 'HARDEN-BEAN-VALIDATION-CONSTRAINT': ('@',),
 'HARDEN-COOKIE-HTTPONLY': ('HttpOnly',),
 'HARDEN-COOKIE-SECURE-FLAG': ('secure',),
 'HARDEN-CORS-EXPLICIT-ORIGIN': ('https://',),
 'HARDEN-CSP-CONFIGURED': ('contentSecurityPolicy', 'ContentSecurityPolicyHeaderWriter'),
 'HARDEN-HSTS-CONFIGURED': ('httpStrictTransportSecurity', 'HstsHeaderWriter'),
 'HARDEN-METHOD-SECURITY': ('EnableMethodSecurity', 'PreAuthorize', 'PostAuthorize'),
 'HARDEN-PREPARED-STATEMENT': ('prepareStatement',),
 'HARDEN-SECURE-RANDOM': ('SecureRandom',),
 'HARDEN-STRONG-PW-ENCODER': ('Argon2PasswordEncoder',
                              'SCryptPasswordEncoder',
                              'Pbkdf2PasswordEncoder'),
 'HARDEN-XXE-DISALLOW-DOCTYPE': ('disallow-doctype-decl',),
 'OAUTH2-REACTIVE-JWK-REMOTE': ('NimbusReactiveJwtDecoder',),
 'OAUTH2-REACTIVE-NO-ISSUER': ('NimbusReactiveJwtDecoder',),
 'RSOCKET-NO-PAYLOAD-AUTH': ('EnableRSocketSecurity',),
 'RSOCKET-PERMITALL': ('authorizePayload', 'RSocketSecurity'),
 'SRC-CMD-EXEC': ('Runtime', 'ProcessBuilder'),
 'SRC-CORS-ORIGIN-REFLECTION': ('Access-Control-Allow-Origin',),
 'SRC-CRLF-HEADER-INJECTION': ('addHeader', 'setHeader'),
 'SRC-CROSSORIGIN-BARE': ('@CrossOrigin',),
 'SRC-CRYPTO-WEAK-CIPHER': ('Cipher',),
 'SRC-CRYPTO-WEAK-HASH': ('MessageDigest',),
 'SRC-CRYPTO-WEAK-KEY': ('KeyPairGenerator', 'RSA', 'DSA'),
 'SRC-CRYPTO-WEAK-RANDOM': ('Random',),
 'SRC-DECOMPRESSION-BOMB': ('InputStream',),
 'SRC-DESER-JACKSON-DEFTYPING': ('enableDefaultTyping', 'activateDefaultTyping'),
 'SRC-DESER-NATIVE': ('ObjectInputStream',),
 'SRC-DESER-SNAKEYAML': ('Yaml',),
 'SRC-DIRECTORY-LISTING': ('Files', 'DirectoryStream'),
 'SRC-EXCEPTION-SWALLOW': ('catch',),
 'SRC-FASTJSON-PARSE': ('JSON',),
 'SRC-HOSTNAME-VERIFIER': ('setHostnameVerifier',),
 'SRC-IDOR': ('Mapping',),
 'SRC-JNDI-LOOKUP': ('lookup',),
 'SRC-LOG-SENSITIVE': ('log',),
 'SRC-MASS-ASSIGNMENT': ('ModelAttribute', 'WebDataBinder'),
 'SRC-OPEN-REDIRECT': ('sendRedirect', 'RedirectView', 'redirect:'),
 'SRC-PATH-TRAVERSAL': ('File', 'Paths'),
 'SRC-REFLECTION-INJECTION': ('Class', 'getDeclaredMethod', 'getMethod', 'invoke', 'Constructor'),
 'SRC-REGEX-INJECTION': ('Pattern', 'matches', 'replaceAll', 'replaceFirst', 'split'),
 'SRC-RESOURCE-EXHAUSTION': ('MultipartFile', 'readAllBytes'),
 'SRC-SENSITIVE-URL': ('sendRedirect', 'URI', 'URL', 'queryParam'),
 'SRC-SPEL-DYNAMIC': ('parseExpression',),
 'SRC-SQLI-CONCAT': ('createQuery',
                     'createNativeQuery',
                     'prepareStatement',
                     'prepareCall',
                     'execute'),
 'SRC-SSRF': ('URL',
              'URI',
              'RestTemplate',
              'getForObject',
              'getForEntity',
              'postForObject',
              'postForEntity',
              'exchange',
              'WebClient',
              'HttpClient'),
 'SRC-TIMING-SECRET-COMPARE': ('equals',),
 'SRC-XPATH-INJECTION': ('XPath',),
 'SpringSecurityCheck-ACTUATOR-EXPOSED': ('web.exposure.include',),
 'SpringSecurityCheck-ACTUATOR-SHUTDOWN': ('management.endpoint.shutdown.enabled',),
 'SpringSecurityCheck-ANONYMOUS-ACCESS': ('anonymous', 'AnonymousAuthenticationFilter'),
 'SpringSecurityCheck-ANTI-DISABLE-SEC': ('@EnableWebSecurity',),
 'SpringSecurityCheck-ANTI-STACKTRACE': ('server.error.include-',),
 'SpringSecurityCheck-ANY-REQUEST-PERMIT': ('anyRequest',),
 'SpringSecurityCheck-BCRYPT-LOW-COST': ('BCryptPasswordEncoder',),
 'SpringSecurityCheck-CORS-ALL-METHODS': ('setAllowedMethods', 'addAllowedMethod'),
 'SpringSecurityCheck-CORS-WILDCARD': ('setAllowedOrigins',),
 'SpringSecurityCheck-CORS-WILDCARD-CRED': ('setAllowedOrigins',),
 'SpringSecurityCheck-CROSS-ORIGIN-BROAD': ('@CrossOrigin',),
 'SpringSecurityCheck-CSRF-DISABLED': ('csrf',),
 'SpringSecurityCheck-CSRF-IGNORE-PATH': ('ignoringRequestMatchers', 'ignoringAntMatchers'),
 'SpringSecurityCheck-EMPTY-PASSWORD-AUTH': ('setHideUserNotFoundExceptions', 'setPasswordEncoder'),
 'SpringSecurityCheck-HARDCODED-BCRYPT-COST-0': ('BCryptPasswordEncoder',),
 'SpringSecurityCheck-HEADERS-DISABLED': ('headers', 'frameOptions'),
 'SpringSecurityCheck-HTTP-BASIC-PROD': ('httpBasic',),
 'SpringSecurityCheck-IGNORE-REQUEST-MATCHER': ('ignoring',),
 'SpringSecurityCheck-INMEMORY-USERS': ('InMemoryUserDetailsManager', 'withDefaultPasswordEncoder'),
 'JWT-PARSE-NO-VERIFY': ('Jwts', 'parserBuilder', 'parser', 'parse'),
 'SRC-CRYPTO-RSA-NO-OAEP': ('Cipher', 'RSA'),
 'SRC-CRYPTO-STATIC-IV': ('GCMParameterSpec', 'IvParameterSpec'),
 'SRC-RANDOM-PREDICTABLE-SEED': ('SecureRandom', 'setSeed'),
 'SRC-SSTI-VIEW-NAME': ('redirect:', 'forward:', 'return'),
 'SpringSecurityCheck-PREAUTH-ON-INTERFACE': ('@PreAuthorize', '@PostAuthorize', '@Secured'),
 'SpringSecurityCheck-REGEX-NO-DOTALL': ('RegexRequestMatcher',),
 'HARDEN-CRYPTO-GCM-RANDOM-IV': ('SecureRandom', 'nextBytes', 'GCMParameterSpec'),
 'HARDEN-RSA-OAEP': ('Cipher', 'RSA', 'OAEP'),
 'JWT-AUDIENCE-VALIDATION': ('Jwts', 'parserBuilder', 'parser'),
 'JWT-CLOCK-SKEW': ('JwtTimestampValidator', 'ClockSkew', 'allowedClockSkew'),
 'JWT-REFRESH-TOKEN-REUSE': ('refreshToken', 'localStorage'),
 'JWT-SENSITIVE-CLAIMS': ('claim',),
 'HARDEN-JWT-AUDIENCE-VALIDATION': ('requireAudience', 'JwtClaimValidator'),
 'HARDEN-JWT-CLOCK-SKEW': ('JwtTimestampValidator',),
 'HARDEN-OAUTH2-PKCE-ENABLED': ('PkceParameterNames', 'requireProofKey', 'codeChallenge'),
 'HARDEN-OAUTH2-STATE-PARAM': ('state', 'UUID', 'random'),
 'OAUTH2-INTROSPECTION-HTTP': ('introspectionUri', 'introspection-uri'),
 'OAUTH2-PKCE-PLAIN': ('code_challenge_method', 'codeChallengeMethod', 'CodeChallengeMethod', 'PkceMethod'),
 'OAUTH2-REDIRECT-PREFIX-MATCH': ('redirect', 'callback', 'returnUrl'),
 'OAUTH2-TOKEN-QUERY-PARAM': ('access_token', 'ACCESS_TOKEN'),
 'OAUTH2-CLIENT-SECRET-URL': ('client_secret', 'CLIENT_SECRET'),
 'OAUTH2-SCOPE-HARDCODED': ('scopes', 'scope'),
 'OAUTH2-STATE-MISSING': ('OAuth2AuthorizationRequest',),
 'OAUTH2-TOKEN-LOGGING': ('log', 'logger', 'LOG', 'LOGGER'),
 'OIDC-NONCE-MISSING': ('OidcUserService', 'OidcAuthorizationCodeAuthenticationProvider'),
 'JWT-BLANK-SECRET': ('signWith',),
 'JWT-JWKS-HTTP': ('withJwkSetUri', 'JWKSet', 'http://'),
 'JWE-ZIP-ENABLED': ('setCompressionAlgorithm', 'compressionAlgorithm', 'customParam', 'zip'),
 'CERT-PRIVATE-KEY-COMMITTED': ('PRIVATE KEY',),
 'JWT-NO-AUDIENCE': ('Jwts',),
 'JWT-NO-EXPIRY': ('Jwts',),
 'JWT-NO-SUBJECT-VALIDATION': ('Jwts', 'parserBuilder', 'parser'),
 'JWT-NULL-SIGNATURE': ('parse', 'ignoreSignature', 'NONE'),
 'JWT-WEAK-KEY-SIZE': ('KeyPairGenerator', 'initialize'),
 'HARDEN-JWT-EXPIRY-SET': ('expiration', 'setExpiration'),
 'HARDEN-JWT-ISSUER-VALIDATION': ('requireIssuer', 'JwtValidators', 'JwtClaimValidator'),
 'HARDEN-JWT-SECRET-FROM-ENV': ('@Value', 'getenv', 'getProperty', 'vault'),
 'HARDEN-JWT-STRONG-ALG': ('signWith', 'SignatureAlgorithm', 'RS256', 'ES256', 'PS256'),
 'SpringSecurityCheck-JWT-ALG-CONFUSION': ('Jwts',),
 'SpringSecurityCheck-JWT-LONG-EXPIRY': ('expiration',),
 'SpringSecurityCheck-JWT-NO-ISSUER': ('NimbusJwtDecoder', 'Jwts'),
 'SpringSecurityCheck-NO-ACCESS-DENIED-HANDLER': ('exceptionHandling',),
 'SpringSecurityCheck-NO-CSP': ('headers',),
 'SpringSecurityCheck-NO-CTX-CLEAR': ('logout',),
 'SpringSecurityCheck-NO-FAILURE-HANDLER': ('formLogin',),
 'SpringSecurityCheck-NO-HSTS': ('headers',),
 'SpringSecurityCheck-NO-HTTPS': ('authorizeHttpRequests', 'authorizeRequests'),
 'SpringSecurityCheck-NO-METHOD-SECURITY': ('@EnableWebSecurity',),
 'SpringSecurityCheck-NULL-USERDETAILS': ('loadUserByUsername',),
 'SpringSecurityCheck-OAUTH2-NO-PKCE': ('ClientAuthenticationMethod',),
 'SpringSecurityCheck-PERMIT-ALL-BROAD': ('permitAll',),
 'SpringSecurityCheck-REMEMBERME-LONG': ('tokenValiditySeconds',),
 'SpringSecurityCheck-REMEMBERME-NO-KEY': ('rememberMe',),
 'SpringSecurityCheck-SAML-NO-SIGN': ('wantAssertionsSigned', 'authnRequestsSigned'),
 'SpringSecurityCheck-SESSION-FIXATION': ('sessionManagement',),
 'SpringSecurityCheck-SESSION-STATELESS-NO-JWT': ('SessionCreationPolicy',),
 'TLS-OLD-PROTOCOL': ('SSLContext', 'setEnabledProtocols', 'setProtocols', 'protocol'),
 'TLS-WEAK-CIPHER': ('TLS_', 'SSL_'),
 'TLS-TRUST-SELF-SIGNED': ('TrustSelfSignedStrategy', 'loadTrustMaterial'),
 'TLS-REVOCATION-DISABLED': ('setRevocationEnabled', 'checkRevocation', 'ocsp.enable'),
 'TLS-MTLS-WANT-INSTEAD-OF-NEED': ('setWantClientAuth', 'setNeedClientAuth', 'ClientAuth'),
 'TLS-KEYSTORE-PASSWORD-HARDCODED': ('keyStorePassword', 'keystorePassword', 'setKeyStorePassword'),
 'TLS-TRUSTSTORE-PASSWORD-HARDCODED': ('trustStorePassword', 'truststorePassword', 'setTrustStorePassword'),
 'WEBFLUX-CSRF-DISABLED': ('csrf',),
 'WEBFLUX-FN-SENSITIVE-ROUTE': ('route',),
 'WEBFLUX-PERMITALL': ('authorizeExchange',),
 'X509-AUTH-CONFIG-REVIEW': ('x509',),
 'XXE-DIGESTER': ('Digester',),
 'XXE-DOM': ('DocumentBuilderFactory',),
 'XXE-DOM4J': ('SAXReader', 'DocumentHelper'),
 'XXE-JACKSON-XML': ('XmlMapper', 'XmlFactory'),
 'XXE-JAXB': ('createUnmarshaller', 'JAXB'),
 'XXE-JDOM': ('SAXBuilder',),
 'XXE-PULLPARSER': ('XmlPullParserFactory', 'newPullParser'),
 'XXE-SAX': ('SAXParserFactory', 'XMLReaderFactory'),
 'XXE-SCHEMA': ('SchemaFactory', 'newValidator'),
 'XXE-SOAP': ('MessageFactory', 'SOAPMessage'),
 'XXE-SPRING-OXM': ('Jaxb2Marshaller',),
 'XXE-STAX': ('XMLInputFactory',),
 'XXE-TRANSFORMER': ('TransformerFactory',),
 'XXE-XERCES-DIRECT': ('DOMParser', 'SAXParser'),
 'XXE-XPATH': ('XPathFactory',)}
_RULE_PREFILTERS = {
    rule.pattern: tuple(value.lower() if rule.pattern.flags & re.I else value
                        for value in _RULE_LITERAL_HINTS[rule.rid])
    for rule in RULES if rule.rid in _RULE_LITERAL_HINTS
}


def _version_key(value):
    """Conservative Maven ordering subset; unresolved syntax returns None."""
    if not value or re.search(r"SNAPSHOT|[${}\[\](),+*]|latest", value, re.I):
        return None
    match = re.fullmatch(r"(\d+(?:\.\d+)*)(?:[.-]?(alpha|beta|milestone|rc|cr|a|b|m|final|ga|release|sp)(\d*))?", value, re.I)
    if not match:
        return None
    numbers = [int(n) for n in match.group(1).split('.')]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    qualifier = (match.group(2) or '').lower()
    rank = {'alpha': -4, 'a': -4, 'beta': -3, 'b': -3,
            'milestone': -2, 'm': -2, 'rc': -1, 'cr': -1,
            '': 0, 'final': 0, 'ga': 0, 'release': 0, 'sp': 1}[qualifier]
    return numbers, rank, int(match.group(3) or 0)


def _compare_versions(left, right):
    a, b = _version_key(left), _version_key(right)
    if a is None or b is None:
        return None
    width = max(len(a[0]), len(b[0]))
    ka = (tuple(a[0] + [0] * (width-len(a[0]))), a[1], a[2])
    kb = (tuple(b[0] + [0] * (width-len(b[0]))), b[1], b[2])
    return (ka > kb) - (ka < kb)


def is_older(found: str, fixed: str) -> Optional[bool]:
    comparison = _compare_versions(found, fixed)
    return None if comparison is None else comparison < 0


def _pom_tree(content):
    import xml.etree.ElementTree as ET
    if re.search(r'<!DOCTYPE|<!ENTITY', content, re.I):
        raise ValueError('DTD/entity declarations are not supported in build metadata')
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError('Invalid Maven XML: ' + str(exc))
    for node in root.iter():
        node.tag = node.tag.rsplit('}', 1)[-1]
    return root


def _xml_value(node, tag):
    return (node.findtext(tag) or '').strip()


def _expand_version(value, properties):
    if not value:
        return None
    seen = set()
    for _ in range(20):
        if value in seen:
            return None
        seen.add(value)
        if not re.search(r'\$\{[^}]+\}|\$[A-Za-z_]\w*', value):
            return value
        def replace(match):
            key = match.group(1) or match.group(2)
            return properties.get(key, match.group())
        value = re.sub(r'\$\{([^}]+)\}|\$([A-Za-z_]\w*)', replace, value)
    return None


def _maven_parent_pom_path(pom_path: str, content: str) -> Optional[str]:
    try:
        project = _pom_tree(content)
    except ValueError:
        return None
    parent = project.find('parent')
    if parent is None:
        return None
    relative = parent.find('relativePath')
    if relative is not None and not (relative.text or '').strip():
        return None
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(pom_path)),
                                       (relative.text or '').strip() if relative is not None else '../pom.xml'))
    if os.path.isdir(path):
        path = os.path.join(path, 'pom.xml')
    try:
        with open(path, encoding='utf-8') as handle:
            candidate = _pom_tree(handle.read())
    except (OSError, ValueError):
        return None
    for tag in ('groupId', 'artifactId', 'version'):
        expected = _xml_value(parent, tag)
        actual = _xml_value(candidate, tag)
        if not actual and tag != 'artifactId':
            actual = _xml_value(candidate, 'parent/' + tag)
        if not expected or expected != actual:
            return None
    return path


def maven_resolution_context(pom_path: str, content: str, max_depth: int = 20):
    """Local matching parent chain only; managed versions use full coordinates."""
    chain, seen = [], set()
    current = os.path.abspath(pom_path)
    for _ in range(max_depth):
        if current in seen:
            break
        seen.add(current)
        try:
            node = _pom_tree(content)
        except ValueError:
            break
        chain.append(node)
        parent = _maven_parent_pom_path(current, content)
        if parent is None:
            break
        try:
            with open(parent, encoding='utf-8') as handle:
                content = handle.read()
        except OSError:
            break
        current = parent
    properties, managed = {}, {}
    for node in reversed(chain):
        props = node.find('properties')
        if props is not None:
            properties.update({child.tag: (child.text or '').strip() for child in props})
        for tag in ('groupId', 'version'):
            value = _xml_value(node, tag) or _xml_value(node, 'parent/' + tag)
            if value:
                properties['project.' + tag] = value
                properties['pom.' + tag] = value
        for dependency in node.findall('dependencyManagement/dependencies/dependency'):
            if _xml_value(dependency, 'type') not in ('', 'jar') or _xml_value(dependency, 'classifier'):
                continue
            group = _expand_version(_xml_value(dependency, 'groupId'), properties)
            artifact = _expand_version(_xml_value(dependency, 'artifactId'), properties)
            version = _xml_value(dependency, 'version')
            if group and artifact and version:
                managed[group + ':' + artifact] = version
    return properties, managed


@dataclass
class DependencyDeclaration:
    group: str
    artifact: str
    version: Optional[str]
    line: int = 1
    reason: str = ''


def _dependency_declarations(path, content):
    """Shared static inventory for built-in rules and OSV. No build execution."""
    rows = []
    def line_of(artifact):
        return next((i for i, line in enumerate(content.splitlines(), 1) if artifact in line), 1)
    if path.endswith('.xml'):
        try:
            project = _pom_tree(content)
        except ValueError as exc:
            return [DependencyDeclaration('', 'build-metadata', None, reason=str(exc))]
        props, managed = maven_resolution_context(path, content)
        entries = [(d, '') for d in project.findall('dependencies/dependency')]
        entries += [(d, 'Profile activation was not evaluated; resolve the effective build.')
                    for d in project.findall('profiles/profile/dependencies/dependency')]
        for entry, reason in entries:
            group = _expand_version(_xml_value(entry, 'groupId'), props) or _xml_value(entry, 'groupId')
            artifact = _expand_version(_xml_value(entry, 'artifactId'), props) or _xml_value(entry, 'artifactId')
            if not artifact:
                continue
            version = _xml_value(entry, 'version')
            if not version and _xml_value(entry, 'type') in ('', 'jar') and not _xml_value(entry, 'classifier'):
                version = managed.get(group + ':' + artifact)
            rows.append(DependencyDeclaration(group, artifact, _expand_version(version, props), line_of(artifact), reason))
    elif path.endswith('.toml'):
        versions = dict(TOML_VERSION.findall(content))
        for alias, group, artifact, ref in TOML_LIB.findall(content):
            entry = re.search(r'^' + re.escape(alias) + r'\s*=\s*\{([^}]+)\}', content, re.M)
            is_reference = entry and re.search(r'\bversion\.ref\s*=', entry.group(1))
            rows.append(DependencyDeclaration(group, artifact, versions.get(ref) if is_reference else ref, line_of(alias)))
    else:
        props = {}
        try:
            with open(os.path.join(os.path.dirname(path), 'gradle.properties'), encoding='utf-8') as handle:
                for line in handle:
                    match = re.match(r'\s*([\w.-]+)\s*=\s*(.*?)\s*$', line)
                    if match:
                        props[match.group(1)] = match.group(2)
        except OSError:
            pass
        clean = strip_comments(content)
        for match in re.finditer(r'''(?:\b(?:val|var|def)\s+)?\b([\w]+)\s*=\s*['"]([^'"\n]+)['"]''', clean):
            props[match.group(1)] = match.group(2)
        coordinate = re.compile(r'''['"]([\w.-]+):([\w.-]+)(?::([^'"\r\n]+))?['"]''')
        constrained = {(g, a): v for g, a, v in GRADLE_VERSION_BLOCK.findall(clean)}
        for match in coordinate.finditer(clean):
            group, artifact, version = match.groups()
            version = constrained.get((group, artifact), version)
            rows.append(DependencyDeclaration(group, artifact, _expand_version(version, props), clean.count('\n', 0, match.start())+1))
        for match in re.finditer(r'''group\s*[:=]\s*['"]([\w.-]+)['"]\s*,\s*name\s*[:=]\s*['"]([\w.-]+)['"]\s*,\s*version\s*[:=]\s*['"]([^'"]+)['"]''', clean):
            group, artifact, version = match.groups()
            rows.append(DependencyDeclaration(group, artifact, _expand_version(version, props), clean.count('\n', 0, match.start())+1))
    unique = {}
    for row in rows:
        unique.setdefault((row.group, row.artifact, row.version, row.reason), row)
    return list(unique.values())


def _dependency_assessment(rule, version):
    """Return status/note/fix; legacy thresholds are review hints, not CVEs."""
    if _version_key(version) is None:
        return 'REVIEW', 'Version unresolved or unsupported; vulnerability assessment incomplete.', 'Resolve the exact effective version and query OSV.'
    if rule.artifact == 'log4j-core':
        ranges = [('2.0-beta9', '2.3.1'), ('2.4', '2.12.2'), ('2.13', '2.15')]
        affected = any(_compare_versions(version, lo) >= 0 and _compare_versions(version, hi) < 0 for lo, hi in ranges)
        if affected:
            return 'VULNERABLE', ('Version is affected by CVE-2021-44228 (Log4Shell); assess runtime configuration. '
                    'https://logging.apache.org/security.html#CVE-2021-44228'), 'Use a supported Log4j release; this CVE was fixed in 2.3.1, 2.12.2 and 2.15.0 on the respective branches. These are not a complete security baseline.'
        return None
    if rule.artifact == 'spring-data-mongodb':
        affected = (_compare_versions(version, '3.3.5') < 0 or
                    (_compare_versions(version, '3.4') >= 0 and _compare_versions(version, '3.4.1') < 0))
        if affected:
            return 'VULNERABLE', ('Version is affected by CVE-2022-22980; exploitation additionally requires unsafe SpEL parameter placeholders in @Query/@Aggregation. '
                    'https://spring.io/security/cve-2022-22980/'), 'This CVE was fixed in 3.3.5 and 3.4.1 on the respective branches. Prefer a supported release and check other advisories.'
        return None
    if rule.fixed and is_older(version, rule.fixed) is False:
        return None
    return 'REVIEW', rule.note, 'Verify exact package/version against current advisories (for example --check-osv); no universal safe version is asserted.'


def _dependency_findings(rows, path, root):
    rel = os.path.relpath(path, root) if root else path
    out = []
    for row in rows:
        rules = [r for r in DEP_RULES if row.artifact == r.artifact and row.group in r.groups]
        uncertain = not _coordinate_known(row.group, row.artifact) or _version_key(row.version) is None or bool(row.reason)
        if uncertain:
            rules = [None]
        for rule in rules:
            assessment = (('REVIEW', row.reason or 'Exact package/version unresolved or unsupported; vulnerability assessment incomplete.',
                           'Resolve the effective dependency graph with --resolve-deps, then check current advisories.')
                          if rule is None else _dependency_assessment(rule, row.version))
            if assessment is None:
                continue
            status, note, fix = assessment
            identity = '{}:{}:{}'.format(row.group or '?', row.artifact, row.version or '?')
            rid = 'DEP-UNRESOLVED' if rule is None else 'DEP-' + row.artifact.upper()
            severity = rule.severity if rule else 'MEDIUM'
            out.append(Finding(file=rel, line=row.line, rule_id=rid, rule_name='Dependency ' + identity,
                               severity=severity, status=status, code=identity, note=note, fix=fix,
                               fingerprint=fingerprint(rel, rid, identity)))
    return out


def analyze_build_file(path: str, root: str) -> List[Finding]:
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            content = handle.read()
    except OSError as exc:
        return _dependency_findings([DependencyDeclaration('', 'build-metadata', None, reason=str(exc))], path, root)
    return _dependency_findings(_dependency_declarations(path, content), path, root)


def _osv_ecosystem_triples(path: str, content: str):
    # Preserve exact ecosystem versions. Static unknowns remain visible as REVIEW.
    return [(r.group, r.artifact, r.version) for r in _dependency_declarations(path, content)
            if _coordinate_known(r.group, r.artifact) and not r.reason and _osv_version_is_concrete(r.version)]


def _coordinate_known(group, artifact):
    return bool(re.fullmatch(r'[\w.-]+', group or '') and re.fullmatch(r'[\w.-]+', artifact or ''))


def _osv_version_is_concrete(version):
    return bool(version and re.match(r'\d', version) and
                not re.search(r'SNAPSHOT|[${}\[\](),+*\s]|latest', version, re.I))


def _normalize_maven_version_for_osv(version: str) -> str:
    """OSV receives the exact published version, including RC/SP qualifiers."""
    return version


def analyze_resolved_dependencies(dependencies, root):
    out = []
    for item in dependencies:
        out.extend(_dependency_findings([DependencyDeclaration(item.group, item.artifact, item.version)], item.build_file, root))
    return out


def osv_query_online(group, artifact, version, timeout=8.0, retries=3):
    """Exact-version OSV query with pagination and bounded per-page retries."""
    import urllib.request
    import urllib.error
    import time
    payload = {'version': version, 'package': {'name': group + ':' + artifact, 'ecosystem': 'Maven'}}
    vulnerabilities, tokens = [], set()
    for _ in range(1000):
        response = None
        for attempt in range(max(1, retries)):
            request = urllib.request.Request(OSV_API_QUERY_URL, data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json', 'User-Agent': 'JSpringGuard/' + VERSION}, method='POST')
            try:
                with urllib.request.urlopen(request, timeout=timeout) as handle:
                    response = json.loads(handle.read().decode('utf-8'))
                if not isinstance(response, dict) or not isinstance(response.get('vulns', []), list):
                    return None, 'Invalid OSV response schema'
                break
            except urllib.error.HTTPError as exc:
                error = 'HTTP {}'.format(exc.code)
                if exc.code != 429 and not 500 <= exc.code < 600:
                    return None, error
            except (OSError, ValueError) as exc:
                error = '{}: {}'.format(type(exc).__name__, exc)
            if attempt + 1 < retries:
                time.sleep(1.5 * 2 ** attempt)
        if response is None:
            return None, error
        vulnerabilities.extend(response.get('vulns', []))
        token = response.get('next_page_token')
        if not token:
            return {'vulns': vulnerabilities}, None
        if not isinstance(token, str) or token in tokens:
            return None, 'Invalid or repeated OSV pagination token'
        tokens.add(token)
        payload['page_token'] = token
    return None, 'OSV pagination limit exceeded; result incomplete'


_DEP_GROUPS = {'castor-xml': ('org.codehaus.castor',),
 'commons-collections': ('commons-collections',),
 'commons-collections4': ('org.apache.commons',),
 'commons-digester': ('commons-digester',),
 'commons-text': ('org.apache.commons',),
 'dom4j': ('dom4j', 'org.dom4j'),
 'h2': ('com.h2database',),
 'jackson-databind': ('com.fasterxml.jackson.core',),
 'java-jwt': ('com.auth0',),
 'jdom': ('org.jdom', 'jdom'),
 'jdom2': ('org.jdom',),
 'jjwt': ('io.jsonwebtoken',),
 'jjwt-api': ('io.jsonwebtoken',),
 'log4j-core': ('org.apache.logging.log4j',),
 'logback-classic': ('ch.qos.logback',),
 'logback-core': ('ch.qos.logback',),
 'nimbus-jose-jwt': ('com.nimbusds',),
 'snakeyaml': ('org.yaml',),
 'spring-boot-autoconfigure': ('org.springframework.boot',),
 'spring-boot-starter-security': ('org.springframework.boot',),
 'spring-cloud-gateway': ('org.springframework.cloud',),
 'spring-cloud-netflix-eureka-client': ('org.springframework.cloud',),
 'spring-data-mongodb': ('org.springframework.data',),
 'spring-data-rest-core': ('org.springframework.data',),
 'spring-oxm': ('org.springframework',),
 'spring-security-config': ('org.springframework.security',),
 'spring-security-core': ('org.springframework.security',),
 'spring-security-web': ('org.springframework.security',),
 'spring-webmvc': ('org.springframework',),
 'tomcat-embed-core': ('org.apache.tomcat.embed',),
 'woodstox-core': ('com.fasterxml.woodstox',),
 'xercesImpl': ('xerces',),
 'xstream': ('com.thoughtworks.xstream',)}
for _dependency_rule in DEP_RULES:
    _dependency_rule.groups = _DEP_GROUPS[_dependency_rule.artifact]



def print_osv_summary(finding_count, occurrences, unique, failed, first_error,
                      diagnostics, offline=False, database=False):
    successful = unique - failed
    mode = "database assessments" if database else ("cache lookups" if offline else "queries")
    print(f"[osv] Checked {successful}/{unique} unique package(s) successfully; "
          f"{finding_count} advisory finding(s).", file=sys.stderr)
    if occurrences != unique:
        print(f"[osv] {occurrences} package occurrence(s) across build files.", file=sys.stderr)
    if failed:
        print(f"[osv] WARNING: {failed}/{unique} {mode} failed. "
              f"First error: {first_error}", file=sys.stderr)
    unresolved = diagnostics.get("unresolved", [])
    if unresolved:
        print(f"[osv] WARNING: {len(unresolved)} unresolved dependency declaration(s) skipped; "
              "no OSV query was sent for these entries.", file=sys.stderr)
        for item in unresolved:
            print(f"[osv]   - {item}", file=sys.stderr)
        advice = ("Supply exact versions in build metadata or review manually; "
                  "the local advisory database cannot resolve a remote BOM." if database else
                  "Resolve exact coordinates/versions (for trusted projects, --resolve-deps) or review manually.")
        print("[osv] " + advice, file=sys.stderr)
    if failed or unresolved:
        print("[osv] Coverage is INCOMPLETE; the findings do not describe a complete scan.", file=sys.stderr)


OSV_MAVEN_DUMP_URL = 'https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip'
OSV_DB_SCHEMA = '1'


def build_osv_database(archive, destination, source='local archive', source_modified=''):
    """Import full Maven advisories and atomically replace the local SQLite DB."""
    import sqlite3
    import zipfile
    from datetime import datetime, timezone
    destination = os.path.abspath(destination)
    if os.path.abspath(archive) == destination:
        raise ValueError('Archive and database paths must differ')
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    digest = hashlib.sha256()
    with open(archive, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    fd, temporary = tempfile.mkstemp(prefix='.osv-build-', suffix='.sqlite', dir=parent)
    os.close(fd)
    connection = None
    try:
        connection = sqlite3.connect(temporary)
        connection.executescript('''
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE advisories (id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE packages (name TEXT NOT NULL, advisory_id TEXT NOT NULL,
                                   PRIMARY KEY(name, advisory_id));
        ''')
        count = 0
        with zipfile.ZipFile(archive) as bundle:
            for entry in bundle.infolist():
                if entry.is_dir() or not entry.filename.endswith('.json'):
                    continue
                record = json.loads(bundle.read(entry))
                if not isinstance(record, dict) or not isinstance(record.get('id'), str):
                    raise ValueError('Invalid OSV record: ' + entry.filename)
                affected = record.get('affected', [])
                if not isinstance(affected, list):
                    raise ValueError('Invalid affected list: ' + entry.filename)
                names = {a.get('package', {}).get('name') for a in affected
                         if a.get('package', {}).get('ecosystem') == 'Maven'}
                if not names and not record.get('withdrawn'):
                    continue
                if any(not isinstance(name, str) or not name for name in names):
                    raise ValueError('Invalid Maven package name: ' + entry.filename)
                connection.execute('INSERT INTO advisories VALUES (?, ?)',
                    (record['id'], json.dumps(record, ensure_ascii=False, separators=(',', ':'))))
                connection.executemany('INSERT INTO packages VALUES (?, ?)',
                    [(name, record['id']) for name in names])
                count += 1
        package_count = connection.execute('SELECT count(DISTINCT name) FROM packages').fetchone()[0]
        if not count or not package_count:
            raise ValueError('Archive contains no usable Maven advisory database')
        metadata = {'schema': OSV_DB_SCHEMA, 'ecosystem': 'Maven', 'source': source,
                    'source_modified': source_modified, 'archive_sha256': digest.hexdigest(),
                    'created_utc': datetime.now(timezone.utc).isoformat(),
                    'advisories': str(count), 'packages': str(package_count)}
        connection.executemany('INSERT INTO metadata VALUES (?, ?)', metadata.items())
        connection.commit()
        if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Database integrity check failed')
        connection.close()
        connection = None
        os.replace(temporary, destination)
        return metadata
    finally:
        if connection is not None:
            connection.close()
        if os.path.exists(temporary):
            os.unlink(temporary)


def update_osv_database(destination):
    """Explicit online operation; ordinary offline scans never call this."""
    import urllib.request
    fd, archive = tempfile.mkstemp(prefix='osv-maven-', suffix='.zip')
    os.close(fd)
    try:
        with urllib.request.urlopen(OSV_MAVEN_DUMP_URL, timeout=60) as response:
            expected = response.headers.get('Content-Length')
            modified = response.headers.get('Last-Modified', '')
            total = 0
            with open(archive, 'wb') as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    total += len(chunk)
            if expected and total != int(expected):
                raise ValueError('Incomplete OSV archive download; existing database preserved')
        return build_osv_database(archive, destination, OSV_MAVEN_DUMP_URL, modified)
    finally:
        if os.path.exists(archive):
            os.unlink(archive)


def _offline_interval_contains(version, introduced, ending=None, inclusive=False):
    lower = 1 if introduced == '0' else _compare_versions(version, introduced)
    upper = -1 if ending is None else _compare_versions(version, ending)
    if lower is not None and lower < 0:
        return False
    if upper is not None and (upper > 0 or (upper == 0 and not inclusive)):
        return False
    if lower is None or upper is None:
        return None
    return True


def _offline_affected(version, affected):
    """OSV union of explicit versions and ranges, with an unknown result."""
    if version in affected.get('versions', []):
        return True
    unknown = False
    ranges = affected.get('ranges', [])
    for item in ranges:
        if item.get('type') != 'ECOSYSTEM':
            unknown = True
            continue
        introduced = None
        events = item.get('events', [])
        if not events:
            unknown = True
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                unknown = True
                continue
            kind, value = next(iter(event.items()))
            if kind == 'introduced':
                if introduced is not None:
                    unknown = True
                introduced = value
            elif kind in ('fixed', 'last_affected', 'limit') and introduced is not None:
                answer = _offline_interval_contains(version, introduced, value, kind == 'last_affected')
                if answer is True:
                    return True
                unknown |= answer is None
                introduced = None
            else:
                unknown = True
        if introduced is not None:
            answer = _offline_interval_contains(version, introduced)
            if answer is True:
                return True
            unknown |= answer is None
    if unknown or (not ranges and not affected.get('versions')):
        return None
    return False


class OfflineOsvDatabase:
    """Read-only indexed lookup of a complete local Maven snapshot."""
    def __init__(self, path):
        import sqlite3
        from pathlib import Path
        self.connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
        try:
            self.metadata = dict(self.connection.execute('SELECT key, value FROM metadata'))
            if self.metadata.get('schema') != OSV_DB_SCHEMA or self.metadata.get('ecosystem') != 'Maven':
                raise ValueError('Unsupported offline database schema/ecosystem')
            self.connection.execute('SELECT name, advisory_id FROM packages LIMIT 1')
            self.connection.execute('SELECT id, data FROM advisories LIMIT 1')
        except Exception:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def query(self, group, artifact, version):
        name = group + ':' + artifact
        matches, uncertain = [], []
        for identifier, encoded in self.connection.execute(
                'SELECT a.id, a.data FROM advisories a JOIN packages p ON p.advisory_id=a.id WHERE p.name=?', (name,)):
            record = json.loads(encoded)
            if record.get('withdrawn'):
                continue
            answers = [_offline_affected(version, item) for item in record.get('affected', [])
                       if item.get('package', {}).get('ecosystem') == 'Maven'
                       and item.get('package', {}).get('name') == name]
            if any(answer is True for answer in answers):
                matches.append(record)
            elif any(answer is None for answer in answers):
                uncertain.append(identifier)
        error = ('Offline version comparison unresolved for ' + ', '.join(uncertain[:5]) +
                 (' ...' if len(uncertain) > 5 else '')) if uncertain else None
        return {'vulns': matches}, error


def offline_database_error_types():
    import sqlite3
    import zipfile
    return (OSError, ValueError, sqlite3.Error, zipfile.BadZipFile, KeyError, TypeError)



COVERAGE_DASHBOARD_HTML = "<div class='coverage-dashboard' id='coverageDashboard'><aside class='coverage-sidebar' aria-label='Security entry points'><input class='coverage-search' id='coverageSearch' type='search' placeholder='Filter entry points…' aria-label='Filter security entry points'><label class='coverage-filter-label' for='coverageFlowFilter'>Reference flow</label><select class='coverage-flow-filter' id='coverageFlowFilter' aria-label='Filter by reference flow'><option value='all'>All entry points</option><option value='has-flow'>Reference flow exists</option><option value='no-flow'>No reference flow</option><option value='sensitive'>Sensitive sink exists</option><option value='unresolved'>Unresolved boundary exists</option><option value='risk'>Prioritized attack path</option></select><div class='coverage-entry-list' id='coverageEntryList'></div></aside><div class='coverage-main'><div class='coverage-overview'><div><h3 id='coverageEntryName'></h3><p id='coverageEntryLocation'></p></div><div class='coverage-overview-actions'><span class='coverage-state COVERED' id='coverageEntryState'></span></div></div><section class='coverage-panel'><div class='coverage-panel-head'><h4>Effective security configuration</h4></div><dl class='coverage-policy' id='coveragePolicy'></dl><div class='coverage-source-links'><button type='button' class='coverage-source-link' id='coveragePolicySource'>Peek configuration source</button></div></section><section class='coverage-panel'><div class='coverage-panel-head'><h4>Reachable processing flow</h4><span class='coverage-subtitle'>Select a node for source details</span></div><div class='coverage-flow' id='coverageFlow'></div></section><section class='coverage-panel coverage-code-panel' aria-labelledby='coverageCodeTitle'><div class='coverage-code-head'><h4 class='coverage-code-title' id='coverageCodeTitle'>Source code preview</h4><span class='coverage-code-location' id='coverageCodeLocation'></span></div><pre class='coverage-code-frame' id='coverageCodeFrame'></pre></section><section class='coverage-panel coverage-reference-panel' aria-labelledby='coverageReferenceTitle'><div class='coverage-panel-head'><h4 id='coverageReferenceTitle'>Find All References</h4><span class='coverage-subtitle' id='coverageReferenceCount'></span></div><div class='coverage-reference-list' id='coverageReferenceList'></div></section><section class='coverage-panel'><div class='coverage-panel-head'><h4>Required security controls</h4><span class='coverage-subtitle'>Select a control for evidence</span></div><div class='coverage-controls' id='coverageControls'></div></section><aside class='coverage-panel coverage-detail coverage-control-decision-panel' id='coverageDetail' aria-live='polite'><div class='coverage-detail-title' id='coverageDetailTitle'></div><div id='coverageDetailBody'></div><div class='coverage-control-triage-editor' id='coverageControlTriage'></div></aside><section class='coverage-panel coverage-flow-triage-panel' aria-labelledby='coverageFlowDecisionTitle'><div class='coverage-panel-head'><div><h4 id='coverageFlowDecisionTitle'>Complete flow triage</h4><p class='coverage-subtitle'>Applies to the complete selected entry-point path.</p></div></div><div class='coverage-flow-triage-fields'><div class='coverage-flow-triage-field'><label for='coverageFlowDecision'>Flow triage status</label><select class='coverage-flow-decision' id='coverageFlowDecision' aria-label='Set complete flow triage status'><option value=''>Open / untriaged</option><option value='confirmed'>Confirmed</option><option value='false-positive'>False Positive</option><option value='accepted-risk'>Accepted Risk</option><option value='fixed'>Fixed</option></select></div><div class='coverage-flow-triage-field'><label for='coverageFlowDecisionNote'>Flow decision note</label><input class='coverage-flow-note' id='coverageFlowDecisionNote' type='text' placeholder='Decision note or evidence…'></div></div></section></div></div>"

COVERAGE_POLICY_TOOLS_HTML = "<div class='coverage-policy-tools'><span class='coverage-policy-tools-title'>Security policy history</span><button class='coverage-policy-action' id='exportPolicySnapshot' type='button'>Export current policy snapshot</button><label class='coverage-policy-action' for='importPolicySnapshot'>Compare previous snapshot<input id='importPolicySnapshot' type='file' accept='application/json,.json' hidden></label></div><section class='coverage-drift' id='coverageDrift' aria-labelledby='coverageDriftTitle'><div class='coverage-drift-head'><h3 id='coverageDriftTitle'>Security policy drift</h3><span class='coverage-drift-summary' id='coverageDriftSummary'></span></div><div class='coverage-drift-list' id='coverageDriftList'></div></section>\n"

COVERAGE_TRIAGE_BAR_HTML = '<div class=\'flow-triage-bar\'><span class=\'flow-triage-count\' id=\'flowTriageCount\'>Triaged <b>0</b> flow controls</span><button class=\'flow-triage-action\' type=\'button\' onclick="document.getElementById(\'importFlowTriage\').click()">Import decisions</button><input id=\'importFlowTriage\' type=\'file\' accept=\'application/json,.json\' hidden></div>\n'

# Security Flow Explorer. All report assets are embedded above; no runtime
# template, JavaScript package, network connection or extra Python package.

def _coverage_source(rel, line, raw_map, root, label='', kind='METHOD', radius=6):
    path = os.path.normpath(os.path.join(root, rel))
    rows = raw_map.get(path)
    if rows is None:
        rows = next((value for key, value in raw_map.items()
                     if os.path.normcase(os.path.abspath(key)) ==
                     os.path.normcase(os.path.abspath(path))), [])
    return {'label': label, 'file': rel.replace('\\', '/'), 'line': line,
            'kind': kind, 'context': [
                {'line': n, 'text': text, 'hit': n == line}
                for n, text in context_lines(rows, line, radius)]}


def _coverage_conditions(text):
    result = []
    names = {'Profile': 'Profile', 'ConditionalOnProperty': 'Property condition',
             'ConditionalOnBean': 'Bean present', 'ConditionalOnMissingBean': 'Bean absent',
             'ConditionalOnExpression': 'Expression', 'Conditional': 'Custom condition'}
    for match in re.finditer(r'@(?:[\w]+\.)*(' + '|'.join(names) + r')\s*\(', text):
        opening = text.index('(', match.start())
        closing = _closing(text, opening)
        if closing >= 0:
            result.append(names[match.group(1)] + ': ' +
                          re.sub(r'\s+', ' ', text[opening+1:closing]).strip())
    return sorted(set(result))


def _coverage_permissions(text, decision=''):
    permissions = []
    for match in re.finditer(r'\b(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\(([^)]*)\)', text, re.I):
        for permission in re.findall(r'''["']([^"']+)["']''', match.group(2)):
            permissions.append(('ROLE_' if 'role' in match.group(1).lower() else '') + permission)
    for match in re.finditer(r'@(?:Secured|RolesAllowed)\s*\(([^)]*)\)', text):
        permissions.extend(re.findall(r'''["']([^"']+)["']''', match.group(1)))
    if decision in {'permitall', 'anonymous'}:
        permissions.append('PUBLIC' if decision == 'permitall' else 'ANONYMOUS')
    elif decision == 'denyall':
        permissions.append('DENIED')
    elif decision in {'authenticated', 'fullyauthenticated', 'rememberme', 'hasrole',
                      'hasanyrole', 'hasauthority', 'hasanyauthority'} or permissions:
        permissions.append('AUTHENTICATED')
    return sorted(set(permissions))




def _coverage_selected_policies(policies, route, http_method, module):
    chains = {}
    for item in policies:
        if module and item.module != module: continue
        chains.setdefault(getattr(item, 'chain', (item.file, 0)), []).append(item)
    candidates = []
    for chain in chains.values():
        first = chain[0]
        patterns = getattr(first, 'chain_patterns', [])
        if patterns and not any(_coverage_pattern_matches(p, route) for p in patterns): continue
        for item in sorted(chain, key=lambda p: p.position):
            if item.http_method in {'ANY', http_method} and (
                    item.pattern == '<dynamic>' or _coverage_pattern_matches(item.pattern, route)):
                candidates.append(item)
                break
        else:
            # A selected chain without an authorization match must not fall
            # through to a lower-priority chain and invent a policy.
            unknown = CoverageRoutePolicy(first.file, first.module, first.position,
                first.line, route, 'unknown', http_method)
            unknown.__dict__.update({k: v for k, v in first.__dict__.items()
                                    if k not in unknown.__dict__})
            candidates.append(unknown)
    candidates.sort(key=lambda p: getattr(p, 'order', 2147483647))
    if not candidates: return []
    chosen = []
    priority = None
    for item in candidates:
        order = getattr(item, 'order', 2147483647)
        if priority is not None and order > priority: break
        chosen.append(item)
        if not getattr(item, 'conditions', []) and not getattr(item, 'dynamic_scope', False):
            priority = order
    return chosen




def _coverage_graph(entry, methods, module_map=None):
    """Bounded call graph: resolve receiver types; retain ambiguous/external boundaries.

    Framework repository calls are terminal sinks. Unsupported reflection, proxy
    dispatch and library implementations are not represented as proven calls.
    """
    module = module_map.get(entry.path, '') if module_map else ''
    available = [m for m in methods if not module_map or module_map.get(m.path, '') == module]
    by_name = {}
    source = {}
    for method in available:
        by_name.setdefault(method.name, []).append(method)
        if method.path not in source:
            try:
                with open(method.path, encoding='utf-8', errors='replace') as handle:
                    source[method.path] = strip_comments(handle.read())
            except OSError: source[method.path] = ''
    reached, unresolved, queue = {}, [], [(entry, [_coverage_method_label(entry)], 0)]
    benign_receivers = {'System', 'Math', 'String', 'Objects', 'Collections', 'List', 'Map',
                        'Set', 'Optional', 'ResponseEntity', 'log', 'logger', 'LOGGER'}
    while queue:
        method, path, depth = queue.pop(0)
        key = _coverage_method_key(method)
        if key in reached: continue
        if len(reached) >= 250:
            unresolved.append('Analysis limit: more than 250 reachable methods')
            break
        reached[key] = (method, path)
        masked = _structure_mask(method.body)
        for call in re.finditer(r'\b(?:(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*)?'
                               r'(?P<name>[A-Za-z_$][\w$]*)\s*\(', masked):
            receiver, name = call.group('receiver') or '', call.group('name')
            if name in {'if','for','while','switch','catch','synchronized','super','this','return','new'}: continue
            # Skip constructor and chained suffix matches already represented by
            # the root call; chained dispatch cannot be reconstructed reliably.
            before = masked[max(0,call.start()-5):call.start()]
            if re.search(r'new\s*$', before): continue
            candidates = by_name.get(name, [])
            if receiver in {'', 'this'}:
                candidates = [m for m in candidates if m.class_name == method.class_name]
            else:
                declaration = re.search(r'\b([A-Z][\w$]*)(?:\s*<[^;=(){}]+>)?\s+' +
                                        re.escape(receiver) + r'\b', source.get(method.path,''))
                receiver_type = declaration.group(1) if declaration else receiver
                direct = [m for m in candidates if m.class_name.lower() == receiver_type.lower()]
                implementations = [m for m in candidates if re.search(
                    r'\bclass\s+'+re.escape(m.class_name)+r'\b[^{}]*\b(?:implements|extends)\s+'
                    r'[^{}]*\b'+re.escape(receiver_type)+r'\b',source.get(m.path,''))]
                candidates = direct or implementations
            label = ' -> '.join(path + [(receiver+'.' if receiver else '')+name+'()'])
            location = f' [{method.rel}:{method.line}]'
            if len(candidates) == 1 and depth < 8:
                callee = candidates[0]
                queue.append((callee,path+[_coverage_method_label(callee)],depth+1))
            elif candidates:
                unresolved.append(label+location+(' (depth limit)' if depth >= 8 else ' (ambiguous target)'))
            elif receiver and receiver not in benign_receivers:
                call_text = method.body[call.start():call.end()]
                if _COVERAGE_SENSITIVE_SINK.search(call_text): continue
                # Field/injected collaborators and sensitive dynamic operations
                # remain review boundaries; value-object accessors are omitted.
                declared = re.search(r'\b[A-Z][\w$]*(?:\s*<[^;={}]+>)?\s+'+re.escape(receiver)+r'\b',
                                     source.get(method.path,''))
                if (declared and not name.startswith(('get','is','to','equals','hashCode'))) or re.search(
                        r'(service|gateway|client|adapter|port|handler|processor|manager)$',receiver,re.I) or name in {'invoke','loadClass'}:
                    unresolved.append(label+location)
    return reached, sorted(set(unresolved))




def coverage_attack_paths(entries):
    paths = []
    for index, entry in enumerate(entries):
        if not entry.sensitive_sinks and not entry.unresolved_calls: continue
        missing = [key for key,value in entry.controls.items() if value == 'MISSING']
        unknown = [key for key,value in entry.controls.items() if value == 'UNKNOWN']
        if not missing and not unknown: continue
        public = entry.route_policy in {'permitall','anonymous'}
        score = min(100, (30 if public else 0) + 15*len(missing) + 8*len(unknown) +
                    (15 if entry.sensitive_sinks else 0) + (10 if entry.unresolved_calls else 0))
        severity = 'CRITICAL' if score >= 85 else 'HIGH' if score >= 60 else 'MEDIUM' if score >= 30 else 'LOW'
        reasons = (['Publicly reachable route policy'] if public else []) + [
            key.replace('_',' ').title()+' is missing' for key in missing] + [
            key.replace('_',' ').title()+' is unknown' for key in unknown]
        paths.append({'entry_index': index, 'entrypoint': entry.entrypoint,
                      'score': score, 'severity': severity, 'reasons': reasons,
                      'flow': entry.flow})
    return sorted(paths, key=lambda p: (-p['score'], p['entrypoint']))


def analyze_security_coverage(loaded, raw_map, root, context_radius=CONTEXT_RADIUS,
                              enabled=None, build_files=(), props_files=()):
    entries, findings = _analyze_security_coverage_base(
        loaded, raw_map, root, context_radius, enabled, build_files)
    methods = _project_method_summaries(loaded, root)
    module_map = _coverage_module_map(loaded, root, build_files)
    policies = _coverage_route_policies(loaded, root, module_map)
    entry_methods = _coverage_entry_methods(methods, loaded)
    entry_methods.sort(key=lambda item: (item[1],
        (item[2]+' '+item[3]) if item[1]=='HTTP' else (item[1]+' '+item[3]),
        item[0].rel, item[0].line))
    patterns = {'authentication': _COVERAGE_AUTHN, 'authorization': _COVERAGE_METHOD_AUTHZ_ANNOTATION,
                'tenant': _COVERAGE_TENANT_BINDING, 'validation': _COVERAGE_VALIDATION,
                'rate_limit': _COVERAGE_RATE_LIMIT, 'audit': _COVERAGE_AUDIT}
    for entry, (method, kind, verb, target) in zip(entries, entry_methods):
        reached, unresolved = _coverage_graph(method, methods, module_map)
        entry.file = entry.file.replace('\\','/')
        entry.unresolved_calls = unresolved
        entry.controls['path_resolution'] = 'UNKNOWN' if unresolved else 'COVERED'
        entry.evidence['path_resolution'] = unresolved or [
            'All recognized project call boundaries resolved within analysis limits; unsupported syntax is not proven.']
        entry.semantic_facts = {'analysis': 'bounded static heuristics', 'max_depth': 8,
                                'max_methods': 250, 'reachable_methods': len(reached)}
        if kind == 'HTTP':
            entry.route_policy, entry.policy_evidence = _coverage_policy_for_route(
                policies, target, verb, module_map.get(method.path,''))
            selected = _coverage_selected_policies(policies,target,verb,module_map.get(method.path,''))
        else:
            entry.route_policy, entry.policy_evidence = 'not_required', ['Non-HTTP entry point']
            selected = []
        permissions = set()
        for policy in selected:
            entry.policy_sources.append(_coverage_source(policy.file,policy.line,raw_map,root,
                getattr(policy,'expression',policy.pattern), 'CONFIG'))
            entry.policy_conditions.extend(getattr(policy,'conditions',[]))
            permissions.update(getattr(policy,'permissions',[]))
        module = module_map.get(method.path,'')
        security_enabled = any(_METHOD_SECURITY_ENABLE.search('\n'.join(lines))
                               for path,(lines,_) in loaded.items() if module_map.get(path,'') == module)
        for current, path in reached.values():
            text = '\n'.join(loaded[current.path][0])
            # The original parser starts at the preceding delimiter; point to
            # the method declaration instead of the preceding class/field line.
            name_match = re.search(r'\b'+re.escape(current.name)+r'\s*\(', current.header)
            line = text.count('\n',0,current.start+(name_match.start() if name_match else 0))+1
            source = _coverage_source(current.rel,line,raw_map,root,_coverage_method_label(current))
            source.update({'class_name': current.class_name,'method':current.name,'path':path})
            if current is method or _coverage_method_key(current)==_coverage_method_key(method):
                source['kind']='ENTRYPOINT'
                entry.line=line
            entry.flow_steps.append(source)
            class_head=text[:text.find('{')] if '{' in text else ''
            entry.activation_conditions.extend(_coverage_conditions(class_head+'\n'+current.header))
            if security_enabled: permissions.update(_coverage_permissions(current.header))
            for sink in _COVERAGE_SENSITIVE_SINK.finditer(current.body):
                sink_line=text.count('\n',0,current.body_offset+sink.start())+1
                sink_name=(sink.group(2) or sink.group(3) or 'sensitive operation')+'()'
                sink_source=_coverage_source(current.rel,sink_line,raw_map,root,sink_name,'SINK')
                sink_source['path']=path+[sink_name]
                entry.sinks.append(sink_source)
            scope=current.header+'\n'+current.body
            for control, pattern in patterns.items():
                for match in pattern.finditer(scope):
                    # Header/body join inserts a newline in place of the brace.
                    evidence_line=text.count('\n',0,current.start+match.start())+1
                    entry.control_sources.setdefault(control,[]).append(_coverage_source(
                        current.rel,evidence_line,raw_map,root,match.group(0),'CONTROL'))
        for key in ('authentication','authorization'):
            entry.control_sources.setdefault(key,[]).extend(entry.policy_sources)
        entry.required_permissions=sorted(permissions)
        entry.policy_conditions=sorted(set(entry.policy_conditions))
        entry.activation_conditions=sorted(set(entry.activation_conditions))
        for config in props_files:
            # Only retain configuration belonging to the current build module.
            directory=os.path.dirname(os.path.abspath(config))
            try:
                if module and os.path.commonpath([directory,module]) != module: continue
            except ValueError: continue
            rel=os.path.relpath(config,root).replace('\\','/')
            profile=re.search(r'application-([^.]+)\.(?:properties|ya?ml)$',config)
            if profile: entry.configuration_profiles.append('Profile file: '+profile.group(1)+' ('+rel+')')
            try:
                with open(config,encoding='utf-8',errors='replace') as handle: config_text=handle.read()
            except OSError: continue
            for match in re.finditer(r'^\s*(?:spring\.config\.activate\.on-profile|spring\.profiles\.active|on-profile)\s*[:=]\s*([^\n#]+)',config_text,re.M):
                entry.configuration_profiles.append('Document profile: '+match.group(1).strip()+' ('+rel+')')
        entry.configuration_profiles=sorted(set(entry.configuration_profiles))
        entry.reference_flow=bool(len(entry.flow_steps)>1 or entry.sinks or unresolved)
        if unresolved and not entry.sensitive_sinks:
            # An external implementation may contain sensitive operations. Its
            # absence from the local sink inventory does not establish N/A.
            for control in ('authentication','authorization','audit'):
                if entry.controls.get(control) != 'NOT_REQUIRED': continue
                if control == 'authentication' and kind == 'Scheduled': continue
                if control == 'audit' and verb in {'GET','HEAD','OPTIONS'}: continue
                entry.controls[control]='UNKNOWN'
                entry.evidence[control]=['An unresolved implementation may require this control; inspect the external boundary.']
                if control == 'authentication' and entry.route_policy in {
                        'authenticated','fullyauthenticated','rememberme','hasrole',
                        'hasanyrole','hasauthority','hasanyauthority'}:
                    entry.controls[control]='COVERED'
                    entry.evidence[control]=entry.policy_evidence[:]
                if control == 'authorization' and entry.route_policy in {
                        'hasrole','hasanyrole','hasauthority','hasanyauthority','denyall'}:
                    entry.controls[control]='COVERED'
                    entry.evidence[control]=entry.policy_evidence[:]
        uncertainty=['Heuristic source analysis does not prove execution order, branch dominance or runtime wiring.']
        if entry.policy_conditions or entry.activation_conditions:
            uncertainty.append('Runtime activation depends on Spring profiles or conditional beans.')
        if unresolved: uncertainty.append('External or ambiguous implementations remain unresolved.')
        for control,status in entry.controls.items():
            entry.control_explanations[control]={
                'summary':' '.join(entry.evidence.get(control,[])),
                'why': {'COVERED':'Matching static evidence was found in the inspected path; verify runtime enforcement.',
                        'MISSING':'The path requires this control but no matching enforcement was identified.',
                        'UNKNOWN':'Available source and configuration cannot establish the control.',
                        'NOT_REQUIRED':'The recognized path classification does not require this control.'}[status],
                'inspected':[f'Effective route policy: {entry.route_policy}',
                             f'Reachable methods inspected: {len(reached)}',f'Sensitive sinks inspected: {len(entry.sinks)}'],
                'uncertainty':uncertainty, 'confidence':'REVIEW',
                'found':entry.evidence.get(control,[])}
        if unresolved and (enabled is None or 'SECURITY-CONTROL-UNRESOLVED-PATH' in enabled):
            finding=_coverage_finding(entry,method,'SECURITY-CONTROL-UNRESOLVED-PATH','MEDIUM',
                entry.entrypoint+' crosses unresolved code. '+unresolved[0],raw_map,context_radius)
            if not finding_suppressed(raw_map.get(method.path,[]),finding): findings.append(finding)
    return entries, findings


def coverage_explorer_html(entries):
    esc=html_mod.escape
    payload=coverage_payload(entries)
    totals=payload['summary']
    parts=["<section class='coverage-wrap' id='security-flow' aria-labelledby='coverageHeading'>",
           "<div class='coverage-title'><div><h2 id='coverageHeading'>Security flow explorer</h2>"
           "<p class='coverage-subtitle'>Select an entry point to trace code, effective security configuration, controls, and sensitive sinks.</p></div>"
           "<div class='coverage-totals'>"]
    for status,count in totals.items():
        parts.append(f"<span class='coverage-total cov-{esc(status)}'>{esc(status)} {count}</span>")
    flows=sum(entry.reference_flow for entry in entries)
    parts.append(f"<span class='coverage-total'>{flows} REFERENCE FLOW</span>"
                 f"<span class='coverage-total'>{len(entries)-flows} NO FLOW</span></div></div>")
    parts.extend([COVERAGE_TRIAGE_BAR_HTML,COVERAGE_POLICY_TOOLS_HTML])
    attacks=payload['attack_paths']
    parts.append("<section class='coverage-attack-section' aria-labelledby='coverageAttackHeading'>"
        "<div class='coverage-attack-head'><div><h3 id='coverageAttackHeading'>Risk-based attack paths</h3>"
        "<p>Prioritized public or insufficiently protected paths to sensitive operations. Heuristic ranking, not CVSS.</p></div>"
        f"<span class='coverage-total'>{len(attacks)} PRIORITIZED</span></div><div class='coverage-attack-list' id='coverageAttackList'>")
    for attack in attacks:
        sev=attack['severity']
        parts.append(f"<button class='coverage-attack {sev}' type='button' data-attack-entry='{attack['entry_index']}'>"
            f"<span class='coverage-attack-top'><span class='badge {sev}'>{sev}</span>"
            f"<span class='coverage-attack-score'>Risk {attack['score']}/100</span></span>"
            f"<span class='coverage-attack-label'>{esc(attack['entrypoint'])}</span>"
            f"<span class='coverage-attack-reason'>{esc(' · '.join(attack['reasons']))}</span></button>")
    if not attacks: parts.append("<div class='coverage-detail-empty'>No prioritized attack paths identified.</div>")
    parts.append('</div></section>')
    permissions=sorted({p for entry in entries for p in entry.required_permissions})
    parts.append("<section class='coverage-permission-section' aria-labelledby='coveragePermissionHeading'>"
        "<div class='coverage-permission-head'><h3 id='coveragePermissionHeading'>Roles and permissions matrix</h3>"
        "<p>Extracted policy requirements; this is not an access grant table. Conditional cells require runtime review.</p></div>"
        "<div class='coverage-permission-scroll'><table class='coverage-permission-table'><thead><tr><th>Entry point</th>"+
        ''.join('<th>'+esc(p)+'</th>' for p in permissions)+'</tr></thead><tbody>')
    for entry in entries:
        parts.append('<tr><td><code>'+esc(entry.entrypoint)+'</code></td>')
        for permission in permissions:
            present=permission in entry.required_permissions
            conditional=bool(entry.policy_conditions or entry.activation_conditions or entry.route_policy=='unknown')
            state='conditional' if present and conditional else 'yes' if present else 'no'
            label='COND' if present and conditional else 'YES' if present else '—'
            parts.append(f"<td class='coverage-permission-{state}'>{label}</td>")
        parts.append('</tr>')
    parts.append('</tbody></table></div></section>')
    if entries: parts.append(COVERAGE_DASHBOARD_HTML)
    else: parts.append("<p class='coverage-detail-empty'>No supported HTTP, listener, or scheduled entry points were found.</p>")
    parts.append("<details class='coverage-static'><summary>Security control coverage matrix</summary>"
                 "<table class='coverage-table'><thead><tr><th>Entry point</th>"+
                 ''.join('<th>'+esc(label)+'</th>' for _,label in _COVERAGE_COLUMNS)+'</tr></thead><tbody>')
    for entry in entries:
        parts.append('<tr><td>'+esc(entry.entrypoint)+'</td>')
        for key,_ in _COVERAGE_COLUMNS:
            status=entry.controls.get(key,'UNKNOWN')
            parts.append(f"<td class='cov-{esc(status)}'>{esc(_COVERAGE_MARK.get(status,status))}</td>")
        parts.append('</tr>')
    parts.append('</tbody></table></details>')
    # Source can contain HTML/script terminators. JSON must remain inert data.
    data=json.dumps(payload,ensure_ascii=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    parts.append("<script type='application/json' id='coverageData'>"+data+'</script></section>')
    return '\n'.join(parts)


_UNRESOLVED_RULE = Rule('SECURITY-CONTROL-UNRESOLVED-PATH',
    'Security-sensitive path crosses unresolved code', re.compile(r'(?!)'), 'MEDIUM', [], [],
    'A reachable collaborator or ambiguous call could not be resolved statically.',
    always_report=True, kind='antipattern', fix=FIX_COVERAGE_CONTROLS)
RULES.append(_UNRESOLVED_RULE)
RULE_BY_ID[_UNRESOLVED_RULE.rid] = _UNRESOLVED_RULE


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(2)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
