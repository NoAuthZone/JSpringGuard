#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security-Check 3.1 - static analysis of JVM source code for XXE and Spring
Security weaknesses.

STANDALONE TOOL: this single file is everything you need. No Semgrep, no
CodeQL CLI/database, no other scripts, and no third-party Python packages -
just this file and a Python 3.8+ interpreter. Any mention of "CodeQL" below
refers to detection techniques that have been ported into this file's own
Python rules; it does not mean CodeQL needs to be installed or run.

New since 1.x:
  * method-precise scope instead of file scope (fewer false negatives)
  * resolution of helper factories across the whole project
  * dependency check for pom.xml / build.gradle (dom4j, XStream, JDOM, ...)
  * baseline file for CI (hide known findings)
  * inline suppression via "sec-check:ignore"
  * additional sinks: Spring OXM, Jackson XmlMapper, SOAP, XmlPullParser, ...
  * output as text / json / sarif / markdown / html, parallel processing

New in 3.0 (Spring Security):
  * CSRF: disabled, GET-only matchers, missing token checks
  * authentication: permitAll on sensitive paths, missing authentication, anonymous access
  * session: stateless without JWT check, no session fixation, no timeout
  * headers: missing CSP, HSTS, X-Frame-Options, no HTTPS redirect
  * CORS: wildcard origin with credentials, insecure method exposure
  * password: insecure encoders (plain, MD5, NoOp), BCrypt without a cost parameter
  * actuator: endpoints exposed without authentication
  * remember-me: without a key, token validity too long
  * logging/audit: no failure handlers, no audit events
  * dependency check: Spring Security, Spring Boot below known minimum versions

New in 3.1 (merged from the standalone scanners, still zero external tools):
  * non-XML injection heuristics, weak crypto, build supply-chain hygiene,
    extra config rules, and the Spring CodeQL detection techniques re-implemented
    natively in Python (no CodeQL install required to get this coverage)

No third-party dependencies. Python 3.8+.

Examples:
    python3 jspringguard.py ./src
    python3 jspringguard.py . --skip-tests --min-severity MEDIUM
    python3 jspringguard.py . --format html --out report.html
    python3 jspringguard.py . --write-baseline .sec-baseline.json
    python3 jspringguard.py . --baseline .sec-baseline.json --fail-on HIGH
    python3 jspringguard.py --selftest
    python3 jspringguard.py --fix CSRF CORS
    python3 jspringguard.py --poc

Exit codes: 0 = nothing above threshold, 1 = findings above threshold, 2 = error.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html as html_mod
import json
import os
import re
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

VERSION = "3.1.0"
AUTHOR = "NoAuthZone"
AUTHOR_URL = "https://github.com/NoAuthZone"
REPO_URL = "https://github.com/NoAuthZone/JSpringGuard"

DEFAULT_EXTS = (".java", ".kt", ".jsp", ".groovy", ".scala")
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
    kind: str = "sink"          # sink | antipattern


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
         re.compile(r"\.csrf\s*\(\s*(?:c\s*->|csrf\s*->)?\s*(?:c|csrf)\s*\.\s*disable\s*\(\s*\)|"
                    r"\.csrf\s*\(\s*AbstractHttpConfigurer\s*::\s*disable\s*\)", re.I),
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
         re.compile(r"\.headers\s*\(\s*(?:h\s*->|HeadersConfigurer)?\s*"
                    r"(?:h\s*\.)?\s*(?:frameOptions\s*\(\s*\)\s*\.\s*disable|"
                    r"disable\s*\(\s*\))\s*\)", re.I),
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

    # ---- Method Security ----
    Rule("SpringSecurityCheck-NO-METHOD-SECURITY", "@EnableMethodSecurity missing",
         re.compile(r"@EnableWebSecurity", re.I),
         "LOW", [["AUTH_REQUIRED"]], [],
         "@EnableMethodSecurity not found - fine-grained method security "
         "(@PreAuthorize, @Secured) is not active.",
         fix=FIX_METHOD_SEC),

    Rule("SpringSecurityCheck-CROSS-ORIGIN-BROAD", "@CrossOrigin without explicit origins",
         re.compile(r"@CrossOrigin\s*(?:\(\s*\)|\(\s*origins\s*=\s*\"\*\"\))", re.I),
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
    ("SpringSecurityCheck-PROP-DEVTOOLS", re.compile(r"spring\.devtools\.restart\.enabled\s*[=:]\s*true|"
                                     r"spring\.h2\.console\.enabled\s*[=:]\s*true", re.I),
     "MEDIUM", "DevTools/H2 console enabled in production.", ""),
    ("SpringSecurityCheck-PROP-WEAK-JWT-SECRET", re.compile(r"(?:jwt\.secret|jwt-secret|app\.secret)\s*[=:]\s*\S{1,20}$", re.I | re.M),
     "HIGH", "JWT secret shorter than 20 characters - too weak for HMAC signatures.", FIX_JWT),
    ("SpringSecurityCheck-PROP-PLAIN-PASSWORD", re.compile(r"(?:spring\.datasource\.password|"
                                           r"spring\.security\.user\.password)\s*[=:]\s*\S+", re.I),
     "LOW", "Database password in a configuration file - better read it from a secrets store.", ""),
    ("SpringSecurityCheck-PROP-SSL-DISABLED", re.compile(r"server\.ssl\.enabled\s*[=:]\s*false", re.I),
     "HIGH", "TLS/HTTPS explicitly disabled - all data is transmitted unencrypted.", ""),
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


DEP_RULES: List[DepRule] = [
    DepRule("dom4j", "2.1.3", "HIGH",
            "dom4j before 2.1.3 parses external entities by default (XXE)."),
    DepRule("xstream", "1.4.21", "CRITICAL",
            "Numerous RCE gadget CVEs. Risky even in current versions without a type allowlist."),
    DepRule("jdom", "2.0.6.1", "HIGH",
            "JDOM before 2.0.6.1 is XXE-vulnerable (incl. CVE-2021-33813)."),
    DepRule("jdom2", "2.0.6.1", "HIGH",
            "JDOM2 before 2.0.6.1 is XXE-vulnerable."),
    DepRule("woodstox-core", "6.4.0", "MEDIUM",
            "Woodstox before 6.4.0 / 5.4.0: DoS via deeply nested structures."),
    DepRule("xercesImpl", None, "MEDIUM",
            "Standalone Xerces version on the classpath: JAXP hardening may behave "
            "differently than the JDK implementation's. Check the version and necessity."),
    DepRule("commons-digester", None, "LOW",
            "Digester uses SAX - check parser hardening."),
    DepRule("spring-oxm", None, "LOW",
            "Check the Jaxb2Marshaller configuration for setSupportDtd/setProcessExternalEntities."),
    DepRule("castor-xml", None, "MEDIUM",
            "Castor-XML is considered unmaintained; check XXE hardening manually."),
    # Spring Security / Boot
    DepRule("spring-security-core", "5.8.0", "HIGH",
            "Spring Security < 5.8: auth-bypass CVEs (incl. CVE-2022-22978, -22976)."),
    DepRule("spring-security-web", "5.8.0", "HIGH",
            "Spring Security Web < 5.8: request-matcher bypass possible."),
    DepRule("spring-security-config", "5.8.0", "HIGH",
            "Spring Security Config < 5.8: configuration can be bypassed."),
    DepRule("spring-boot-starter-security", "3.0.0", "MEDIUM",
            "Spring Boot 2.x end of life. Migration to 3.x recommended."),
    DepRule("spring-boot-autoconfigure", "2.7.0", "MEDIUM",
            "Spring Boot < 2.7.0: various CVEs in autoconfig modules."),
    DepRule("spring-webmvc", "5.3.20", "MEDIUM",
            "Spring MVC < 5.3.20: path traversal (CVE-2022-22970)."),
    DepRule("nimbus-jose-jwt", "9.31", "HIGH",
            "Nimbus JOSE+JWT < 9.31: algorithm-confusion attacks possible."),
    DepRule("jjwt", "0.12.0", "MEDIUM",
            "JJWT < 0.12.0: 'none' algorithm possible."),
    DepRule("jjwt-api", "0.12.0", "MEDIUM",
            "JJWT-API < 0.12.0: no automatic algorithm whitelist."),
    DepRule("java-jwt", "4.3.0", "MEDIUM",
            "Auth0 Java JWT < 4.3.0: algorithm-confusion CVEs."),
    # Critical ecosystem CVEs
    DepRule("log4j-core", "2.17.1", "CRITICAL",
            "Log4Shell CVE-2021-44228: JNDI RCE via log input."),
    DepRule("log4j-api", "2.17.1", "CRITICAL",
            "Log4Shell CVE-2021-44228: log4j-api as a transitive trigger."),
    DepRule("spring-cloud-gateway", "3.1.1", "CRITICAL",
            "SpEL injection via Actuator route CVE-2022-22947: RCE without auth."),
    DepRule("spring-data-commons", "2.6.3", "HIGH",
            "SpEL injection CVE-2022-22980 in spring-data-commons."),
    DepRule("snakeyaml", "2.0", "HIGH",
            "Unsafe YAML load CVE-2022-1471: deserialization RCE."),
    DepRule("jackson-databind", "2.14.0", "HIGH",
            "Polymorphic deserialization CVEs; from 2.14 default safe typing is active."),
    DepRule("commons-text", "1.10.0", "HIGH",
            "Text4Shell CVE-2022-42889: StringSubstitutor with script/dns/url lookups."),
    DepRule("h2", "2.1.210", "CRITICAL",
            "H2 console RCE via INIT/TRACE CVE-2021-42392 and CVE-2022-45868."),
    DepRule("logback-classic", "1.2.11", "HIGH",
            "JNDI lookup in Logback CVE-2021-42550: RCE via a manipulated log server."),
    DepRule("logback-core", "1.2.11", "HIGH",
            "Logback-core CVE-2021-42550 (transitive dependency of logback-classic)."),
    DepRule("tomcat-embed-core", "10.1.5", "HIGH",
            "Various RCE/DoS CVEs in older Tomcat versions (CVE-2022-42252 among others)."),
    DepRule("spring-cloud-netflix-eureka-client", None, "MEDIUM",
            "Eureka client SSRF: server.url could point to an internal network. Check the URL."),
    DepRule("spring-data-rest-core", "3.7.0", "HIGH",
            "Spring Data REST < 3.7.0: SpEL injection (successor to CVE-2017-8046)."),
    DepRule("commons-collections", "3.2.2", "CRITICAL",
            "Commons Collections < 3.2.2: gadget chain for Java deserialization (RCE)."),
    DepRule("commons-collections4", "4.1", "CRITICAL",
            "Commons Collections4 < 4.1: gadget chain for Java deserialization (RCE)."),
]

MAVEN_DEP = re.compile(
    r"<artifactId>\s*([\w.\-]+)\s*</artifactId>\s*(?:<[^>]+>\s*)*?<version>\s*([^<\s]+)\s*</version>",
    re.S)
MAVEN_ARTIFACT_ONLY = re.compile(r"<artifactId>\s*([\w.\-]+)\s*</artifactId>")
MAVEN_PROPERTY = re.compile(r"<([\w.\-]+)>\s*([\d][\d.\-_a-zA-Z]+)\s*</\1>")
MAVEN_PROPERTY_REF = re.compile(r"\$\{([\w.\-]+)\}")

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
SPRING_BOOT_MANAGED: Dict[str, Dict[str, str]] = {
    "3.2": {"spring-security-core": "6.2.0", "nimbus-jose-jwt": "9.37.3",
            "snakeyaml": "2.2", "logback-classic": "1.4.14", "tomcat-embed-core": "10.1.18",
            "jackson-databind": "2.16.1", "h2": "2.2.224"},
    "3.1": {"spring-security-core": "6.1.0", "nimbus-jose-jwt": "9.37.1",
            "snakeyaml": "2.0", "logback-classic": "1.4.11", "tomcat-embed-core": "10.1.13",
            "jackson-databind": "2.15.2", "h2": "2.2.220"},
    "2.7": {"spring-security-core": "5.7.10", "nimbus-jose-jwt": "9.31",
            "snakeyaml": "1.33", "logback-classic": "1.2.12", "tomcat-embed-core": "9.0.83",
            "jackson-databind": "2.13.5", "h2": "2.1.214"},
}
SPRING_BOOT_VER = re.compile(
    r"spring[\-_]boot[\-_]starter[\-_]parent.*?<version>\s*([\d.]+)\s*</version>|"
    r"id\s*[\'\"]org\.springframework\.boot[\'\"]\s*version\s*[\'\"]([\d.]+)[\'\"]",
    re.S | re.I)


def version_tuple(ver: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", ver)
    return tuple(int(p) for p in parts[:5]) or (0,)


def is_older(found: str, fixed: str) -> bool:
    if re.search(r"\$\{|\+|latest|SNAPSHOT", found, re.I):
        return False
    return version_tuple(found) < version_tuple(fixed)


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
        hits = [gid for gid, pat in GUARD_PATTERNS.items() if pat.search(line)]
        if not hits:
            continue
        if var_re is None or var_re.search(line):
            found.update(hits)
    return found


def build_helper_index(files_data: Dict[str, Tuple[List[str], List[Method]]]) -> Dict[str, Set[str]]:
    """Method name -> guards it sets, for factory helpers across the whole project."""
    index: Dict[str, Set[str]] = {}
    for path, (lines, methods) in files_data.items():
        for m in methods:
            if not FACTORY_RETURN_HINT.search(m.ret or ""):
                continue
            body = lines[m.start - 1:m.end]
            guards = collect_guards(body, None)
            if guards:
                index.setdefault(m.name, set()).update(guards)
    return index


def taint_hints(text: str) -> List[str]:
    return [label for pat, label in TAINT_PATTERNS if pat.search(text)]


def evaluate(rule: Rule, guards: Set[str]) -> Tuple[str, List[str]]:
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


def analyze_file(path: str, raw_lines: List[str], lines: List[str], methods: List[Method],
                 helper_index: Dict[str, Set[str]], root: str,
                 show_hardened: bool) -> List[Finding]:
    code_text = "\n".join(lines)
    file_taint = taint_hints(code_text)
    is_test = bool(TEST_PATH.search(path)) or path.endswith(("Test.java", "Tests.java", "IT.java"))
    rel = os.path.relpath(path, root) if root else path

    findings: List[Finding] = []
    for idx, line in enumerate(lines, start=1):
        raw_line = raw_lines[idx - 1] if idx - 1 < len(raw_lines) else ""
        prev_raw = raw_lines[idx - 2] if idx >= 2 else ""
        sup_match = SUPPRESS_MARKER.search(raw_line) or SUPPRESS_MARKER.search(prev_raw)
        suppressed_rules = None
        if sup_match:
            if sup_match.group(1):
                suppressed_rules = {r.strip().upper() for r in sup_match.group(1).split(",") if r.strip()}
            else:
                continue

        for rule in RULES:
            if not rule.pattern.search(line):
                continue
            if suppressed_rules is not None and rule.rid.upper() in suppressed_rules:
                continue

            var = None
            m = VAR_ASSIGN.search(line)
            if m:
                var = m.group(1)

            meth = enclosing_method(methods, idx)
            scope_lines = lines[meth.start - 1:meth.end] if meth else lines
            guards = collect_guards(scope_lines, var) if var else set()

            # Resolve a helper factory: dbf = XmlUtils.secureFactory();
            via_helper = None
            rhs = RHS_CALL.search(line)
            if rhs:
                callee = rhs.group(2)
                if callee not in ("newInstance", "newFactory") and callee in helper_index:
                    guards |= helper_index[callee]
                    via_helper = callee

            status, missing = evaluate(rule, guards)

            note = rule.note
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
            if status in ("VULNERABLE", "REVIEW", "ANTIPATTERN") and file_taint and not is_test:
                severity = bump(severity, 1)
            if is_test:
                severity = bump(severity, -1)

            snippet = raw_line.strip()[:200]
            findings.append(Finding(
                file=rel, line=idx, rule_id=rule.rid, rule_name=rule.name,
                severity=severity, status=status, code=snippet, variable=var,
                method=meth.name if meth else None,
                guards_found=sorted(guards), guards_missing=missing,
                taint=file_taint, note=note.strip(), is_test=is_test,
                fingerprint=fingerprint(rel, rule.rid, snippet),
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


def analyze_build_file(path: str, root: str) -> List[Finding]:
    """Analyzes pom.xml, build.gradle(.kts), libs.versions.toml for vulnerable deps."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    rel = os.path.relpath(path, root) if root else path
    raw_lines = content.splitlines()
    found: List[Finding] = []
    seen: Set[str] = set()

    def line_of(needle: str) -> int:
        for i, ln in enumerate(raw_lines, start=1):
            if needle in ln:
                return i
        return 1

    # --- property expansion for Maven ------------------------------------
    props: Dict[str, str] = {}
    if path.endswith(".xml"):
        for k, v in MAVEN_PROPERTY.findall(content):
            props[k] = v

    def resolve(ver: Optional[str]) -> Optional[str]:
        if not ver:
            return None
        m = MAVEN_PROPERTY_REF.match(ver.strip())
        if m:
            return props.get(m.group(1))
        return ver.strip() if ver.strip() else None

    # --- detect the managed Spring Boot version ---------------------------
    sb_ver: Optional[str] = None
    m = SPRING_BOOT_VER.search(content)
    if m:
        sb_ver = (m.group(1) or m.group(2) or "").strip()

    def managed_version(artifact: str) -> Optional[str]:
        if not sb_ver:
            return None
        for prefix in sorted(SPRING_BOOT_MANAGED.keys(), reverse=True):
            if sb_ver.startswith(prefix):
                return SPRING_BOOT_MANAGED[prefix].get(artifact)
        return None

    # --- collect (artifact, version) pairs --------------------------------
    pairs: List[Tuple[str, Optional[str]]] = []

    if path.endswith(".xml"):
        for a, v in MAVEN_DEP.findall(content):
            pairs.append((a, resolve(v)))
        known = {a for a, _ in pairs}
        for a in MAVEN_ARTIFACT_ONLY.findall(content):
            if a not in known:
                pairs.append((a, managed_version(a)))

    elif path.endswith(".toml"):
        # libs.versions.toml: build a version table
        ver_map: Dict[str, str] = {k: v for k, v in TOML_VERSION.findall(content)}
        for _alias, grp, art, ver_ref in TOML_LIB.findall(content):
            resolved = ver_map.get(ver_ref, ver_ref)
            pairs.append((art, resolved if not ver_ref.startswith("[") else None))

    else:  # build.gradle / build.gradle.kts
        # standard "group:artifact:version"
        for _, a, v in GRADLE_DEP.findall(content):
            pairs.append((a, v))
        # Kotlin DSL version { strictly(...) }
        for _, a, v in GRADLE_VERSION_BLOCK.findall(content):
            pairs.append((a, v))
        # constraints block
        for _, a, v in GRADLE_CONSTRAINT.findall(content):
            pairs.append((a, v))
        # resolve gradle.properties variables
        gprops_path = os.path.join(os.path.dirname(path), "gradle.properties")
        gprops: Dict[str, str] = {}
        if os.path.isfile(gprops_path):
            try:
                for gl in open(gprops_path, encoding="utf-8", errors="replace"):
                    m2 = re.match(r"^([\w.]+)\s*=\s*(\S+)", gl.strip())
                    if m2:
                        gprops[m2.group(1)] = m2.group(2)
            except OSError:
                pass
        pairs = [(a, gprops.get(v.strip("${}"), v) if v and v.startswith("$") else v)
                 for a, v in pairs]

    # --- compare against DEP_RULES ----------------------------------------
    for artifact, version in pairs:
        for dep in DEP_RULES:
            if artifact.lower() != dep.artifact.lower():
                continue
            key = f"{artifact}:{version}"
            if key in seen:
                continue
            seen.add(key)
            if dep.fixed and version and not is_older(version, dep.fixed):
                continue
            status = "VULNERABLE" if (dep.fixed and version) else "REVIEW"
            note = dep.note
            if dep.fixed:
                note += f" Fixed from {dep.fixed}."
            if not version:
                note += " Version not directly determinable (property/BOM/catalog) - check manually."
            if sb_ver and not version:
                mv = managed_version(artifact)
                if mv:
                    note += f" Spring Boot {sb_ver} provides {artifact}:{mv}."
            sev = dep.severity if status == "VULNERABLE" else bump(dep.severity, -1)

            # Show the real declaration (not just "artifact:version") and a
            # concrete, copy-pasteable fix wherever the file lets us build one.
            line_no = line_of(artifact)
            snippet = f"{artifact}:{version or '?'}"
            fix_text = f"Upgrade {artifact} to {dep.fixed} or later." if dep.fixed else ""

            if path.endswith(".xml"):
                block = _find_maven_dep_block(content, artifact)
                if block:
                    block_text, offset = block
                    snippet = block_text.strip("\n")
                    line_no = content.count("\n", 0, offset) + 1
                    if dep.fixed:
                        fixed_block = re.sub(
                            r"(<version>\s*)[^<]+(\s*</version>)",
                            lambda mo: mo.group(1) + dep.fixed + mo.group(2),
                            block_text, count=1)
                        fix_text = ("Bump the <version> to " + dep.fixed +
                                   " or later:\n\n" + fixed_block.strip("\n"))
            elif path.endswith((".gradle", ".kts", ".toml")):
                ln = _find_gradle_dep_line(raw_lines, artifact, version)
                if ln:
                    line_text, line_no = ln
                    snippet = line_text
                    if dep.fixed and version and version in line_text:
                        fix_text = ("Bump the version to " + dep.fixed +
                                   " or later:\n\n" +
                                   line_text.replace(version, dep.fixed))

            found.append(Finding(
                file=rel, line=line_no, rule_id=f"DEP-{artifact.upper()}",
                rule_name=f"Dependency {artifact}", severity=sev, status=status,
                code=snippet, note=note, fix=fix_text,
                fingerprint=fingerprint(rel, f"DEP-{artifact.upper()}", f"{artifact}:{version or '?'}"),
            ))
    return found


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

_MAVEN_GROUP_RE = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>")
_MAVEN_ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")
_MAVEN_VERSION_RE = re.compile(r"<version>\s*([^<\s]+)\s*</version>")


def _osv_ecosystem_triples(path: str, content: str) -> List[Tuple[str, str, str]]:
    """Returns (groupId, artifactId, version) triples for one build file, with
    Maven <properties> and Gradle version-catalog references resolved the
    same way analyze_build_file does. Covers:
      - Maven pom.xml <dependency> blocks
      - Gradle build.gradle/.kts inline 'group:artifact:version' strings
      - Gradle Kotlin DSL version { strictly/require/prefer(...) } blocks
      - Gradle constraints { } blocks
      - Gradle version catalogs (libs.versions.toml) - the default in
        current Gradle projects, previously not checked against OSV at all
    """
    triples: List[Tuple[str, str, str]] = []
    valid_version = lambda v: v and not re.search(r"\$\{|\+|latest|SNAPSHOT", v, re.I)  # noqa: E731

    if path.endswith(".xml"):
        props: Dict[str, str] = dict(MAVEN_PROPERTY.findall(content))

        def resolve(v: str) -> Optional[str]:
            m = MAVEN_PROPERTY_REF.match(v.strip())
            if m:
                return props.get(m.group(1))
            return v.strip() or None

        for block_m in _MAVEN_DEPENDENCY_BLOCK_RE.finditer(content):
            block = block_m.group(0)
            g, a, v = _MAVEN_GROUP_RE.search(block), _MAVEN_ARTIFACT_RE.search(block), _MAVEN_VERSION_RE.search(block)
            if g and a and v:
                ver = resolve(v.group(1))
                if valid_version(ver):
                    triples.append((g.group(1), a.group(1), ver))

    elif path.endswith((".gradle", ".kts")):
        seen: Set[Tuple[str, str]] = set()
        for g, a, v in (list(GRADLE_DEP.findall(content))
                       + list(GRADLE_VERSION_BLOCK.findall(content))
                       + list(GRADLE_CONSTRAINT.findall(content))):
            if valid_version(v) and (g, a) not in seen:
                seen.add((g, a))
                triples.append((g, a, v))

    elif path.endswith(".toml"):
        # Gradle version catalog: [versions] table + [libraries] entries that
        # reference it via version.ref (the standard modern Gradle layout).
        ver_map: Dict[str, str] = dict(TOML_VERSION.findall(content))
        for _alias, group, artifact, ver_ref in TOML_LIB.findall(content):
            version = ver_map.get(ver_ref, ver_ref)
            if valid_version(version) and not version.startswith(("[", "{")):
                triples.append((group, artifact, version))

    return triples


_MAVEN_VERSION_QUALIFIER_RE = re.compile(r"\.(RELEASE|Final|GA|RC\d*|SP\d*)$", re.I)


def _normalize_maven_version_for_osv(version: str) -> str:
    """Strips common non-semver Maven qualifiers (.RELEASE, .Final, .GA, .RC1,
    .SP1) before sending a version to osv.dev's query API.

    OSV's version-range comparator expects roughly semver-shaped versions; a
    real-world Maven version like '4.2.12.RELEASE' may not be recognized as
    falling inside a vulnerable range expressed in plain numeric form, causing
    a false "not affected" instead of an error - it looks identical to a
    clean result, which is worse than an explicit failure. The ORIGINAL
    version is still used for the report and the cache key; only the string
    sent to OSV is normalized."""
    return _MAVEN_VERSION_QUALIFIER_RE.sub("", version)


def osv_query_online(group: str, artifact: str, version: str,
                     timeout: float = 8.0) -> Tuple[Optional[dict], Optional[str]]:
    """A single live query to osv.dev. Returns (response, None) on success, or
    (None, error_message) on any network/HTTP/parse error - the caller can
    then tell a real failure apart from "no vulnerabilities found", and show
    the user what actually went wrong instead of silently reporting zero."""
    import urllib.request
    import urllib.error

    body = json.dumps({
        "version": version,
        "package": {"name": f"{group}:{artifact}", "ecosystem": "Maven"},
    }).encode("utf-8")
    req = urllib.request.Request(
        OSV_API_QUERY_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            detail = ""
        return None, f"HTTP {exc.code} {exc.reason}" + (f" - {detail}" if detail else "")
    except urllib.error.URLError as exc:
        return None, f"connection failed: {exc.reason}"
    except TimeoutError:
        return None, "timed out"
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _osv_severity(vuln: dict) -> str:
    """Best-effort mapping of an OSV vulnerability record to our severity
    scale. OSV does not always carry a normalized severity, so this checks a
    few known shapes and falls back to MEDIUM rather than over- or
    under-stating an unknown risk."""
    db_sev = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    mapping = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
              "MEDIUM": "MEDIUM", "LOW": "LOW"}
    if db_sev in mapping:
        return mapping[db_sev]
    for sev in vuln.get("severity") or []:
        score_field = str(sev.get("score", "")).strip()
        # Only trust a bare numeric score (e.g. "9.8"). OSV's CVSS entries are
        # usually a full vector string like "CVSS:3.1/AV:N/AC:L/.../A:H" with
        # no numeric base score included - naively regex-extracting a number
        # from that string would grab the "3.1" CVSS *version*, not a score.
        # Computing a real base score from a vector needs the CVSS formula,
        # which is out of scope here.
        if re.fullmatch(r"\d+(?:\.\d+)?", score_field):
            score = float(score_field)
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
    if vuln.get("severity"):
        # A CVSS vector was present but not a bare score - OSV/GHSA only
        # attaches CVSS scoring to vulnerabilities considered notable, so
        # treat its mere presence as at least HIGH rather than guessing.
        return "HIGH"
    return "MEDIUM"


def osv_check_build_files(build_files: List[str], root: str,
                          cache_read: Optional[Dict[str, dict]],
                          cache_write: Optional[Dict[str, dict]],
                          jobs: int = 8) -> Tuple[List["Finding"], int, int, int, Optional[str]]:
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
    packages_failed, first_error). packages_failed/first_error let the caller
    distinguish "OSV genuinely found nothing" from "every query failed" (no
    real internet access, a proxy/firewall, or osv.dev being unreachable) -
    both look identical from the finding count alone otherwise.
    """
    # Pass 1: collect every (file, group, artifact, version) occurrence.
    occurrences: List[Tuple[str, str, str, str]] = []
    for bf in build_files:
        try:
            content = open(bf, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        rel = os.path.relpath(bf, root) if root else bf
        for group, artifact, version in _osv_ecosystem_triples(bf, content):
            occurrences.append((rel, group, artifact, version))

    # Pass 2: reduce to the unique packages that actually need a lookup.
    unique: Dict[str, Tuple[str, str, str]] = {}
    for _rel, group, artifact, version in occurrences:
        key = f"{group}:{artifact}@{version}"
        unique.setdefault(key, (group, artifact, version))

    results: Dict[str, Optional[dict]] = {}
    failed = 0
    first_error: Optional[str] = None

    if cache_read is not None:
        for key in unique:
            results[key] = cache_read.get(key)
    else:
        def _fetch(item: Tuple[str, Tuple[str, str, str]]):
            key, (group, artifact, version) = item
            data, err = osv_query_online(group, artifact, _normalize_maven_version_for_osv(version))
            return key, data, err

        items = list(unique.items())
        if jobs > 1 and len(items) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(jobs, len(items))) as pool:
                fetched = list(pool.map(_fetch, items))
        else:
            fetched = [_fetch(it) for it in items]

        for key, data, err in fetched:
            results[key] = data
            if err is not None:
                failed += 1
                if first_error is None:
                    first_error = f"{key}: {err}"
            if cache_write is not None and data is not None:
                cache_write[key] = data

    # Pass 3: expand the (deduplicated) results back out to every occurrence,
    # so each build file still gets its own finding for a shared dependency.
    out: List[Finding] = []
    for rel, group, artifact, version in occurrences:
        data = results.get(f"{group}:{artifact}@{version}")
        if not data:
            continue
        for v in data.get("vulns") or []:
            vid = v.get("id", "UNKNOWN")
            summary = (v.get("summary") or (v.get("details") or "")[:200]).strip()
            snippet = f"{group}:{artifact}:{version}"
            out.append(Finding(
                file=rel, line=1, rule_id=f"OSV-{vid}",
                rule_name=f"OSV advisory {vid} for {group}:{artifact}",
                severity=_osv_severity(v), status="VULNERABLE", code=snippet,
                note=summary or f"See https://osv.dev/vulnerability/{vid}",
                fix=f"Check {vid} at https://osv.dev/vulnerability/{vid} for the fixed version(s).",
                fingerprint=fingerprint(rel, f"OSV-{vid}", snippet)))
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
            ))
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


def print_text(findings: List[Finding], scanned: int, builds: int, use_color: bool,
               show_fix: bool) -> None:
    print(f"JSpringGuard {VERSION} - {scanned} source file(s), {builds} build file(s), "
          f"{len(findings)} finding(s)\n")
    if not findings:
        print("No open XML sinks found.")
        print(f"\nJSpringGuard v{VERSION} by {AUTHOR} - {REPO_URL}")
        return

    for f in sort_findings(findings):
        print(colorize(f"[{f.severity}] {f.rule_id} - {f.rule_name}  ({f.status})",
                       f.severity, use_color))
        loc = f"  {f.file}:{f.line}"
        if f.method:
            loc += f"  in {f.method}()"
        print(loc)
        print(colorize(f"  > {f.code}", "DIM", use_color))
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
    print(f"\nJSpringGuard v{VERSION} by {AUTHOR} - {REPO_URL}")


HTML_CSS = """
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
.mini-btn{flex:none;background:var(--surface-2);border:1px solid var(--line);color:var(--dim);
font-size:12.5px;font-weight:600;padding:10px 14px;border-radius:var(--r-sm);cursor:pointer;
white-space:nowrap;transition:all .12s}
.mini-btn:hover{color:var(--text);border-color:var(--accent-soft);background:var(--surface-3)}
@media (max-width:560px){.filter-row{flex-wrap:wrap}.type-filter{max-width:none;width:100%}
.mini-btn{width:100%}}
.empty-note{color:var(--faint);font-size:13px;text-align:center;padding:40px 12px}
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

HTML_JS = """
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
var search=document.getElementById('findingSearch');
var typeFilter=document.getElementById('typeFilter');
var sevFilter=document.getElementById('severityFilter');
var chips=document.getElementById('sevChips');
function applyFilters(){
  var q = search ? search.value.toLowerCase() : '';
  var t = typeFilter ? typeFilter.value : '';
  var s = sevFilter ? sevFilter.value : '';
  var cards=document.querySelectorAll('.card');
  var shown=0;
  cards.forEach(function(c){
    var textHit = c.getAttribute('data-search').indexOf(q) !== -1;
    var typeHit = !t || c.getAttribute('data-type') === t;
    var sevHit = !s || c.classList.contains(s);
    var hit = textHit && typeHit && sevHit;
    c.style.display = hit ? '' : 'none';
    if(hit) shown++;
  });
  var note=document.getElementById('noMatch');
  if(note) note.style.display = shown===0 ? '' : 'none';
  if(chips){
    chips.querySelectorAll('div').forEach(function(d){
      d.classList.toggle('active', d.getAttribute('data-sev') === s && s !== '');
    });
  }
}
if(search) search.addEventListener('input', applyFilters);
if(typeFilter) typeFilter.addEventListener('change', applyFilters);
if(sevFilter) sevFilter.addEventListener('change', applyFilters);
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
})();
"""


def to_html(findings: List[Finding], scanned: int, builds: int) -> str:
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

    if findings:
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
        parts.append("<button type='button' id='toggleFixes' class='mini-btn' "
                     "title='Expand or collapse every Fix template at once'>Expand all fixes</button>")
        parts.append("</div>")

    if not findings:
        parts.append("<div class='empty-note'>No findings above the configured threshold.</div>")
    else:
        parts.append("<div id='noMatch' class='empty-note' style='display:none'>No findings match your filter.</div>")

    for f in sort_findings(findings):
        search_blob = esc(" ".join([f.rule_id, f.rule_name, f.file, f.severity, f.status, f.note]).lower())
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
        if f.code:
            parts.append(f"<pre>{esc(f.code)}</pre>")
        if f.guards_found:
            parts.append(f"<div class='meta-line'><b>Set:</b> <code>{esc(', '.join(f.guards_found))}</code></div>")
        if f.guards_missing:
            parts.append("<div class='meta-line'><b>Missing:</b></div><ul class='missing'>" + "".join(
                f"<li>{esc(GUARD_HINTS.get(g, g))}</li>" for g in f.guards_missing) + "</ul>")
        if f.taint:
            parts.append(f"<div class='meta-line'>External input: {esc(', '.join(f.taint))}</div>")
        if f.is_test:
            parts.append("<div class='meta-line'>Test code</div>")
        if f.note:
            parts.append(f"<div class='meta-line'>{esc(f.note)}</div>")
        parts.append(f"<span class='fp'>{esc(f.fingerprint)}</span>")
        rule = RULE_BY_ID.get(f.rule_id)
        fix_text = f.fix or (rule.fix if rule else "")
        if fix_text:
            parts.append(f"<details class='fix'><summary>Fix template</summary><pre>{esc(fix_text)}</pre></details>")
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


def to_markdown(findings: List[Finding], scanned: int, builds: int) -> str:
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
    if not findings:
        out.append("No open XML sinks found.")
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
        if f.note:
            out.append(f"- Note: {f.note}")
        out.append(f"- Fingerprint: `{f.fingerprint}`")
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
        })
        results.append({
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "warning"),
            "partialFingerprints": {"xxeCheck/v1": f.fingerprint},
            "message": {"text": f"{f.status}: {f.rule_name}. "
                                f"Missing: {', '.join(f.guards_missing) or '-'}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                    "region": {"startLine": f.line, "snippet": {"text": f.code}},
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
}


def run_selftest() -> int:
    tmp = tempfile.mkdtemp(prefix="seccheck_")
    for name, content in SAMPLES.items():
        with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
            fh.write(content)

    findings = scan(tmp, exts=DEFAULT_EXTS, exclude=set(DEFAULT_EXCLUDE_DIRS),
                    skip_tests=False, show_hardened=True, jobs=2, with_deps=True)[0]

    by_key: Dict[str, Finding] = {}
    for f in findings:
        by_key[f"{os.path.basename(f.file)}:{f.line}"] = f

    def status_of(fname: str) -> List[str]:
        return [f.status for f in findings if os.path.basename(f.file) == fname]

    def has_rule(fname: str, rid: str) -> bool:
        return any(os.path.basename(f.file) == fname and f.rule_id == rid for f in findings)
    def rule_status(fname: str, rid: str) -> List[str]:
        return [f.status for f in findings if os.path.basename(f.file) == fname and f.rule_id == rid]

    checks: List[Tuple[str, bool]] = [
        # XXE
        ("Vulnerable.java detected", status_of("Vulnerable.java") == ["VULNERABLE"]),
        ("Safe.java marked as hardened", status_of("Safe.java") == ["HARDENED"]),
        ("Method scope separates safe/unsafe",
         sorted(status_of("MethodScope.java")) == ["HARDENED", "VULNERABLE"]),
        ("Helper factory resolved", status_of("UsesHelper.java") == ["HARDENED"]),
        ("Suppression applies", status_of("Suppressed.java") == []),
        ("dom4j 2.1.1 detected as vulnerable",
         any(f.rule_id == "DEP-DOM4J" and f.status == "VULNERABLE" for f in findings)),
        ("XStream 1.4.10 detected as vulnerable",
         any(f.rule_id == "DEP-XSTREAM" and f.status == "VULNERABLE" for f in findings)),
        # Spring Security
        ("SpringSecurityCheck-CSRF-DISABLED detected (bad config)",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-CSRF-DISABLED")),
        ("SpringSecurityCheck-ANY-REQUEST-PERMIT detected",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-ANY-REQUEST-PERMIT")),
        ("SpringSecurityCheck-NOOP-ENCODER detected",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-NOOP-ENCODER")),
        ("SpringSecurityCheck-REMEMBERME-NO-KEY detected",
         has_rule("SecurityConfigBad.java", "SpringSecurityCheck-REMEMBERME-NO-KEY")),
        ("spring-security-web 5.6.0 detected as vulnerable",
         any(f.rule_id == "DEP-SPRING-SECURITY-WEB" and f.status == "VULNERABLE" for f in findings)),
        ("nimbus-jose-jwt 9.10 detected as vulnerable",
         any(f.rule_id == "DEP-NIMBUS-JOSE-JWT" and f.status == "VULNERABLE" for f in findings)),
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
         paths: Optional[List[str]] = None) -> Tuple[List[Finding], int, int]:
    targets = paths or [root]
    src_files, build_files = walk(targets, exts, exclude, skip_tests, with_deps)

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
        if not data:
            continue
        _, raw_lines, lines, methods = data
        loaded[p] = (lines, methods)
        raw_map[p] = raw_lines

    helper_index = build_helper_index(loaded)

    findings: List[Finding] = []
    for p, (lines, methods) in loaded.items():
        findings.extend(analyze_file(p, raw_map[p], lines, methods, helper_index,
                                     root, show_hardened))
    if with_deps:
        for b in build_files:
            findings.extend(analyze_build_file(b, root))
    # scan properties files
    for pf in walk_props(targets, exclude):
        findings.extend(analyze_props_file(pf, root))
    return findings, len(src_files), len(build_files)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Output path helper
# --------------------------------------------------------------------------

EXT_BY_FORMAT = {"html": ".html", "markdown": ".md", "json": ".json", "sarif": ".sarif"}


def auto_report_path(fmt: str, root: str) -> str:
    """Builds an auto-generated report filename in the current directory, e.g.
    security-check-myproject-20260905-142301.html. Used whenever --format is
    not 'text' and --out was not given, so html/json/sarif/markdown reports
    always land in a file instead of being dumped to the terminal."""
    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = EXT_BY_FORMAT.get(fmt, ".txt")
    base = os.path.basename(os.path.abspath(root)) if root else "report"
    base = re.sub(r"[^\w.-]", "_", base) or "report"
    return f"security-check-{base}-{ts}{ext}"


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
    ap.add_argument("--show-hardened", action="store_true", help="Also list hardened locations")
    ap.add_argument("--no-deps", action="store_true", help="Skip the dependency check")
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
    ap.add_argument("--min-severity", default="LOW", choices=SEVERITY_LIST)
    ap.add_argument("--fail-on", default="MEDIUM", choices=SEVERITY_LIST + ["NONE"])
    ap.add_argument("--format", default="text", choices=["text", "json", "sarif", "markdown", "html"])
    ap.add_argument("--out", help="Output file. If omitted and --format is not "
                    "'text', a filename is generated automatically (e.g. "
                    "security-check-<project>-<timestamp>.html).")
    ap.add_argument("--baseline", help="JSON baseline: fingerprints it contains are hidden")
    ap.add_argument("--write-baseline", metavar="PATH", help="Save current findings as a baseline")
    ap.add_argument("--show-fix", action="store_true", help="Also print a fix snippet per finding")
    ap.add_argument("--jobs", type=int, default=4, help="Parallel readers (default 4)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--fix", nargs="*", metavar="RULE",
                    help="Print hardened code templates (e.g. --fix DOM STAX)")
    ap.add_argument("--poc", action="store_true", help="Test payloads for the counter-test")
    ap.add_argument("--version", action="version",
                    version=f"JSpringGuard {VERSION} by {AUTHOR} - {REPO_URL}")
    args = ap.parse_args(argv)

    print(f"JSpringGuard v{VERSION} by {AUTHOR} - {REPO_URL}", file=sys.stderr)

    if (args.osv_cache_read or args.osv_cache_write) and not args.check_osv:
        print("[osv] --osv-cache-read/--osv-cache-write given without --check-osv - "
             "enabling --check-osv automatically (it would otherwise be silently ignored).",
             file=sys.stderr)
        args.check_osv = True

    if args.poc:
        print(POC_TEXT)
        return 0
    if args.fix is not None:
        return print_fixes(args.fix)
    if args.selftest:
        return run_selftest()
    if not args.paths:
        ap.error("Please provide at least one path (or --selftest / --fix / --poc).")

    exts = tuple(e if e.startswith(".") else "." + e
                 for e in (x.strip() for x in args.ext.split(",")) if e)
    exclude = set(DEFAULT_EXCLUDE_DIRS) | {x.strip() for x in args.exclude.split(",") if x.strip()}
    root = args.paths[0] if len(args.paths) == 1 and os.path.isdir(args.paths[0]) else ""

    findings, n_src, n_build = scan(root, exts, exclude, args.skip_tests, args.show_hardened,
                                    max(1, args.jobs), not args.no_deps, paths=args.paths)

    if args.check_osv:
        cache_read: Optional[Dict[str, dict]] = None
        cache_write: Optional[Dict[str, dict]] = None
        if args.osv_cache_read:
            # Read-only mode: report from the local file, no network call, and
            # nothing is written back - there is nothing new to save.
            try:
                with open(args.osv_cache_read, "r", encoding="utf-8") as fh:
                    cache_read = json.load(fh)
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
        _, osv_build_files = walk(args.paths, exts, exclude, args.skip_tests, True)
        osv_findings, osv_occurrences, osv_unique, osv_failed, osv_first_error = osv_check_build_files(
            osv_build_files, root, cache_read, cache_write, jobs=max(1, args.jobs))
        findings.extend(osv_findings)
        dedupe_note = (f" ({osv_occurrences} occurrence(s) across build files)"
                      if osv_occurrences != osv_unique else "")
        print(f"[osv] Checked {osv_unique} unique package(s){dedupe_note}, "
             f"{len(osv_findings)} advisory(ies) found.", file=sys.stderr)
        if osv_failed:
            print(f"[osv] WARNING: {osv_failed}/{osv_unique} quer{'y' if osv_failed == 1 else 'ies'} "
                 f"failed - the {len(osv_findings)} figure above is INCOMPLETE, not a clean scan. "
                 f"First error: {osv_first_error}", file=sys.stderr)
            if osv_failed == osv_unique:
                print("[osv] Every single query failed - this points to no real internet access, "
                     "a proxy/firewall blocking api.osv.dev, or an SSL/certificate problem, not "
                     "\"no vulnerabilities found\". Check connectivity, e.g.:\n"
                     "        curl -s https://api.osv.dev/v1/query -d '{\"version\":\"2.9.1\","
                     "\"package\":{\"name\":\"org.apache.logging.log4j:log4j-core\","
                     "\"ecosystem\":\"Maven\"}}'", file=sys.stderr)
        if cache_write is not None:
            try:
                with open(args.osv_cache_write, "w", encoding="utf-8") as fh:
                    json.dump(cache_write, fh, indent=2)
                abs_cache = os.path.abspath(args.osv_cache_write)
                print(f"[osv] Cache written: {abs_cache} ({len(cache_write)} package(s)) "
                     f"- copy this file to the air-gapped machine and use --check-osv-read there.",
                     file=sys.stderr)
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
                    print_text(findings, n_src, n_build, False, args.show_fix)
                finally:
                    sys.stdout = old
        else:
            print_text(findings, n_src, n_build,
                       not args.no_color and sys.stdout.isatty(), args.show_fix)
    elif args.format in ("markdown", "html"):
        text = (to_markdown(findings, n_src, n_build) if args.format == "markdown"
                else to_html(findings, n_src, n_build))
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        payload = (to_sarif(findings) if args.format == "sarif"
                   else {"tool": "JSpringGuard", "version": VERSION,
                         "author": AUTHOR, "repository": REPO_URL,
                         "files_scanned": n_src, "build_files_scanned": n_build,
                         "findings": [asdict(f) for f in findings]})
        text = json.dumps(payload, indent=2, ensure_ascii=False)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    if out_path:
        abs_path = os.path.abspath(out_path)
        print(f"Report written: {abs_path}", file=sys.stderr)
        print(f"Open it: file://{abs_path}", file=sys.stderr)

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
]

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


def analyze_spel_from_request(rel: str, text: str) -> List["Finding"]:
    """CodeQL technique java/spring/spel-injection-from-request in Python:
    a request-bound method parameter + a dynamic parseExpression() in the same
    method."""
    out: List[Finding] = []
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
                fingerprint=fingerprint(rel, "SRC-SPEL-REQUEST", snippet)))
    return out


# Same file-wide-scope reasoning as SRC-SPEL-REQUEST above: a per-line Rule
# cannot see a variable declared on one line (e.g. "DirContext ctx") and used
# on a later line ("ctx.search(...)"), so LDAP injection is detected the same
# way - across the whole file text, not line by line.
_LDAP_TYPE_RE = re.compile(r"\b(?:DirContext|LdapTemplate)\b")
_LDAP_SEARCH_CONCAT_RE = re.compile(r"\.search\s*\([^;]{0,200}[\"']\s*\+")


def analyze_ldap_injection(rel: str, text: str) -> List["Finding"]:
    """Flags an LDAP search filter built via string concatenation, where a
    DirContext/LdapTemplate type is mentioned earlier in the same file
    (heuristic, file-scoped rather than true data flow)."""
    out: List[Finding] = []
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
            fingerprint=fingerprint(rel, "SRC-LDAP-INJECTION", snippet)))
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


def analyze_log_injection(rel: str, text: str) -> List["Finding"]:
    """Flags a logger call whose sole, bare argument is a method parameter -
    the parameter reaches the log sink unmodified and unformatted, which is
    exactly the Log4Shell attack shape (and log-forging in general)."""
    out: List[Finding] = []
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
                note="A method parameter is passed bare into a logger call in the same method - "
                     "this is the exact code-level trigger shape for Log4Shell-class bugs "
                     "(a vulnerable logging library evaluates attacker-controlled lookup syntax "
                     "in the logged string) and enables log forging/injection regardless of the "
                     "logging library's own patch status.",
                fix="Never log raw, unvalidated request input directly; use a parameterized "
                    "logging call (e.g. logger.info(\"token={}\", sanitize(token))) and/or strip "
                    "control characters and lookup-like syntax (${...}) before logging.",
                fingerprint=fingerprint(rel, "SRC-LOG-INJECTION", snippet)))
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


def analyze_sqli_var_concat(rel: str, text: str) -> List["Finding"]:
    """Flags String sql = "..." + var; ... executeQuery(sql) - a variable built
    via concatenation earlier in the SAME METHOD and later passed bare into a
    JDBC/JPA execute-style call. Method-scoped correlation, not full data flow;
    a PreparedStatement built from a literal-only string (no '+') is correctly
    not flagged, since the assignment step requires concatenation."""
    out: List[Finding] = []
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
                fingerprint=fingerprint(rel, "SRC-SQLI-VAR-CONCAT", snippet)))
    return out


# Found scanning JoyChou93/java-sec-code's Cors.java: reflecting the request's
# own Origin header back as the CORS allow-origin value is worse than a static
# wildcard (it bypasses "no '*' with credentials"), and none of the existing
# --- extend scan() so build hygiene + the SpEL technique run too ----------
# A wrapper instead of editing the existing scan(): it rebinds the module name
# 'scan' BEFORE it is called by main()/run_selftest().
_orig_scan_before_merge = scan


def scan(root: str, exts: Tuple[str, ...], exclude: Set[str], skip_tests: bool,
         show_hardened: bool, jobs: int, with_deps: bool,
         paths: Optional[List[str]] = None) -> Tuple[List["Finding"], int, int]:
    findings, n_src, n_build = _orig_scan_before_merge(
        root, exts, exclude, skip_tests, show_hardened, jobs, with_deps, paths)
    if with_deps:
        targets = paths or [root]
        _, build_files = walk(targets, exts, exclude, skip_tests, True)
        for b in build_files:
            findings.extend(analyze_build_hygiene(b, root))
        # gradle-wrapper.properties is not scanned by the base -> add it here.
        for t in targets:
            if os.path.isfile(t) and os.path.basename(t) == "gradle-wrapper.properties":
                findings.extend(analyze_build_hygiene(t, root))
            elif os.path.isdir(t):
                for r, dirs, names in os.walk(t):
                    dirs[:] = [d for d in dirs if d not in exclude]
                    if "gradle-wrapper.properties" in names:
                        findings.extend(analyze_build_hygiene(
                            os.path.join(r, "gradle-wrapper.properties"), root))

    # CodeQL "source -> sink" technique for SpEL, method-scoped, in Python.
    # (Comments are stripped first - if the base provides strip_comments - to
    #  avoid false positives from commented-out code.)
    targets = paths or [root]
    src_files, _sb = walk(targets, exts, exclude, skip_tests, False)
    _strip = globals().get("strip_comments")
    for p in src_files:
        if not p.endswith((".java", ".kt")):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                txt = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(p, root) if root else p
        findings.extend(analyze_spel_from_request(rel, _strip(txt) if _strip else txt))
        findings.extend(analyze_ldap_injection(rel, _strip(txt) if _strip else txt))
        findings.extend(analyze_log_injection(rel, _strip(txt) if _strip else txt))
        findings.extend(analyze_sqli_var_concat(rel, _strip(txt) if _strip else txt))

    return findings, n_src, n_build

# ==========================================================================
#  END MERGE BLOCK
# ==========================================================================


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
