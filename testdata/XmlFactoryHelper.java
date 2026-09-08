package com.example.demo;

import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Test fixture for JSpringGuard — helper-factory resolution.
 *
 * The hardening lives here, not at the call site. A file-scoped scanner would
 * flag every caller; JSpringGuard resolves this helper across the project and
 * treats callers as safe.
 */
public final class XmlFactoryHelper {

    private XmlFactoryHelper() {
    }

    public static DocumentBuilderFactory secureDocumentBuilderFactory() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        return dbf;
    }
}
