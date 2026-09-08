package com.example.demo;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;

/**
 * Test fixture for JSpringGuard — XXE detection.
 *
 * Each "vulnerable*" method is expected to be REPORTED.
 * Each "hardened*" method is expected to be SILENT (regression guard against
 * false positives).
 *
 * This file is never executed; it exists only so the scanner has something
 * to match against.
 */
public class XxeExamples {

    // EXPECT: XXE-DOM — no hardening features set at all.
    public void vulnerableDom(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder().parse(in);
    }

    // EXPECT: no finding — DOCTYPE declarations are rejected outright.
    public void hardenedDom(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.newDocumentBuilder().parse(in);
    }

    // EXPECT: XXE-SAX
    public void vulnerableSax(InputStream in) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.newSAXParser().parse(in, new org.xml.sax.helpers.DefaultHandler());
    }

    // EXPECT: no finding
    public void hardenedSax(InputStream in) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        spf.newSAXParser().parse(in, new org.xml.sax.helpers.DefaultHandler());
    }

    // EXPECT: XXE-STAX — StAX supports DTDs unless told otherwise.
    public void vulnerableStax(InputStream in) throws Exception {
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.createXMLStreamReader(in);
    }

    // EXPECT: no finding
    public void hardenedStax(InputStream in) throws Exception {
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.createXMLStreamReader(in);
    }

    // EXPECT: no finding — helper-factory resolution across the project.
    public void usesSharedSecureFactory(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = XmlFactoryHelper.secureDocumentBuilderFactory();
        dbf.newDocumentBuilder().parse(in);
    }
}
