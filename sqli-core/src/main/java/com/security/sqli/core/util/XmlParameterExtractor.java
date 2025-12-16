package com.security.sqli.core.util;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class for extracting and injecting parameters in XML payloads.
 */
public class XmlParameterExtractor {
    private static final Logger logger = LoggerFactory.getLogger(XmlParameterExtractor.class);

    /**
     * Extracts all text parameters from an XML body.
     *
     * @param xmlBody XML string
     * @return Map of parameter paths to values
     */
    public static Map<String, String> extractParameters(String xmlBody) {
        Map<String, String> parameters = new HashMap<>();

        try {
            Document doc = Jsoup.parse(xmlBody, "", Parser.xmlParser());
            extractParametersRecursive(doc.root(), "", parameters);
        } catch (Exception e) {
            logger.error("Failed to parse XML: {}", e.getMessage());
        }

        return parameters;
    }

    /**
     * Recursively extracts parameters from XML elements.
     */
    private static void extractParametersRecursive(Element element, String path,
                                                   Map<String, String> parameters) {
        // Get element path
        String currentPath = path.isEmpty() ?
                element.tagName() :
                path + "." + element.tagName();

        // Extract attributes
        element.attributes().forEach(attr -> {
            String attrPath = currentPath + "[@" + attr.getKey() + "]";
            parameters.put(attrPath, attr.getValue());
        });

        // Extract text content (only if no child elements)
        if (element.children().isEmpty() && !element.text().trim().isEmpty()) {
            parameters.put(currentPath, element.text().trim());
        }

        // Recursively process child elements
        element.children().forEach(child ->
                extractParametersRecursive(child, currentPath, parameters));
    }

    /**
     * Injects a payload into a specific parameter in XML.
     *
     * @param xmlBody Original XML string
     * @param parameterPath Path to parameter (e.g., "root.user.name" or "root.user[@id]")
     * @param payload Payload to inject
     * @return Modified XML string
     */
    public static String injectPayload(String xmlBody, String parameterPath, String payload) {
        try {
            Document doc = Jsoup.parse(xmlBody, "", Parser.xmlParser());

            // Handle attribute paths
            if (parameterPath.contains("[@")) {
                injectAttributePayload(doc, parameterPath, payload);
            } else {
                injectElementPayload(doc, parameterPath, payload);
            }

            return doc.outerHtml();
        } catch (Exception e) {
            logger.error("Failed to inject payload into XML: {}", e.getMessage());
            return xmlBody;
        }
    }

    /**
     * Injects payload into an XML attribute.
     */
    private static void injectAttributePayload(Document doc, String path, String payload) {
        // Parse path: "root.user.name[@id]"
        int attrStart = path.indexOf("[@");
        String elementPath = path.substring(0, attrStart);
        String attrName = path.substring(attrStart + 2, path.length() - 1);

        Element element = findElementByPath(doc.root(), elementPath);
        if (element != null) {
            element.attr(attrName, payload);
        }
    }

    /**
     * Injects payload into an XML element's text content.
     */
    private static void injectElementPayload(Document doc, String path, String payload) {
        Element element = findElementByPath(doc.root(), path);
        if (element != null) {
            element.text(payload);
        }
    }

    /**
     * Finds an element by its path.
     */
    private static Element findElementByPath(Element root, String path) {
        if (path.isEmpty()) {
            return root;
        }

        String[] parts = path.split("\\.");
        Element current = root;

        for (String part : parts) {
            if (current.tagName().equals(part)) {
                continue;
            }

            Element found = null;
            for (Element child : current.children()) {
                if (child.tagName().equals(part)) {
                    found = child;
                    break;
                }
            }

            if (found == null) {
                return null;
            }

            current = found;
        }

        return current;
    }

    /**
     * Gets all injectable parameter paths from XML.
     *
     * @param xmlBody XML string
     * @return List of parameter paths
     */
    public static List<String> getParameterPaths(String xmlBody) {
        return new ArrayList<>(extractParameters(xmlBody).keySet());
    }

    /**
     * Validates if a string is valid XML.
     *
     * @param xmlString String to validate
     * @return True if valid XML, false otherwise
     */
    public static boolean isValidXml(String xmlString) {
        if (xmlString == null || xmlString.trim().isEmpty()) {
            return false;
        }

        try {
            Jsoup.parse(xmlString, "", Parser.xmlParser());
            return xmlString.trim().startsWith("<");
        } catch (Exception e) {
            return false;
        }
    }
}
