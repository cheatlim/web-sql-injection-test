package com.security.sqli.cli.service;

import com.security.sqli.core.detector.ErrorBasedDetector;
import com.security.sqli.core.detector.BooleanBlindDetector;
import com.security.sqli.core.detector.TimeBasedDetector;
import com.security.sqli.core.detector.UnionBasedDetector;
import com.security.sqli.core.http.HttpClient;
import com.security.sqli.core.model.HttpRequest;
import com.security.sqli.core.model.Vulnerability;
import com.security.sqli.core.util.JsonParameterExtractor;
import com.security.sqli.core.util.XmlParameterExtractor;
import com.security.sqli.payloads.Payload;
import com.security.sqli.payloads.PayloadLibrary;
import com.security.sqli.reporter.ConsoleReporter;
import com.security.sqli.reporter.model.ScanResult;
import com.security.sqli.reporter.model.VulnerabilityReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for orchestrating SQL injection scans.
 */
public class ScanService {
    private static final Logger logger = LoggerFactory.getLogger(ScanService.class);

    private final HttpClient httpClient;
    private final PayloadLibrary payloadLibrary;
    private final ConsoleReporter reporter;

    public ScanService(HttpClient httpClient, PayloadLibrary payloadLibrary, ConsoleReporter reporter) {
        this.httpClient = httpClient;
        this.payloadLibrary = payloadLibrary;
        this.reporter = reporter;
    }

    /**
     * Scans a URL for SQL injection vulnerabilities.
     *
     * @param request The HTTP request to test
     * @param deepScan Whether to perform deep scanning
     * @return Scan results
     */
    public ScanResult scanUrl(HttpRequest request, boolean deepScan) {
        ScanResult result = new ScanResult();
        result.setTargetUrl(request.getUrl());

        try {
            // Extract parameters to test
            Map<String, String> parametersToTest = extractParameters(request);

            result.setTotalParametersTested(parametersToTest.size());

            if (parametersToTest.isEmpty()) {
                reporter.printWarning("No parameters found to test in the URL");
                result.finish();
                return result;
            }

            logger.info("Found {} parameters to test", parametersToTest.size());

            // Test each parameter
            for (Map.Entry<String, String> param : parametersToTest.entrySet()) {
                String paramName = param.getKey();
                String paramValue = param.getValue();

                // Test for error-based SQL injection
                Vulnerability vuln = testErrorBasedInjection(request, paramName, paramValue, deepScan);

                if (vuln != null) {
                    reporter.printVulnerabilityFound(paramName, vuln.getType().getDisplayName());
                    result.addVulnerability(convertToReport(vuln, request));
                } else {
                    reporter.printParameterSafe(paramName);
                }
            }

            result.finish();

        } catch (Exception e) {
            logger.error("Error during scan: {}", e.getMessage(), e);
            reporter.printError("Scan failed: " + e.getMessage());
        }

        return result;
    }

    /**
     * Tests a parameter for error-based SQL injection.
     */
    private Vulnerability testErrorBasedInjection(HttpRequest request, String paramName,
                                                 String paramValue, boolean deepScan) {
        reporter.printTestingParameter(paramName, "error-based injection");

        // Get payloads for error-based testing
        List<Payload> payloads = deepScan ?
                payloadLibrary.getPayloadsByType(Payload.PayloadType.ERROR_BASED) :
                payloadLibrary.getSafePayloads(Payload.PayloadType.ERROR_BASED);

        // Convert to string list
        List<String> payloadStrings = payloads.stream()
                .map(Payload::getValue)
                .collect(Collectors.toList());

        // Create detector and test
        ErrorBasedDetector detector = new ErrorBasedDetector(httpClient);
        return detector.testParameter(request, paramName, paramValue, payloadStrings);
    }

    /**
     * Extracts parameters from the request.
     */
    private Map<String, String> extractParameters(HttpRequest request) {
        Map<String, String> parameters = new HashMap<>();

        // Add query parameters
        parameters.putAll(request.getQueryParams());

        // Extract parameters from URL if not already parsed
        try {
            URL url = new URL(request.getUrl());
            String query = url.getQuery();
            if (query != null && !query.isEmpty()) {
                String[] pairs = query.split("&");
                for (String pair : pairs) {
                    int idx = pair.indexOf("=");
                    if (idx > 0) {
                        String key = pair.substring(0, idx);
                        String value = pair.length() > idx + 1 ? pair.substring(idx + 1) : "";
                        if (!parameters.containsKey(key)) {
                            parameters.put(key, value);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error parsing URL: {}", e.getMessage());
        }

        // Extract parameters from body (JSON, XML, form data)
        if (request.getBody() != null && !request.getBody().isEmpty()) {
            String body = request.getBody();
            String contentType = request.getContentType().toLowerCase();

            if (contentType.contains("application/json") || JsonParameterExtractor.isValidJson(body)) {
                // Extract JSON parameters
                logger.info("Detected JSON body, extracting parameters");
                Map<String, String> jsonParams = JsonParameterExtractor.extractParameters(body);
                jsonParams.forEach((key, value) -> parameters.put("json:" + key, value));
            } else if (contentType.contains("application/xml") || contentType.contains("text/xml")
                       || XmlParameterExtractor.isValidXml(body)) {
                // Extract XML parameters
                logger.info("Detected XML body, extracting parameters");
                Map<String, String> xmlParams = XmlParameterExtractor.extractParameters(body);
                xmlParams.forEach((key, value) -> parameters.put("xml:" + key, value));
            } else if (contentType.contains("application/x-www-form-urlencoded")) {
                // Extract form parameters
                String[] pairs = body.split("&");
                for (String pair : pairs) {
                    int idx = pair.indexOf("=");
                    if (idx > 0) {
                        String key = pair.substring(0, idx);
                        String value = pair.length() > idx + 1 ? pair.substring(idx + 1) : "";
                        parameters.put("body:" + key, value);
                    }
                }
            }
        }

        return parameters;
    }

    /**
     * Converts a Vulnerability to a VulnerabilityReport.
     */
    private VulnerabilityReport convertToReport(Vulnerability vuln, HttpRequest request) {
        VulnerabilityReport report = new VulnerabilityReport();
        report.setUrl(vuln.getUrl());
        report.setParameter(vuln.getParameter());
        report.setMethod(request.getMethod().name());
        report.setType(vuln.getType().getDisplayName());
        report.setSeverity(vuln.getSeverity().name());
        report.setDatabaseType(vuln.getDatabaseType().name());
        report.setConfidence(vuln.getConfidence());
        report.setPayload(vuln.getPayload());
        report.setDescription(vuln.getDescription());
        report.setRecommendations(vuln.getRecommendations());

        // Convert evidence
        for (var evidence : vuln.getEvidence()) {
            VulnerabilityReport.EvidenceReport evidenceReport =
                    new VulnerabilityReport.EvidenceReport();
            evidenceReport.setPayload(evidence.getPayload());
            evidenceReport.setStatusCode(evidence.getStatusCode());
            evidenceReport.setResponseSnippet(evidence.getResponseSnippet());
            evidenceReport.setResponseTimeMs(evidence.getResponseTimeMs());
            evidenceReport.setObservation(evidence.getObservation());
            report.addEvidence(evidenceReport);
        }

        return report;
    }
}
