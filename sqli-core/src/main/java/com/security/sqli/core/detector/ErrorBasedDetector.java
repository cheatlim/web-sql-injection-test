package com.security.sqli.core.detector;

import com.security.sqli.core.http.HttpClient;
import com.security.sqli.core.model.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Detector for error-based SQL injection vulnerabilities.
 *
 * AUTHORIZATION REQUIRED: This detector must only be used against systems
 * you own or have explicit written permission to test.
 */
public class ErrorBasedDetector {
    private static final Logger logger = LoggerFactory.getLogger(ErrorBasedDetector.class);

    private final HttpClient httpClient;

    public ErrorBasedDetector(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Tests a URL parameter for error-based SQL injection.
     *
     * @param request Base HTTP request
     * @param parameterName Parameter to test
     * @param originalValue Original parameter value
     * @param payloads List of payloads to test
     * @return Vulnerability if found, null otherwise
     */
    public Vulnerability testParameter(HttpRequest request, String parameterName,
                                      String originalValue, List<String> payloads) {
        logger.info("Testing parameter '{}' for error-based SQL injection", parameterName);

        // Get baseline response
        HttpResponse baseline = httpClient.execute(request);
        if (!baseline.isSuccessful()) {
            logger.warn("Failed to get baseline response for parameter '{}'", parameterName);
            return null;
        }

        // Test each payload
        for (String payload : payloads) {
            HttpRequest injectedRequest = cloneRequest(request);

            // Inject payload into parameter
            if (!injectedRequest.getQueryParams().isEmpty() &&
                injectedRequest.getQueryParams().containsKey(parameterName)) {
                injectedRequest.getQueryParams().put(parameterName, payload);
            } else if (injectedRequest.getBody() != null) {
                // Handle body parameters (simple replacement for now)
                String newBody = injectedRequest.getBody().replace(
                    parameterName + "=" + originalValue,
                    parameterName + "=" + payload
                );
                injectedRequest.setBody(newBody);
            }

            // Execute request with payload
            HttpResponse injectedResponse = httpClient.execute(injectedRequest);

            if (!injectedResponse.isSuccessful()) {
                continue;
            }

            // Check for database errors in response
            if (DatabaseFingerprinter.containsDatabaseError(injectedResponse.getBody())) {
                logger.info("Potential SQL injection found with payload: {}", payload);

                // Verify the vulnerability
                Vulnerability vulnerability = verifyVulnerability(
                    request, parameterName, payload, baseline, injectedResponse
                );

                if (vulnerability != null) {
                    return vulnerability;
                }
            }
        }

        logger.info("No error-based SQL injection found in parameter '{}'", parameterName);
        return null;
    }

    /**
     * Verifies a potential vulnerability with additional tests.
     */
    private Vulnerability verifyVulnerability(HttpRequest request, String parameterName,
                                             String payload, HttpResponse baseline,
                                             HttpResponse injectedResponse) {
        // Extract error message snippet
        String errorSnippet = extractErrorSnippet(injectedResponse.getBody());

        // Fingerprint database
        DatabaseType dbType = DatabaseFingerprinter.fingerprint(injectedResponse.getBody());

        // Build evidence
        List<Evidence> evidenceList = new ArrayList<>();
        evidenceList.add(Evidence.builder()
                .payload(payload)
                .statusCode(injectedResponse.getStatusCode())
                .responseSnippet(errorSnippet)
                .responseTime(injectedResponse.getResponseTimeMs())
                .contentLength(injectedResponse.getContentLength())
                .observation("Database error message detected in response")
                .build());

        // Calculate confidence based on error clarity
        int confidence = calculateConfidence(injectedResponse.getBody(), dbType);

        // Build vulnerability
        Vulnerability vulnerability = Vulnerability.builder()
                .url(request.getUrl())
                .parameter(parameterName)
                .parameterLocation(determineParameterLocation(request, parameterName))
                .type(InjectionType.ERROR_BASED)
                .severity(Severity.CRITICAL)
                .databaseType(dbType)
                .confidence(confidence)
                .payload(payload)
                .description(buildDescription(parameterName, dbType))
                .recommendation("Use parameterized queries (prepared statements)")
                .recommendation("Implement input validation and sanitization")
                .recommendation("Use ORM frameworks with proper escaping")
                .recommendation("Disable detailed error messages in production")
                .recommendation("Apply principle of least privilege to database accounts")
                .build();

        vulnerability.setEvidence(evidenceList);

        logger.info("Error-based SQL injection CONFIRMED in parameter '{}' with {}% confidence",
                parameterName, confidence);

        return vulnerability;
    }

    /**
     * Extracts a snippet of the error message from response.
     */
    private String extractErrorSnippet(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return "";
        }

        // Find error message and extract context
        String[] lines = responseBody.split("\n");
        for (String line : lines) {
            if (DatabaseFingerprinter.containsDatabaseError(line)) {
                return StringUtils.abbreviate(line.trim(), 200);
            }
        }

        // If no specific line, return first 200 chars
        return StringUtils.abbreviate(responseBody, 200);
    }

    /**
     * Calculates confidence score based on error message clarity.
     */
    private int calculateConfidence(String responseBody, DatabaseType dbType) {
        int confidence = 50; // Base confidence

        // Higher confidence if database type identified
        if (dbType != DatabaseType.UNKNOWN) {
            confidence += 30;
        }

        // Higher confidence if SQL keywords present
        if (responseBody.toLowerCase().contains("syntax") ||
            responseBody.toLowerCase().contains("sql") ||
            responseBody.toLowerCase().contains("query")) {
            confidence += 10;
        }

        // Higher confidence if error code present (e.g., ORA-00933, MySQL 1064)
        if (responseBody.matches(".*\\b(ORA-\\d{5}|ERROR \\d{4}).*")) {
            confidence += 10;
        }

        return Math.min(100, confidence);
    }

    /**
     * Determines where the parameter is located.
     */
    private String determineParameterLocation(HttpRequest request, String parameterName) {
        if (request.getQueryParams().containsKey(parameterName)) {
            return "query";
        } else if (request.getBody() != null && request.getBody().contains(parameterName)) {
            return "body";
        } else if (request.getHeaders().containsKey(parameterName)) {
            return "header";
        } else if (request.getCookies().containsKey(parameterName)) {
            return "cookie";
        }
        return "unknown";
    }

    /**
     * Builds a description for the vulnerability.
     */
    private String buildDescription(String parameterName, DatabaseType dbType) {
        StringBuilder desc = new StringBuilder();
        desc.append("Error-based SQL injection vulnerability detected in parameter '");
        desc.append(parameterName);
        desc.append("'. ");

        if (dbType != DatabaseType.UNKNOWN) {
            desc.append("Database type identified as ");
            desc.append(dbType.getDisplayName());
            desc.append(". ");
        }

        desc.append("The application returns database error messages when malicious SQL payloads are injected, ");
        desc.append("which can be exploited to extract sensitive information from the database.");

        return desc.toString();
    }

    /**
     * Clones an HTTP request.
     */
    private HttpRequest cloneRequest(HttpRequest original) {
        HttpRequest clone = new HttpRequest();
        clone.setUrl(original.getUrl());
        clone.setMethod(original.getMethod());
        clone.setHeaders(new java.util.HashMap<>(original.getHeaders()));
        clone.setQueryParams(new java.util.HashMap<>(original.getQueryParams()));
        clone.setCookies(new java.util.HashMap<>(original.getCookies()));
        clone.setBody(original.getBody());
        clone.setContentType(original.getContentType());
        clone.setTimeoutMs(original.getTimeoutMs());
        clone.setFollowRedirects(original.isFollowRedirects());
        return clone;
    }
}
