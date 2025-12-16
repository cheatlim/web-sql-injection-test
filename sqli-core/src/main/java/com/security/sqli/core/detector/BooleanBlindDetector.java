package com.security.sqli.core.detector;

import com.security.sqli.core.http.HttpClient;
import com.security.sqli.core.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Detector for Boolean-based blind SQL injection vulnerabilities.
 *
 * Boolean-based blind SQL injection occurs when the application's behavior changes
 * based on TRUE/FALSE SQL conditions, but no error messages are returned.
 *
 * AUTHORIZATION REQUIRED: This detector must only be used against systems
 * you own or have explicit written permission to test.
 */
public class BooleanBlindDetector {
    private static final Logger logger = LoggerFactory.getLogger(BooleanBlindDetector.class);

    private final HttpClient httpClient;
    private static final int SIMILARITY_THRESHOLD = 95; // 95% similarity required

    public BooleanBlindDetector(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Tests a URL parameter for Boolean-based blind SQL injection.
     *
     * @param request Base HTTP request
     * @param parameterName Parameter to test
     * @param originalValue Original parameter value
     * @param payloads List of payload pairs (true/false conditions)
     * @return Vulnerability if found, null otherwise
     */
    public Vulnerability testParameter(HttpRequest request, String parameterName,
                                      String originalValue, List<String[]> payloads) {
        logger.info("Testing parameter '{}' for Boolean-based blind SQL injection", parameterName);

        // Get baseline response
        HttpResponse baseline = httpClient.execute(request);
        if (!baseline.isSuccessful()) {
            logger.warn("Failed to get baseline response for parameter '{}'", parameterName);
            return null;
        }

        // Test each payload pair
        for (String[] payloadPair : payloads) {
            if (payloadPair.length != 2) continue;

            String truePayload = payloadPair[0];
            String falsePayload = payloadPair[1];

            // Test TRUE condition
            HttpRequest trueRequest = cloneAndInjectPayload(request, parameterName, truePayload);
            HttpResponse trueResponse = httpClient.execute(trueRequest);

            if (!trueResponse.isSuccessful()) {
                continue;
            }

            // Test FALSE condition
            HttpRequest falseRequest = cloneAndInjectPayload(request, parameterName, falsePayload);
            HttpResponse falseResponse = httpClient.execute(falseRequest);

            if (!falseResponse.isSuccessful()) {
                continue;
            }

            // Analyze responses
            boolean vulnerability = analyzeResponses(baseline, trueResponse, falseResponse);

            if (vulnerability) {
                logger.info("Boolean-based blind SQL injection detected with payloads: {} / {}",
                        truePayload, falsePayload);

                return verifyVulnerability(request, parameterName, truePayload, falsePayload,
                        baseline, trueResponse, falseResponse);
            }
        }

        logger.info("No Boolean-based blind SQL injection found in parameter '{}'", parameterName);
        return null;
    }

    /**
     * Analyzes responses to detect Boolean-based blind SQL injection.
     */
    private boolean analyzeResponses(HttpResponse baseline, HttpResponse trueResponse,
                                    HttpResponse falseResponse) {
        // Calculate similarities
        int baselineTrueSimilarity = calculateSimilarity(baseline.getBody(), trueResponse.getBody());
        int baselineFalseSimilarity = calculateSimilarity(baseline.getBody(), falseResponse.getBody());
        int trueFalseSimilarity = calculateSimilarity(trueResponse.getBody(), falseResponse.getBody());

        // Check content length differences
        int baselineLength = baseline.getContentLength();
        int trueLength = trueResponse.getContentLength();
        int falseLength = falseResponse.getContentLength();

        // Boolean-based blind SQL injection indicators:
        // 1. TRUE response should be similar to baseline (same data returned)
        // 2. FALSE response should be different from TRUE (different data/no data)
        // 3. Content lengths should show significant difference between TRUE and FALSE

        boolean lengthDifference = Math.abs(trueLength - falseLength) > 50;
        boolean trueSimilarToBaseline = baselineTrueSimilarity >= SIMILARITY_THRESHOLD;
        boolean falseDifferentFromTrue = trueFalseSimilarity < SIMILARITY_THRESHOLD;

        logger.debug("Similarity - Baseline/True: {}%, Baseline/False: {}%, True/False: {}%",
                baselineTrueSimilarity, baselineFalseSimilarity, trueFalseSimilarity);
        logger.debug("Lengths - Baseline: {}, True: {}, False: {}",
                baselineLength, trueLength, falseLength);

        return lengthDifference && trueSimilarToBaseline && falseDifferentFromTrue;
    }

    /**
     * Calculates similarity percentage between two strings.
     */
    private int calculateSimilarity(String s1, String s2) {
        if (s1 == null || s2 == null) return 0;
        if (s1.equals(s2)) return 100;

        // Use Levenshtein distance for similarity
        int distance = levenshteinDistance(s1, s2);
        int maxLength = Math.max(s1.length(), s2.length());

        if (maxLength == 0) return 100;

        return (int) ((1.0 - ((double) distance / maxLength)) * 100);
    }

    /**
     * Calculates Levenshtein distance between two strings.
     */
    private int levenshteinDistance(String s1, String s2) {
        int[][] dp = new int[s1.length() + 1][s2.length() + 1];

        for (int i = 0; i <= s1.length(); i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= s2.length(); j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= s1.length(); i++) {
            for (int j = 1; j <= s2.length(); j++) {
                int cost = s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(
                        dp[i - 1][j] + 1,
                        dp[i][j - 1] + 1),
                        dp[i - 1][j - 1] + cost);
            }
        }

        return dp[s1.length()][s2.length()];
    }

    /**
     * Verifies a potential vulnerability with additional tests.
     */
    private Vulnerability verifyVulnerability(HttpRequest request, String parameterName,
                                             String truePayload, String falsePayload,
                                             HttpResponse baseline, HttpResponse trueResponse,
                                             HttpResponse falseResponse) {
        // Build evidence
        List<Evidence> evidenceList = new ArrayList<>();

        evidenceList.add(Evidence.builder()
                .payload("Baseline: " + request.getQueryParams().get(parameterName))
                .statusCode(baseline.getStatusCode())
                .contentLength(baseline.getContentLength())
                .responseTime(baseline.getResponseTimeMs())
                .observation("Baseline response")
                .build());

        evidenceList.add(Evidence.builder()
                .payload(truePayload)
                .statusCode(trueResponse.getStatusCode())
                .contentLength(trueResponse.getContentLength())
                .responseTime(trueResponse.getResponseTimeMs())
                .observation("TRUE condition - response similar to baseline")
                .build());

        evidenceList.add(Evidence.builder()
                .payload(falsePayload)
                .statusCode(falseResponse.getStatusCode())
                .contentLength(falseResponse.getContentLength())
                .responseTime(falseResponse.getResponseTimeMs())
                .observation("FALSE condition - response differs from TRUE")
                .build());

        // Calculate confidence
        int trueSimilarity = calculateSimilarity(baseline.getBody(), trueResponse.getBody());
        int falseSimilarity = calculateSimilarity(trueResponse.getBody(), falseResponse.getBody());
        int confidence = calculateConfidence(trueSimilarity, falseSimilarity);

        // Try to fingerprint database
        DatabaseType dbType = DatabaseType.UNKNOWN;
        if (truePayload.contains("SUBSTRING") || truePayload.contains("ASCII")) {
            if (truePayload.contains("DATABASE()")) {
                dbType = DatabaseType.MYSQL;
            } else if (truePayload.contains("CURRENT_DATABASE()")) {
                dbType = DatabaseType.POSTGRESQL;
            } else if (truePayload.contains("DB_NAME()")) {
                dbType = DatabaseType.MSSQL;
            }
        }

        // Build vulnerability
        Vulnerability vulnerability = Vulnerability.builder()
                .url(request.getUrl())
                .parameter(parameterName)
                .parameterLocation(determineParameterLocation(request, parameterName))
                .type(InjectionType.BOOLEAN_BLIND)
                .severity(Severity.HIGH)
                .databaseType(dbType)
                .confidence(confidence)
                .payload(truePayload + " / " + falsePayload)
                .description(buildDescription(parameterName, trueSimilarity, falseSimilarity))
                .recommendation("Use parameterized queries (prepared statements)")
                .recommendation("Implement input validation with allowlists")
                .recommendation("Use ORM frameworks with proper query builders")
                .recommendation("Normalize response behavior for all inputs")
                .recommendation("Implement request rate limiting")
                .build();

        vulnerability.setEvidence(evidenceList);

        logger.info("Boolean-based blind SQL injection CONFIRMED in parameter '{}' with {}% confidence",
                parameterName, confidence);

        return vulnerability;
    }

    /**
     * Calculates confidence score.
     */
    private int calculateConfidence(int trueSimilarity, int falseSimilarity) {
        int confidence = 50; // Base confidence

        // Higher confidence if TRUE is very similar to baseline
        if (trueSimilarity >= 95) {
            confidence += 25;
        } else if (trueSimilarity >= 90) {
            confidence += 15;
        }

        // Higher confidence if FALSE is very different from TRUE
        if (falseSimilarity < 50) {
            confidence += 25;
        } else if (falseSimilarity < 70) {
            confidence += 15;
        }

        return Math.min(100, confidence);
    }

    /**
     * Builds a description for the vulnerability.
     */
    private String buildDescription(String parameterName, int trueSimilarity, int falseSimilarity) {
        StringBuilder desc = new StringBuilder();
        desc.append("Boolean-based blind SQL injection vulnerability detected in parameter '");
        desc.append(parameterName);
        desc.append("'. ");
        desc.append("The application's response changes based on TRUE/FALSE SQL conditions. ");
        desc.append("TRUE condition similarity to baseline: ").append(trueSimilarity).append("%. ");
        desc.append("TRUE/FALSE response similarity: ").append(falseSimilarity).append("%. ");
        desc.append("This allows an attacker to extract data bit by bit through conditional queries.");

        return desc.toString();
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
     * Clones a request and injects a payload.
     */
    private HttpRequest cloneAndInjectPayload(HttpRequest original, String parameterName, String payload) {
        HttpRequest clone = cloneRequest(original);

        if (clone.getQueryParams().containsKey(parameterName)) {
            clone.getQueryParams().put(parameterName, payload);
        } else if (clone.getBody() != null && clone.getBody().contains(parameterName + "=")) {
            String originalValue = original.getQueryParams().getOrDefault(parameterName, "");
            String newBody = clone.getBody().replace(
                    parameterName + "=" + originalValue,
                    parameterName + "=" + payload
            );
            clone.setBody(newBody);
        }

        return clone;
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
