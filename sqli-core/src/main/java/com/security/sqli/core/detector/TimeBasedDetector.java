package com.security.sqli.core.detector;

import com.security.sqli.core.http.HttpClient;
import com.security.sqli.core.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Detector for Time-based blind SQL injection vulnerabilities.
 *
 * Time-based blind SQL injection occurs when the application's response time
 * can be controlled through SQL time delay functions (e.g., SLEEP, WAITFOR).
 *
 * AUTHORIZATION REQUIRED: This detector must only be used against systems
 * you own or have explicit written permission to test.
 */
public class TimeBasedDetector {
    private static final Logger logger = LoggerFactory.getLogger(TimeBasedDetector.class);

    private final HttpClient httpClient;
    private static final int TIME_THRESHOLD_MS = 3000; // Minimum delay to consider significant
    private static final double TIME_CORRELATION = 0.8; // 80% correlation required

    public TimeBasedDetector(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Tests a URL parameter for Time-based blind SQL injection.
     *
     * @param request Base HTTP request
     * @param parameterName Parameter to test
     * @param originalValue Original parameter value
     * @param payloadSets List of payload sets with different delays
     * @return Vulnerability if found, null otherwise
     */
    public Vulnerability testParameter(HttpRequest request, String parameterName,
                                      String originalValue, List<TimePayloadSet> payloadSets) {
        logger.info("Testing parameter '{}' for Time-based blind SQL injection", parameterName);

        // Get baseline response time (average of 3 requests)
        long baselineTime = getBaselineResponseTime(request);
        logger.debug("Baseline response time: {}ms", baselineTime);

        // Test each payload set
        for (TimePayloadSet payloadSet : payloadSets) {
            boolean vulnerable = testPayloadSet(request, parameterName, payloadSet, baselineTime);

            if (vulnerable) {
                logger.info("Time-based blind SQL injection detected with payload set: {}",
                        payloadSet.getDatabaseType());

                return verifyVulnerability(request, parameterName, payloadSet, baselineTime);
            }
        }

        logger.info("No Time-based blind SQL injection found in parameter '{}'", parameterName);
        return null;
    }

    /**
     * Tests a payload set with different delay values.
     */
    private boolean testPayloadSet(HttpRequest request, String parameterName,
                                   TimePayloadSet payloadSet, long baselineTime) {
        List<Long> delays = new ArrayList<>();
        List<Long> expectedDelays = new ArrayList<>();

        // Test each payload in the set
        for (TimePayload payload : payloadSet.getPayloads()) {
            HttpRequest injectedRequest = cloneAndInjectPayload(request, parameterName, payload.getPayload());
            HttpResponse response = httpClient.execute(injectedRequest);

            if (!response.isSuccessful()) {
                return false;
            }

            long actualDelay = response.getResponseTimeMs() - baselineTime;
            delays.add(actualDelay);
            expectedDelays.add(payload.getExpectedDelayMs());

            logger.debug("Payload: {}, Expected delay: {}ms, Actual delay: {}ms",
                    payload.getPayload(), payload.getExpectedDelayMs(), actualDelay);
        }

        // Check if delays correlate with expected delays
        return checkTimeCorrelation(delays, expectedDelays);
    }

    /**
     * Checks if actual delays correlate with expected delays.
     */
    private boolean checkTimeCorrelation(List<Long> actualDelays, List<Long> expectedDelays) {
        if (actualDelays.size() != expectedDelays.size() || actualDelays.isEmpty()) {
            return false;
        }

        // Check each delay meets threshold
        for (int i = 0; i < actualDelays.size(); i++) {
            long actual = actualDelays.get(i);
            long expected = expectedDelays.get(i);

            // For zero delay, actual should be close to zero
            if (expected == 0) {
                if (actual > TIME_THRESHOLD_MS) {
                    return false;
                }
                continue;
            }

            // For non-zero delay, check if actual is close to expected
            double ratio = (double) actual / expected;

            // Actual should be within 80-120% of expected
            if (ratio < TIME_CORRELATION || ratio > 1.5) {
                logger.debug("Time correlation failed: actual={}ms, expected={}ms, ratio={}",
                        actual, expected, ratio);
                return false;
            }
        }

        // Calculate Pearson correlation coefficient
        double correlation = calculateCorrelation(actualDelays, expectedDelays);
        logger.debug("Pearson correlation coefficient: {}", correlation);

        return correlation >= TIME_CORRELATION;
    }

    /**
     * Calculates Pearson correlation coefficient.
     */
    private double calculateCorrelation(List<Long> x, List<Long> y) {
        int n = x.size();
        if (n == 0) return 0.0;

        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumY2 = 0;

        for (int i = 0; i < n; i++) {
            double xi = x.get(i);
            double yi = y.get(i);

            sumX += xi;
            sumY += yi;
            sumXY += xi * yi;
            sumX2 += xi * xi;
            sumY2 += yi * yi;
        }

        double numerator = n * sumXY - sumX * sumY;
        double denominator = Math.sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));

        if (denominator == 0) return 0.0;

        return numerator / denominator;
    }

    /**
     * Gets baseline response time by averaging multiple requests.
     */
    private long getBaselineResponseTime(HttpRequest request) {
        long totalTime = 0;
        int samples = 3;

        for (int i = 0; i < samples; i++) {
            HttpResponse response = httpClient.execute(request);
            if (response.isSuccessful()) {
                totalTime += response.getResponseTimeMs();
            }
        }

        return totalTime / samples;
    }

    /**
     * Verifies a potential vulnerability with additional tests.
     */
    private Vulnerability verifyVulnerability(HttpRequest request, String parameterName,
                                             TimePayloadSet payloadSet, long baselineTime) {
        List<Evidence> evidenceList = new ArrayList<>();

        // Add baseline evidence
        evidenceList.add(Evidence.builder()
                .payload("Baseline request")
                .responseTime(baselineTime)
                .observation("Average baseline response time")
                .build());

        // Test payloads again and collect evidence
        for (TimePayload payload : payloadSet.getPayloads()) {
            HttpRequest injectedRequest = cloneAndInjectPayload(request, parameterName, payload.getPayload());
            HttpResponse response = httpClient.execute(injectedRequest);

            long actualDelay = response.getResponseTimeMs() - baselineTime;

            String observation = String.format(
                    "Expected delay: %dms, Actual delay: %dms, Ratio: %.2f",
                    payload.getExpectedDelayMs(),
                    actualDelay,
                    actualDelay / (double) Math.max(1, payload.getExpectedDelayMs())
            );

            evidenceList.add(Evidence.builder()
                    .payload(payload.getPayload())
                    .responseTime(response.getResponseTimeMs())
                    .observation(observation)
                    .build());
        }

        // Determine database type
        DatabaseType dbType = mapDatabaseType(payloadSet.getDatabaseType());

        // Calculate confidence
        int confidence = calculateConfidence(payloadSet.getPayloads(), baselineTime);

        // Build vulnerability
        Vulnerability vulnerability = Vulnerability.builder()
                .url(request.getUrl())
                .parameter(parameterName)
                .parameterLocation(determineParameterLocation(request, parameterName))
                .type(InjectionType.TIME_BLIND)
                .severity(Severity.CRITICAL)
                .databaseType(dbType)
                .confidence(confidence)
                .payload(payloadSet.getPayloads().get(0).getPayload())
                .description(buildDescription(parameterName, dbType, baselineTime))
                .recommendation("Use parameterized queries (prepared statements)")
                .recommendation("Implement strict input validation")
                .recommendation("Use stored procedures with parameter binding")
                .recommendation("Implement query timeout limits")
                .recommendation("Monitor for unusual response times")
                .build();

        vulnerability.setEvidence(evidenceList);

        logger.info("Time-based blind SQL injection CONFIRMED in parameter '{}' with {}% confidence",
                parameterName, confidence);

        return vulnerability;
    }

    /**
     * Calculates confidence score.
     */
    private int calculateConfidence(List<TimePayload> payloads, long baselineTime) {
        int confidence = 60; // Base confidence for time-based

        // Higher confidence if multiple delays tested
        if (payloads.size() >= 3) {
            confidence += 20;
        }

        // Higher confidence if delays are significant
        for (TimePayload payload : payloads) {
            if (payload.getExpectedDelayMs() >= 5000) {
                confidence += 10;
                break;
            }
        }

        // Higher confidence if baseline is low
        if (baselineTime < 1000) {
            confidence += 10;
        }

        return Math.min(100, confidence);
    }

    /**
     * Maps database type string to enum.
     */
    private DatabaseType mapDatabaseType(String dbType) {
        if (dbType == null) return DatabaseType.UNKNOWN;

        switch (dbType.toLowerCase()) {
            case "mysql":
            case "mariadb":
                return DatabaseType.MYSQL;
            case "postgres":
            case "postgresql":
                return DatabaseType.POSTGRESQL;
            case "mssql":
            case "sqlserver":
                return DatabaseType.MSSQL;
            case "oracle":
                return DatabaseType.ORACLE;
            case "sqlite":
                return DatabaseType.SQLITE;
            default:
                return DatabaseType.UNKNOWN;
        }
    }

    /**
     * Builds a description for the vulnerability.
     */
    private String buildDescription(String parameterName, DatabaseType dbType, long baselineTime) {
        StringBuilder desc = new StringBuilder();
        desc.append("Time-based blind SQL injection vulnerability detected in parameter '");
        desc.append(parameterName);
        desc.append("'. ");

        if (dbType != DatabaseType.UNKNOWN) {
            desc.append("Database type identified as ").append(dbType.getDisplayName()).append(". ");
        }

        desc.append("The application's response time can be controlled through SQL time delay functions. ");
        desc.append("Baseline response time: ").append(baselineTime).append("ms. ");
        desc.append("Response times increase proportionally with SLEEP/WAITFOR values, ");
        desc.append("allowing an attacker to extract data bit by bit through timed conditional queries.");

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

    /**
     * Represents a time-based payload with expected delay.
     */
    public static class TimePayload {
        private final String payload;
        private final long expectedDelayMs;

        public TimePayload(String payload, long expectedDelayMs) {
            this.payload = payload;
            this.expectedDelayMs = expectedDelayMs;
        }

        public String getPayload() {
            return payload;
        }

        public long getExpectedDelayMs() {
            return expectedDelayMs;
        }
    }

    /**
     * Represents a set of time-based payloads for a specific database.
     */
    public static class TimePayloadSet {
        private final String databaseType;
        private final List<TimePayload> payloads;

        public TimePayloadSet(String databaseType) {
            this.databaseType = databaseType;
            this.payloads = new ArrayList<>();
        }

        public void addPayload(String payload, long expectedDelayMs) {
            payloads.add(new TimePayload(payload, expectedDelayMs));
        }

        public String getDatabaseType() {
            return databaseType;
        }

        public List<TimePayload> getPayloads() {
            return payloads;
        }
    }
}
