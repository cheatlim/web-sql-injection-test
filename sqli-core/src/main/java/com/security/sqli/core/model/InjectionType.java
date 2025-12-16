package com.security.sqli.core.model;

/**
 * Types of SQL injection vulnerabilities.
 */
public enum InjectionType {
    ERROR_BASED("Error-Based SQL Injection",
            "SQL errors are returned in the response, revealing database information"),

    BOOLEAN_BLIND("Boolean-Based Blind SQL Injection",
            "Application behavior changes based on TRUE/FALSE SQL conditions"),

    TIME_BLIND("Time-Based Blind SQL Injection",
            "Response time can be controlled through SQL time delay functions"),

    UNION_BASED("Union-Based SQL Injection",
            "UNION operator can be used to retrieve data from other tables"),

    STACKED_QUERIES("Stacked Queries SQL Injection",
            "Multiple SQL statements can be executed in a single query"),

    OUT_OF_BAND("Out-of-Band SQL Injection",
            "Data can be exfiltrated through DNS/HTTP requests");

    private final String displayName;
    private final String description;

    InjectionType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
