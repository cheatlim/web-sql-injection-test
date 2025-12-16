package com.security.sqli.core.model;

/**
 * Severity levels for SQL injection vulnerabilities.
 */
public enum Severity {
    CRITICAL("Critical", 4),
    HIGH("High", 3),
    MEDIUM("Medium", 2),
    LOW("Low", 1),
    INFO("Informational", 0);

    private final String displayName;
    private final int level;

    Severity(String displayName, int level) {
        this.displayName = displayName;
        this.level = level;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getLevel() {
        return level;
    }
}
