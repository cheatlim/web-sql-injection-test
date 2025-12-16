package com.security.sqli.core.model;

/**
 * Supported database types for SQL injection detection.
 */
public enum DatabaseType {
    MYSQL("MySQL"),
    MARIADB("MariaDB"),
    POSTGRESQL("PostgreSQL"),
    MSSQL("Microsoft SQL Server"),
    ORACLE("Oracle Database"),
    SQLITE("SQLite"),
    UNKNOWN("Unknown");

    private final String displayName;

    DatabaseType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
