package com.security.sqli.core.detector;

import com.security.sqli.core.model.DatabaseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;

/**
 * Database fingerprinting utility to identify database type from error messages.
 */
public class DatabaseFingerprinter {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseFingerprinter.class);

    // MySQL/MariaDB error patterns
    private static final Pattern MYSQL_PATTERN = Pattern.compile(
            "SQL syntax.*?MySQL|" +
            "Warning.*?mysql_.*|" +
            "MySQLSyntaxErrorException|" +
            "valid MySQL result|" +
            "check the manual that corresponds to your (MySQL|MariaDB) server version|" +
            "Unknown column.*?in.*?field list|" +
            "MySqlClient\\.|" +
            "com\\.mysql\\.jdbc",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // PostgreSQL error patterns
    private static final Pattern POSTGRESQL_PATTERN = Pattern.compile(
            "PostgreSQL.*?ERROR|" +
            "Warning.*?\\Wpg_.*|" +
            "valid PostgreSQL result|" +
            "Npgsql\\.|" +
            "PG::SyntaxError|" +
            "org\\.postgresql\\.util\\.PSQLException|" +
            "ERROR:\\s*syntax error at or near",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // Microsoft SQL Server error patterns
    private static final Pattern MSSQL_PATTERN = Pattern.compile(
            "Driver.*? SQL[\\-\\_\\ ]*Server|" +
            "OLE DB.*? SQL Server|" +
            "\\[SQL Server\\]|" +
            "\\[Microsoft\\]\\[ODBC SQL Server Driver\\]|" +
            "\\[SQLServer JDBC Driver\\]|" +
            "\\[SqlException|" +
            "System\\.Data\\.SqlClient\\.SqlException|" +
            "Unclosed quotation mark after the character string|" +
            "Microsoft SQL Native Client error",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // Oracle error patterns
    private static final Pattern ORACLE_PATTERN = Pattern.compile(
            "\\bORA-[0-9][0-9][0-9][0-9]|" +
            "Oracle error|" +
            "Oracle.*?Driver|" +
            "Warning.*?\\Woci_.*|" +
            "Warning.*?\\Wora_.*|" +
            "oracle\\.jdbc\\.driver|" +
            "quoted string not properly terminated",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // SQLite error patterns
    private static final Pattern SQLITE_PATTERN = Pattern.compile(
            "SQLite/JDBCDriver|" +
            "SQLite\\.Exception|" +
            "System\\.Data\\.SQLite\\.SQLiteException|" +
            "Warning.*?\\W(sqlite_.*|SQLite3::)|" +
            "\\[SQLITE_ERROR\\]|" +
            "unrecognized token|" +
            "near \".*?\": syntax error",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    /**
     * Attempts to fingerprint the database type from an error message.
     *
     * @param errorMessage The error message from the response
     * @return Detected database type
     */
    public static DatabaseType fingerprint(String errorMessage) {
        if (errorMessage == null || errorMessage.isEmpty()) {
            return DatabaseType.UNKNOWN;
        }

        // Check for MySQL/MariaDB
        if (MYSQL_PATTERN.matcher(errorMessage).find()) {
            logger.info("Database fingerprinted as MySQL/MariaDB");
            return DatabaseType.MYSQL;
        }

        // Check for PostgreSQL
        if (POSTGRESQL_PATTERN.matcher(errorMessage).find()) {
            logger.info("Database fingerprinted as PostgreSQL");
            return DatabaseType.POSTGRESQL;
        }

        // Check for MSSQL
        if (MSSQL_PATTERN.matcher(errorMessage).find()) {
            logger.info("Database fingerprinted as Microsoft SQL Server");
            return DatabaseType.MSSQL;
        }

        // Check for Oracle
        if (ORACLE_PATTERN.matcher(errorMessage).find()) {
            logger.info("Database fingerprinted as Oracle");
            return DatabaseType.ORACLE;
        }

        // Check for SQLite
        if (SQLITE_PATTERN.matcher(errorMessage).find()) {
            logger.info("Database fingerprinted as SQLite");
            return DatabaseType.SQLITE;
        }

        return DatabaseType.UNKNOWN;
    }

    /**
     * Checks if a response contains a database error.
     *
     * @param responseBody The response body to check
     * @return True if a database error is detected
     */
    public static boolean containsDatabaseError(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return false;
        }

        return MYSQL_PATTERN.matcher(responseBody).find() ||
               POSTGRESQL_PATTERN.matcher(responseBody).find() ||
               MSSQL_PATTERN.matcher(responseBody).find() ||
               ORACLE_PATTERN.matcher(responseBody).find() ||
               SQLITE_PATTERN.matcher(responseBody).find();
    }
}
