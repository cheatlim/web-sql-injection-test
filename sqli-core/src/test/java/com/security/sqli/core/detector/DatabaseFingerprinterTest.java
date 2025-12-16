package com.security.sqli.core.detector;

import com.security.sqli.core.model.DatabaseType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for DatabaseFingerprinter.
 */
class DatabaseFingerprinterTest {

    @Test
    void testFingerprintMySQL() {
        String errorMessage = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";
        DatabaseType result = DatabaseFingerprinter.fingerprint(errorMessage);
        assertEquals(DatabaseType.MYSQL, result);
    }

    @Test
    void testFingerprintPostgreSQL() {
        String errorMessage = "ERROR: syntax error at or near \"'\" at character 15";
        DatabaseType result = DatabaseFingerprinter.fingerprint(errorMessage);
        assertEquals(DatabaseType.POSTGRESQL, result);
    }

    @Test
    void testFingerprintMSSQL() {
        String errorMessage = "[Microsoft][ODBC SQL Server Driver][SQL Server]Unclosed quotation mark after the character string";
        DatabaseType result = DatabaseFingerprinter.fingerprint(errorMessage);
        assertEquals(DatabaseType.MSSQL, result);
    }

    @Test
    void testFingerprintOracle() {
        String errorMessage = "ORA-00933: SQL command not properly ended";
        DatabaseType result = DatabaseFingerprinter.fingerprint(errorMessage);
        assertEquals(DatabaseType.ORACLE, result);
    }

    @Test
    void testFingerprintSQLite() {
        String errorMessage = "SQLite3::SQLException: near \"'\": syntax error";
        DatabaseType result = DatabaseFingerprinter.fingerprint(errorMessage);
        assertEquals(DatabaseType.SQLITE, result);
    }

    @Test
    void testFingerprintUnknown() {
        String errorMessage = "Some generic error message";
        DatabaseType result = DatabaseFingerprinter.fingerprint(errorMessage);
        assertEquals(DatabaseType.UNKNOWN, result);
    }

    @Test
    void testContainsDatabaseError() {
        String response = "Error: You have an error in your SQL syntax";
        assertTrue(DatabaseFingerprinter.containsDatabaseError(response));
    }

    @Test
    void testDoesNotContainDatabaseError() {
        String response = "Welcome to our website!";
        assertFalse(DatabaseFingerprinter.containsDatabaseError(response));
    }

    @Test
    void testNullInput() {
        DatabaseType result = DatabaseFingerprinter.fingerprint(null);
        assertEquals(DatabaseType.UNKNOWN, result);

        assertFalse(DatabaseFingerprinter.containsDatabaseError(null));
    }

    @Test
    void testEmptyInput() {
        DatabaseType result = DatabaseFingerprinter.fingerprint("");
        assertEquals(DatabaseType.UNKNOWN, result);

        assertFalse(DatabaseFingerprinter.containsDatabaseError(""));
    }
}
