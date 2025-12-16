package com.security.sqli.payloads;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PayloadLibrary.
 */
class PayloadLibraryTest {

    private PayloadLibrary payloadLibrary;

    @BeforeEach
    void setUp() {
        payloadLibrary = new PayloadLibrary();
    }

    @Test
    void testLibraryNotEmpty() {
        List<Payload> allPayloads = payloadLibrary.getAllPayloads();
        assertNotNull(allPayloads);
        assertFalse(allPayloads.isEmpty());
    }

    @Test
    void testGetErrorBasedPayloads() {
        List<Payload> payloads = payloadLibrary.getPayloadsByType(Payload.PayloadType.ERROR_BASED);
        assertNotNull(payloads);
        assertFalse(payloads.isEmpty());

        // Verify all returned payloads are error-based
        for (Payload payload : payloads) {
            assertEquals(Payload.PayloadType.ERROR_BASED, payload.getType());
        }
    }

    @Test
    void testGetBooleanBlindPayloads() {
        List<Payload> payloads = payloadLibrary.getPayloadsByType(Payload.PayloadType.BOOLEAN_BLIND);
        assertNotNull(payloads);
        assertFalse(payloads.isEmpty());

        for (Payload payload : payloads) {
            assertEquals(Payload.PayloadType.BOOLEAN_BLIND, payload.getType());
        }
    }

    @Test
    void testGetTimeBasedPayloads() {
        List<Payload> payloads = payloadLibrary.getPayloadsByType(Payload.PayloadType.TIME_BLIND);
        assertNotNull(payloads);
        assertFalse(payloads.isEmpty());

        for (Payload payload : payloads) {
            assertEquals(Payload.PayloadType.TIME_BLIND, payload.getType());
        }
    }

    @Test
    void testGetUnionBasedPayloads() {
        List<Payload> payloads = payloadLibrary.getPayloadsByType(Payload.PayloadType.UNION_BASED);
        assertNotNull(payloads);
        assertFalse(payloads.isEmpty());

        for (Payload payload : payloads) {
            assertEquals(Payload.PayloadType.UNION_BASED, payload.getType());
        }
    }

    @Test
    void testGetPayloadsByDatabase() {
        List<Payload> mysqlPayloads = payloadLibrary.getPayloadsByDatabase("mysql");
        assertNotNull(mysqlPayloads);
        assertFalse(mysqlPayloads.isEmpty());

        // Should include both "all" and "mysql" specific payloads
        for (Payload payload : mysqlPayloads) {
            assertTrue(payload.getDatabaseType().equals("all") ||
                      payload.getDatabaseType().equalsIgnoreCase("mysql"));
        }
    }

    @Test
    void testGetPayloadsByTypeAndDatabase() {
        List<Payload> payloads = payloadLibrary.getPayloads(
                Payload.PayloadType.ERROR_BASED, "mysql");
        assertNotNull(payloads);
        assertFalse(payloads.isEmpty());

        for (Payload payload : payloads) {
            assertEquals(Payload.PayloadType.ERROR_BASED, payload.getType());
            assertTrue(payload.getDatabaseType().equals("all") ||
                      payload.getDatabaseType().equalsIgnoreCase("mysql"));
        }
    }

    @Test
    void testGetSafePayloads() {
        List<Payload> safePayloads = payloadLibrary.getSafePayloads(Payload.PayloadType.ERROR_BASED);
        assertNotNull(safePayloads);
        assertFalse(safePayloads.isEmpty());

        // Verify all payloads have risk level <= 2
        for (Payload payload : safePayloads) {
            assertTrue(payload.getRisk() <= 2);
            assertEquals(Payload.PayloadType.ERROR_BASED, payload.getType());
        }
    }

    @Test
    void testBasicErrorPayloadsExist() {
        List<Payload> payloads = payloadLibrary.getPayloadsByType(Payload.PayloadType.ERROR_BASED);

        // Check for some basic payloads
        boolean hasSingleQuote = payloads.stream()
                .anyMatch(p -> p.getValue().equals("'"));
        assertTrue(hasSingleQuote, "Should contain single quote payload");

        boolean hasDoubleQuote = payloads.stream()
                .anyMatch(p -> p.getValue().equals("\""));
        assertTrue(hasDoubleQuote, "Should contain double quote payload");
    }

    @Test
    void testMySQLSpecificPayloads() {
        List<Payload> payloads = payloadLibrary.getPayloads(
                Payload.PayloadType.TIME_BLIND, "mysql");

        boolean hasSleepPayload = payloads.stream()
                .anyMatch(p -> p.getValue().contains("SLEEP"));
        assertTrue(hasSleepPayload, "MySQL payloads should include SLEEP function");
    }

    @Test
    void testPostgreSQLSpecificPayloads() {
        List<Payload> payloads = payloadLibrary.getPayloads(
                Payload.PayloadType.TIME_BLIND, "postgres");

        boolean hasPgSleepPayload = payloads.stream()
                .anyMatch(p -> p.getValue().contains("PG_SLEEP"));
        assertTrue(hasPgSleepPayload, "PostgreSQL payloads should include PG_SLEEP function");
    }

    @Test
    void testAllPayloadsHaveValues() {
        List<Payload> allPayloads = payloadLibrary.getAllPayloads();

        for (Payload payload : allPayloads) {
            assertNotNull(payload.getValue(), "Payload value should not be null");
            assertFalse(payload.getValue().isEmpty(), "Payload value should not be empty");
            assertNotNull(payload.getType(), "Payload type should not be null");
            assertNotNull(payload.getDatabaseType(), "Payload database type should not be null");
            assertTrue(payload.getRisk() >= 1 && payload.getRisk() <= 5,
                    "Risk level should be between 1 and 5");
        }
    }
}
