package com.security.sqli.payloads;

/**
 * Represents a SQL injection payload.
 *
 * LEGAL DISCLAIMER: These payloads are intended ONLY for authorized security testing
 * of systems you own or have explicit written permission to test.
 */
public class Payload {
    private String value;
    private String description;
    private PayloadType type;
    private String databaseType; // mysql, postgres, mssql, oracle, sqlite, all
    private int risk; // 1-5, where 1 is safest (read-only) and 5 is most aggressive

    public Payload(String value, PayloadType type, String databaseType) {
        this.value = value;
        this.type = type;
        this.databaseType = databaseType;
        this.risk = 1;
    }

    public Payload(String value, String description, PayloadType type, String databaseType, int risk) {
        this.value = value;
        this.description = description;
        this.type = type;
        this.databaseType = databaseType;
        this.risk = risk;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public PayloadType getType() {
        return type;
    }

    public void setType(PayloadType type) {
        this.type = type;
    }

    public String getDatabaseType() {
        return databaseType;
    }

    public void setDatabaseType(String databaseType) {
        this.databaseType = databaseType;
    }

    public int getRisk() {
        return risk;
    }

    public void setRisk(int risk) {
        this.risk = risk;
    }

    public enum PayloadType {
        ERROR_BASED,
        BOOLEAN_BLIND,
        TIME_BLIND,
        UNION_BASED,
        STACKED_QUERIES
    }
}
