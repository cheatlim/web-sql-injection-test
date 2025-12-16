package com.security.sqli.reporter.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents the overall result of a SQL injection scan.
 */
public class ScanResult {
    private String targetUrl;
    private int totalParametersTested;
    private List<VulnerabilityReport> vulnerabilities;
    private long startTimeMs;
    private long endTimeMs;
    private int totalPayloadsTested;

    public ScanResult() {
        this.vulnerabilities = new ArrayList<>();
        this.startTimeMs = System.currentTimeMillis();
    }

    public void finish() {
        this.endTimeMs = System.currentTimeMillis();
    }

    public int getVulnerabilityCount() {
        return vulnerabilities.size();
    }

    public int getCriticalCount() {
        return (int) vulnerabilities.stream()
                .filter(v -> "CRITICAL".equalsIgnoreCase(v.getSeverity()))
                .count();
    }

    public int getHighCount() {
        return (int) vulnerabilities.stream()
                .filter(v -> "HIGH".equalsIgnoreCase(v.getSeverity()))
                .count();
    }

    public int getMediumCount() {
        return (int) vulnerabilities.stream()
                .filter(v -> "MEDIUM".equalsIgnoreCase(v.getSeverity()))
                .count();
    }

    public int getLowCount() {
        return (int) vulnerabilities.stream()
                .filter(v -> "LOW".equalsIgnoreCase(v.getSeverity()))
                .count();
    }

    public double getDurationSeconds() {
        return (endTimeMs - startTimeMs) / 1000.0;
    }

    // Getters and setters
    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public int getTotalParametersTested() {
        return totalParametersTested;
    }

    public void setTotalParametersTested(int totalParametersTested) {
        this.totalParametersTested = totalParametersTested;
    }

    public List<VulnerabilityReport> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<VulnerabilityReport> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public void addVulnerability(VulnerabilityReport vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }

    public long getStartTimeMs() {
        return startTimeMs;
    }

    public void setStartTimeMs(long startTimeMs) {
        this.startTimeMs = startTimeMs;
    }

    public long getEndTimeMs() {
        return endTimeMs;
    }

    public void setEndTimeMs(long endTimeMs) {
        this.endTimeMs = endTimeMs;
    }

    public int getTotalPayloadsTested() {
        return totalPayloadsTested;
    }

    public void setTotalPayloadsTested(int totalPayloadsTested) {
        this.totalPayloadsTested = totalPayloadsTested;
    }
}
