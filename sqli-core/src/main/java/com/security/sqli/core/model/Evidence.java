package com.security.sqli.core.model;

/**
 * Evidence collected during SQL injection testing.
 */
public class Evidence {
    private String payload;
    private int statusCode;
    private String responseSnippet;
    private long responseTimeMs;
    private int contentLength;
    private String observation;

    public Evidence() {
    }

    public Evidence(String payload, String observation) {
        this.payload = payload;
        this.observation = observation;
    }

    public static EvidenceBuilder builder() {
        return new EvidenceBuilder();
    }

    // Getters and setters
    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getResponseSnippet() {
        return responseSnippet;
    }

    public void setResponseSnippet(String responseSnippet) {
        this.responseSnippet = responseSnippet;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public int getContentLength() {
        return contentLength;
    }

    public void setContentLength(int contentLength) {
        this.contentLength = contentLength;
    }

    public String getObservation() {
        return observation;
    }

    public void setObservation(String observation) {
        this.observation = observation;
    }

    public static class EvidenceBuilder {
        private final Evidence evidence;

        public EvidenceBuilder() {
            this.evidence = new Evidence();
        }

        public EvidenceBuilder payload(String payload) {
            evidence.payload = payload;
            return this;
        }

        public EvidenceBuilder statusCode(int statusCode) {
            evidence.statusCode = statusCode;
            return this;
        }

        public EvidenceBuilder responseSnippet(String snippet) {
            evidence.responseSnippet = snippet;
            return this;
        }

        public EvidenceBuilder responseTime(long timeMs) {
            evidence.responseTimeMs = timeMs;
            return this;
        }

        public EvidenceBuilder contentLength(int length) {
            evidence.contentLength = length;
            return this;
        }

        public EvidenceBuilder observation(String observation) {
            evidence.observation = observation;
            return this;
        }

        public Evidence build() {
            return evidence;
        }
    }
}
