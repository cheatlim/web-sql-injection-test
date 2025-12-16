package com.security.sqli.core.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents an HTTP response from a tested endpoint.
 */
public class HttpResponse {
    private int statusCode;
    private String body;
    private Map<String, String> headers;
    private long responseTimeMs;
    private String errorMessage;
    private boolean successful;

    public HttpResponse() {
        this.headers = new HashMap<>();
        this.successful = true;
    }

    public HttpResponse(int statusCode, String body, Map<String, String> headers, long responseTimeMs) {
        this.statusCode = statusCode;
        this.body = body;
        this.headers = headers != null ? headers : new HashMap<>();
        this.responseTimeMs = responseTimeMs;
        this.successful = true;
    }

    public static HttpResponse error(String errorMessage) {
        HttpResponse response = new HttpResponse();
        response.errorMessage = errorMessage;
        response.successful = false;
        return response;
    }

    // Getters and setters
    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public boolean isSuccessful() {
        return successful;
    }

    public void setSuccessful(boolean successful) {
        this.successful = successful;
    }

    public boolean hasError() {
        return !successful || errorMessage != null;
    }

    public int getContentLength() {
        return body != null ? body.length() : 0;
    }
}
