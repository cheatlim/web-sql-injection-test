package com.security.sqli.core.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents an HTTP request for SQL injection testing.
 *
 * WARNING: This class is designed for AUTHORIZED security testing only.
 * Unauthorized testing may violate laws such as the Computer Fraud and Abuse Act.
 */
public class HttpRequest {
    private String url;
    private HttpMethod method;
    private Map<String, String> headers;
    private Map<String, String> queryParams;
    private String body;
    private Map<String, String> cookies;
    private String contentType;
    private int timeoutMs;
    private boolean followRedirects;

    public HttpRequest() {
        this.method = HttpMethod.GET;
        this.headers = new HashMap<>();
        this.queryParams = new HashMap<>();
        this.cookies = new HashMap<>();
        this.contentType = "application/x-www-form-urlencoded";
        this.timeoutMs = 30000; // 30 seconds default
        this.followRedirects = true;
    }

    public static HttpRequestBuilder builder() {
        return new HttpRequestBuilder();
    }

    // Getters and setters
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public HttpMethod getMethod() {
        return method;
    }

    public void setMethod(HttpMethod method) {
        this.method = method;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public Map<String, String> getQueryParams() {
        return queryParams;
    }

    public void setQueryParams(Map<String, String> queryParams) {
        this.queryParams = queryParams;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public Map<String, String> getCookies() {
        return cookies;
    }

    public void setCookies(Map<String, String> cookies) {
        this.cookies = cookies;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public void setTimeoutMs(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public void setFollowRedirects(boolean followRedirects) {
        this.followRedirects = followRedirects;
    }

    public static class HttpRequestBuilder {
        private final HttpRequest request;

        public HttpRequestBuilder() {
            this.request = new HttpRequest();
        }

        public HttpRequestBuilder url(String url) {
            request.url = url;
            return this;
        }

        public HttpRequestBuilder method(HttpMethod method) {
            request.method = method;
            return this;
        }

        public HttpRequestBuilder header(String name, String value) {
            request.headers.put(name, value);
            return this;
        }

        public HttpRequestBuilder headers(Map<String, String> headers) {
            request.headers.putAll(headers);
            return this;
        }

        public HttpRequestBuilder queryParam(String name, String value) {
            request.queryParams.put(name, value);
            return this;
        }

        public HttpRequestBuilder queryParams(Map<String, String> params) {
            request.queryParams.putAll(params);
            return this;
        }

        public HttpRequestBuilder body(String body) {
            request.body = body;
            return this;
        }

        public HttpRequestBuilder cookie(String name, String value) {
            request.cookies.put(name, value);
            return this;
        }

        public HttpRequestBuilder cookies(Map<String, String> cookies) {
            request.cookies.putAll(cookies);
            return this;
        }

        public HttpRequestBuilder contentType(String contentType) {
            request.contentType = contentType;
            return this;
        }

        public HttpRequestBuilder timeout(int timeoutMs) {
            request.timeoutMs = timeoutMs;
            return this;
        }

        public HttpRequestBuilder followRedirects(boolean followRedirects) {
            request.followRedirects = followRedirects;
            return this;
        }

        public HttpRequest build() {
            if (request.url == null || request.url.isEmpty()) {
                throw new IllegalStateException("URL is required");
            }
            return request;
        }
    }
}
