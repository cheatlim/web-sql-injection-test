package com.security.sqli.core.http;

import com.security.sqli.core.model.HttpRequest;
import com.security.sqli.core.model.HttpResponse;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * HTTP client wrapper for making requests during SQL injection testing.
 *
 * LEGAL WARNING: This client is designed EXCLUSIVELY for authorized security testing.
 * Unauthorized use against systems you do not own or have explicit permission to test
 * may violate computer fraud and abuse laws.
 */
public class HttpClient {
    private static final Logger logger = LoggerFactory.getLogger(HttpClient.class);

    private final OkHttpClient client;
    private final String proxyHost;
    private final int proxyPort;

    public HttpClient() {
        this(null, 0);
    }

    public HttpClient(String proxyHost, int proxyPort) {
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.client = buildClient();
    }

    private OkHttpClient buildClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .followRedirects(true)
                .followSslRedirects(true);

        // Add proxy if configured (useful for Burp Suite integration)
        if (proxyHost != null && !proxyHost.isEmpty() && proxyPort > 0) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
            builder.proxy(proxy);
            logger.info("HTTP client configured with proxy: {}:{}", proxyHost, proxyPort);
        }

        return builder.build();
    }

    /**
     * Executes an HTTP request and returns the response.
     *
     * @param httpRequest The request to execute
     * @return The HTTP response
     */
    public HttpResponse execute(HttpRequest httpRequest) {
        try {
            // Build URL with query parameters
            HttpUrl.Builder urlBuilder = HttpUrl.parse(httpRequest.getUrl()).newBuilder();
            for (Map.Entry<String, String> param : httpRequest.getQueryParams().entrySet()) {
                urlBuilder.addQueryParameter(param.getKey(), param.getValue());
            }
            HttpUrl url = urlBuilder.build();

            // Build request
            Request.Builder requestBuilder = new Request.Builder().url(url);

            // Add headers
            for (Map.Entry<String, String> header : httpRequest.getHeaders().entrySet()) {
                requestBuilder.addHeader(header.getKey(), header.getValue());
            }

            // Add cookies
            if (!httpRequest.getCookies().isEmpty()) {
                String cookieHeader = buildCookieHeader(httpRequest.getCookies());
                requestBuilder.addHeader("Cookie", cookieHeader);
            }

            // Build request body based on method
            RequestBody requestBody = null;
            if (httpRequest.getBody() != null && !httpRequest.getBody().isEmpty()) {
                MediaType mediaType = MediaType.parse(httpRequest.getContentType());
                requestBody = RequestBody.create(httpRequest.getBody(), mediaType);
            } else if (httpRequest.getMethod().name().equals("POST") ||
                       httpRequest.getMethod().name().equals("PUT") ||
                       httpRequest.getMethod().name().equals("PATCH")) {
                // Empty body for POST/PUT/PATCH if no body specified
                requestBody = RequestBody.create("", null);
            }

            // Set method
            switch (httpRequest.getMethod()) {
                case GET:
                    requestBuilder.get();
                    break;
                case POST:
                    requestBuilder.post(requestBody);
                    break;
                case PUT:
                    requestBuilder.put(requestBody);
                    break;
                case DELETE:
                    if (requestBody != null) {
                        requestBuilder.delete(requestBody);
                    } else {
                        requestBuilder.delete();
                    }
                    break;
                case PATCH:
                    requestBuilder.patch(requestBody);
                    break;
                case HEAD:
                    requestBuilder.head();
                    break;
                case OPTIONS:
                    requestBuilder.method("OPTIONS", null);
                    break;
            }

            Request request = requestBuilder.build();

            // Execute request and measure time
            long startTime = System.currentTimeMillis();
            try (Response response = client.newCall(request).execute()) {
                long endTime = System.currentTimeMillis();
                long responseTime = endTime - startTime;

                // Extract headers
                Map<String, String> responseHeaders = new HashMap<>();
                response.headers().names().forEach(name ->
                    responseHeaders.put(name, response.header(name))
                );

                // Extract body
                String responseBody = "";
                if (response.body() != null) {
                    responseBody = response.body().string();
                }

                return new HttpResponse(
                    response.code(),
                    responseBody,
                    responseHeaders,
                    responseTime
                );
            }

        } catch (IOException e) {
            logger.error("HTTP request failed: {}", e.getMessage());
            return HttpResponse.error("Request failed: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during HTTP request: {}", e.getMessage(), e);
            return HttpResponse.error("Unexpected error: " + e.getMessage());
        }
    }

    private String buildCookieHeader(Map<String, String> cookies) {
        StringBuilder cookieBuilder = new StringBuilder();
        for (Map.Entry<String, String> cookie : cookies.entrySet()) {
            if (cookieBuilder.length() > 0) {
                cookieBuilder.append("; ");
            }
            cookieBuilder.append(cookie.getKey()).append("=").append(cookie.getValue());
        }
        return cookieBuilder.toString();
    }

    /**
     * Creates a new HTTP client with proxy configuration.
     *
     * @param proxyHost Proxy hostname
     * @param proxyPort Proxy port
     * @return New HTTP client instance
     */
    public static HttpClient withProxy(String proxyHost, int proxyPort) {
        return new HttpClient(proxyHost, proxyPort);
    }
}
