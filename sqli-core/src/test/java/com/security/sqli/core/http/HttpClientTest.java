package com.security.sqli.core.http;

import com.security.sqli.core.model.HttpMethod;
import com.security.sqli.core.model.HttpRequest;
import com.security.sqli.core.model.HttpResponse;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HttpClient using MockWebServer.
 */
class HttpClientTest {

    private MockWebServer mockWebServer;
    private HttpClient httpClient;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
        httpClient = new HttpClient();
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    void testSuccessfulGetRequest() throws InterruptedException {
        // Arrange
        mockWebServer.enqueue(new MockResponse()
                .setBody("Hello, World!")
                .setResponseCode(200));

        HttpRequest request = HttpRequest.builder()
                .url(mockWebServer.url("/test").toString())
                .method(HttpMethod.GET)
                .build();

        // Act
        HttpResponse response = httpClient.execute(request);

        // Assert
        assertTrue(response.isSuccessful());
        assertEquals(200, response.getStatusCode());
        assertEquals("Hello, World!", response.getBody());
        assertTrue(response.getResponseTimeMs() >= 0);

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertEquals("GET", recordedRequest.getMethod());
        assertEquals("/test", recordedRequest.getPath());
    }

    @Test
    void testPostRequestWithBody() throws InterruptedException {
        // Arrange
        mockWebServer.enqueue(new MockResponse()
                .setBody("Created")
                .setResponseCode(201));

        HttpRequest request = HttpRequest.builder()
                .url(mockWebServer.url("/api/data").toString())
                .method(HttpMethod.POST)
                .body("test=data")
                .contentType("application/x-www-form-urlencoded")
                .build();

        // Act
        HttpResponse response = httpClient.execute(request);

        // Assert
        assertTrue(response.isSuccessful());
        assertEquals(201, response.getStatusCode());
        assertEquals("Created", response.getBody());

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertEquals("POST", recordedRequest.getMethod());
        assertEquals("test=data", recordedRequest.getBody().readUtf8());
    }

    @Test
    void testRequestWithQueryParameters() throws InterruptedException {
        // Arrange
        mockWebServer.enqueue(new MockResponse()
                .setBody("OK")
                .setResponseCode(200));

        HttpRequest request = HttpRequest.builder()
                .url(mockWebServer.url("/search").toString())
                .method(HttpMethod.GET)
                .queryParam("q", "test")
                .queryParam("page", "1")
                .build();

        // Act
        HttpResponse response = httpClient.execute(request);

        // Assert
        assertTrue(response.isSuccessful());

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        String path = recordedRequest.getPath();
        assertTrue(path.contains("q=test"));
        assertTrue(path.contains("page=1"));
    }

    @Test
    void testRequestWithCustomHeaders() throws InterruptedException {
        // Arrange
        mockWebServer.enqueue(new MockResponse()
                .setBody("OK")
                .setResponseCode(200));

        HttpRequest request = HttpRequest.builder()
                .url(mockWebServer.url("/api").toString())
                .method(HttpMethod.GET)
                .header("Authorization", "Bearer token123")
                .header("X-Custom-Header", "value")
                .build();

        // Act
        HttpResponse response = httpClient.execute(request);

        // Assert
        assertTrue(response.isSuccessful());

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertEquals("Bearer token123", recordedRequest.getHeader("Authorization"));
        assertEquals("value", recordedRequest.getHeader("X-Custom-Header"));
    }

    @Test
    void testRequestWithCookies() throws InterruptedException {
        // Arrange
        mockWebServer.enqueue(new MockResponse()
                .setBody("OK")
                .setResponseCode(200));

        HttpRequest request = HttpRequest.builder()
                .url(mockWebServer.url("/api").toString())
                .method(HttpMethod.GET)
                .cookie("session", "abc123")
                .cookie("user", "john")
                .build();

        // Act
        HttpResponse response = httpClient.execute(request);

        // Assert
        assertTrue(response.isSuccessful());

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        String cookieHeader = recordedRequest.getHeader("Cookie");
        assertNotNull(cookieHeader);
        assertTrue(cookieHeader.contains("session=abc123"));
        assertTrue(cookieHeader.contains("user=john"));
    }

    @Test
    void testServerError() {
        // Arrange
        mockWebServer.enqueue(new MockResponse()
                .setBody("Internal Server Error")
                .setResponseCode(500));

        HttpRequest request = HttpRequest.builder()
                .url(mockWebServer.url("/error").toString())
                .method(HttpMethod.GET)
                .build();

        // Act
        HttpResponse response = httpClient.execute(request);

        // Assert
        assertTrue(response.isSuccessful()); // Request was successful, but server returned error
        assertEquals(500, response.getStatusCode());
    }

    @Test
    void testInvalidUrl() {
        // Arrange
        HttpRequest request = HttpRequest.builder()
                .url("http://invalid-host-that-does-not-exist-12345.com")
                .method(HttpMethod.GET)
                .build();

        // Act
        HttpResponse response = httpClient.execute(request);

        // Assert
        assertFalse(response.isSuccessful());
        assertTrue(response.hasError());
        assertNotNull(response.getErrorMessage());
    }
}
