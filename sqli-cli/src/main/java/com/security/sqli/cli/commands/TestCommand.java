package com.security.sqli.cli.commands;

import com.security.sqli.cli.service.ScanService;
import com.security.sqli.core.http.HttpClient;
import com.security.sqli.core.model.HttpMethod;
import com.security.sqli.core.model.HttpRequest;
import com.security.sqli.payloads.PayloadLibrary;
import com.security.sqli.reporter.ConsoleReporter;
import com.security.sqli.reporter.HtmlReportGenerator;
import com.security.sqli.reporter.JsonReportGenerator;
import com.security.sqli.reporter.model.ScanResult;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * Test command for scanning a single URL for SQL injection vulnerabilities.
 */
@Command(
    name = "test",
    description = "Test a single URL for SQL injection vulnerabilities"
)
public class TestCommand implements Callable<Integer> {

    @Parameters(
        index = "0",
        description = "Target URL to test (required)",
        arity = "0..1"
    )
    private String url;

    @Option(
        names = {"-u", "--url"},
        description = "Target URL to test"
    )
    private String urlOption;

    @Option(
        names = {"-m", "--method"},
        description = "HTTP method (GET, POST, PUT, etc.)",
        defaultValue = "GET"
    )
    private String method;

    @Option(
        names = {"-d", "--data"},
        description = "Request body data (for POST/PUT requests)"
    )
    private String data;

    @Option(
        names = {"-H", "--header"},
        description = "Custom headers (can be used multiple times)"
    )
    private Map<String, String> headers = new HashMap<>();

    @Option(
        names = {"-c", "--cookie"},
        description = "Cookies (can be used multiple times)"
    )
    private Map<String, String> cookies = new HashMap<>();

    @Option(
        names = {"--proxy"},
        description = "Proxy URL (e.g., http://localhost:8080)"
    )
    private String proxy;

    @Option(
        names = {"--timeout"},
        description = "Request timeout in milliseconds",
        defaultValue = "30000"
    )
    private int timeout;

    @Option(
        names = {"--mode"},
        description = "Scan mode: quick or deep",
        defaultValue = "quick"
    )
    private String mode;

    @Option(
        names = {"-o", "--output"},
        description = "Output file path for report (JSON or HTML based on extension)"
    )
    private String output;

    @Override
    public Integer call() throws Exception {
        // Use url parameter or urlOption
        String targetUrl = url != null ? url : urlOption;

        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            System.err.println("[ERROR] Target URL is required. Use --url or provide URL as argument.");
            return 1;
        }

        // Validate URL
        try {
            new URL(targetUrl);
        } catch (Exception e) {
            System.err.println("[ERROR] Invalid URL: " + targetUrl);
            return 1;
        }

        ConsoleReporter reporter = new ConsoleReporter();
        reporter.printBanner();

        // Parse proxy if provided
        String proxyHost = null;
        int proxyPort = 0;
        if (proxy != null) {
            try {
                URL proxyUrl = new URL(proxy);
                proxyHost = proxyUrl.getHost();
                proxyPort = proxyUrl.getPort();
                reporter.printInfo("Using proxy: " + proxyHost + ":" + proxyPort);
            } catch (Exception e) {
                reporter.printError("Invalid proxy URL: " + proxy);
                return 1;
            }
        }

        // Create HTTP client
        HttpClient httpClient = proxyHost != null ?
                new HttpClient(proxyHost, proxyPort) : new HttpClient();

        // Build HTTP request
        HttpRequest.HttpRequestBuilder requestBuilder = HttpRequest.builder()
                .url(targetUrl)
                .method(HttpMethod.valueOf(method.toUpperCase()))
                .timeout(timeout);

        // Add headers
        headers.forEach(requestBuilder::header);

        // Add cookies
        cookies.forEach(requestBuilder::cookie);

        // Add body if provided
        if (data != null && !data.isEmpty()) {
            requestBuilder.body(data);
            if (!headers.containsKey("Content-Type")) {
                requestBuilder.contentType("application/x-www-form-urlencoded");
            }
        }

        HttpRequest request = requestBuilder.build();

        // Initialize services
        PayloadLibrary payloadLibrary = new PayloadLibrary();
        ScanService scanService = new ScanService(httpClient, payloadLibrary, reporter);

        // Determine test mode
        boolean deepScan = "deep".equalsIgnoreCase(mode);

        reporter.printScanStart(targetUrl, method.toUpperCase());

        // Perform scan
        ScanResult result = scanService.scanUrl(request, deepScan);

        // Print results
        reporter.printScanSummary(result);

        // Print detailed vulnerability reports
        for (var vulnerability : result.getVulnerabilities()) {
            reporter.printVulnerabilityReport(vulnerability);
        }

        // Generate report file if requested
        if (output != null && !output.trim().isEmpty()) {
            try {
                if (output.toLowerCase().endsWith(".html")) {
                    HtmlReportGenerator htmlGenerator = new HtmlReportGenerator();
                    htmlGenerator.generateReport(result, output);
                    reporter.printSuccess("HTML report saved to: " + output);
                } else if (output.toLowerCase().endsWith(".json")) {
                    JsonReportGenerator jsonGenerator = new JsonReportGenerator();
                    jsonGenerator.generateReport(result, output);
                    reporter.printSuccess("JSON report saved to: " + output);
                } else {
                    reporter.printWarning("Unknown output format. Use .html or .json extension.");
                }
            } catch (Exception e) {
                reporter.printError("Failed to generate report: " + e.getMessage());
            }
        }

        // Return exit code: 0 if no vulnerabilities, 1 if vulnerabilities found
        return result.getVulnerabilityCount() > 0 ? 1 : 0;
    }
}
