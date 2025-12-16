package com.security.sqli.reporter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.security.sqli.reporter.model.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Generates JSON reports for SQL injection scan results.
 * JSON format is ideal for CI/CD integration and programmatic processing.
 */
public class JsonReportGenerator {
    private static final Logger logger = LoggerFactory.getLogger(JsonReportGenerator.class);
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    /**
     * Generates a JSON report from scan results.
     *
     * @param result Scan results
     * @param outputPath Path to output file
     * @throws IOException If writing fails
     */
    public void generateReport(ScanResult result, String outputPath) throws IOException {
        String json = objectMapper.writeValueAsString(result);

        Path path = Paths.get(outputPath);
        Files.createDirectories(path.getParent());
        Files.writeString(path, json);

        logger.info("JSON report generated: {}", outputPath);
    }

    /**
     * Converts scan results to JSON string.
     *
     * @param result Scan results
     * @return JSON string
     * @throws IOException If serialization fails
     */
    public String toJson(ScanResult result) throws IOException {
        return objectMapper.writeValueAsString(result);
    }
}
