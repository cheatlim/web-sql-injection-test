package com.security.sqli.reporter;

import com.security.sqli.reporter.model.ScanResult;
import com.security.sqli.reporter.model.VulnerabilityReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Generates HTML reports for SQL injection scan results.
 */
public class HtmlReportGenerator {
    private static final Logger logger = LoggerFactory.getLogger(HtmlReportGenerator.class);

    /**
     * Generates an HTML report from scan results.
     *
     * @param result Scan results
     * @param outputPath Path to output file
     * @throws IOException If writing fails
     */
    public void generateReport(ScanResult result, String outputPath) throws IOException {
        String html = buildHtmlReport(result);

        Path path = Paths.get(outputPath);
        Files.createDirectories(path.getParent());
        Files.writeString(path, html);

        logger.info("HTML report generated: {}", outputPath);
    }

    /**
     * Builds the complete HTML report.
     */
    private String buildHtmlReport(ScanResult result) {
        StringBuilder html = new StringBuilder();

        html.append(buildHeader());
        html.append(buildSummarySection(result));

        if (!result.getVulnerabilities().isEmpty()) {
            html.append(buildVulnerabilitiesSection(result));
        }

        html.append(buildFooter());

        return html.toString();
    }

    /**
     * Builds the HTML header with CSS styles.
     */
    private String buildHeader() {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Test Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .warning-banner {
            background: #ff6b6b;
            color: white;
            padding: 20px;
            text-align: center;
            font-weight: bold;
        }

        .summary {
            padding: 40px;
            background: #f8f9fa;
            border-bottom: 3px solid #667eea;
        }

        .summary h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 2em;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .summary-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }

        .severity-critical { color: #e74c3c; }
        .severity-high { color: #e67e22; }
        .severity-medium { color: #f39c12; }
        .severity-low { color: #3498db; }

        .vulnerabilities {
            padding: 40px;
        }

        .vulnerability {
            background: white;
            border-left: 4px solid #e74c3c;
            margin-bottom: 30px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .vulnerability.high {
            border-left-color: #e67e22;
        }

        .vulnerability.medium {
            border-left-color: #f39c12;
        }

        .vulnerability.low {
            border-left-color: #3498db;
        }

        .vulnerability h3 {
            font-size: 1.8em;
            margin-bottom: 15px;
            color: #2c3e50;
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .severity-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }

        .badge-critical {
            background: #e74c3c;
            color: white;
        }

        .badge-high {
            background: #e67e22;
            color: white;
        }

        .badge-medium {
            background: #f39c12;
            color: white;
        }

        .badge-low {
            background: #3498db;
            color: white;
        }

        .vuln-details {
            margin: 20px 0;
        }

        .detail-row {
            display: flex;
            padding: 10px 0;
            border-bottom: 1px solid #ecf0f1;
        }

        .detail-label {
            font-weight: bold;
            width: 150px;
            color: #7f8c8d;
        }

        .detail-value {
            flex: 1;
            word-break: break-all;
        }

        .evidence {
            background: #f8f9fa;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }

        .evidence h4 {
            color: #667eea;
            margin-bottom: 15px;
        }

        .evidence-item {
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-left: 3px solid #667eea;
        }

        .code-block {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
        }

        .recommendations {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 20px;
            margin: 20px 0;
        }

        .recommendations h4 {
            color: #28a745;
            margin-bottom: 15px;
        }

        .recommendations ul {
            margin-left: 20px;
        }

        .recommendations li {
            margin: 8px 0;
            color: #155724;
        }

        .footer {
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
        }

        .footer p {
            margin: 5px 0;
        }

        .timestamp {
            color: #95a5a6;
            font-size: 0.9em;
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }

            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SQL Injection Test Report</h1>
            <p>Automated Security Testing Results</p>
        </div>

        <div class="warning-banner">
            ⚠️ CONFIDENTIAL - This report contains security vulnerability information. Handle with care.
        </div>
""";
    }

    /**
     * Builds the summary section.
     */
    private String buildSummarySection(ScanResult result) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        return String.format("""
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="timestamp">Generated: %s</div>

            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Target</h3>
                    <div class="value" style="font-size: 1.2em; word-break: break-all;">%s</div>
                </div>

                <div class="summary-card">
                    <h3>Parameters Tested</h3>
                    <div class="value">%d</div>
                </div>

                <div class="summary-card">
                    <h3>Vulnerabilities Found</h3>
                    <div class="value severity-critical">%d</div>
                </div>

                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <div class="value">%.2fs</div>
                </div>
            </div>

            <div class="summary-grid" style="margin-top: 20px;">
                <div class="summary-card">
                    <h3>Critical</h3>
                    <div class="value severity-critical">%d</div>
                </div>

                <div class="summary-card">
                    <h3>High</h3>
                    <div class="value severity-high">%d</div>
                </div>

                <div class="summary-card">
                    <h3>Medium</h3>
                    <div class="value severity-medium">%d</div>
                </div>

                <div class="summary-card">
                    <h3>Low</h3>
                    <div class="value severity-low">%d</div>
                </div>
            </div>
        </div>
""",
                timestamp,
                escapeHtml(result.getTargetUrl()),
                result.getTotalParametersTested(),
                result.getVulnerabilityCount(),
                result.getDurationSeconds(),
                result.getCriticalCount(),
                result.getHighCount(),
                result.getMediumCount(),
                result.getLowCount()
        );
    }

    /**
     * Builds the vulnerabilities section.
     */
    private String buildVulnerabilitiesSection(ScanResult result) {
        StringBuilder html = new StringBuilder();
        html.append("        <div class=\"vulnerabilities\">\n");
        html.append("            <h2>Detailed Findings</h2>\n\n");

        int count = 1;
        for (VulnerabilityReport vuln : result.getVulnerabilities()) {
            html.append(buildVulnerabilityCard(vuln, count++));
        }

        html.append("        </div>\n");
        return html.toString();
    }

    /**
     * Builds a single vulnerability card.
     */
    private String buildVulnerabilityCard(VulnerabilityReport vuln, int number) {
        String severityClass = vuln.getSeverity().toLowerCase();
        String badgeClass = "badge-" + severityClass;

        StringBuilder html = new StringBuilder();
        html.append(String.format("            <div class=\"vulnerability %s\">\n", severityClass));
        html.append("                <div class=\"vuln-header\">\n");
        html.append(String.format("                    <h3>%d. %s</h3>\n", number, escapeHtml(vuln.getType())));
        html.append(String.format("                    <span class=\"severity-badge %s\">%s</span>\n",
                badgeClass, vuln.getSeverity()));
        html.append("                </div>\n\n");

        // Details
        html.append("                <div class=\"vuln-details\">\n");
        html.append(buildDetailRow("URL", escapeHtml(vuln.getUrl())));
        html.append(buildDetailRow("Parameter", escapeHtml(vuln.getParameter())));
        html.append(buildDetailRow("Method", vuln.getMethod()));

        if (vuln.getDatabaseType() != null && !vuln.getDatabaseType().equals("UNKNOWN")) {
            html.append(buildDetailRow("Database", vuln.getDatabaseType()));
        }

        html.append(buildDetailRow("Confidence", vuln.getConfidence() + "%"));
        html.append("                </div>\n\n");

        // Description
        if (vuln.getDescription() != null) {
            html.append("                <div style=\"margin: 20px 0;\">\n");
            html.append("                    <h4>Description</h4>\n");
            html.append("                    <p>").append(escapeHtml(vuln.getDescription())).append("</p>\n");
            html.append("                </div>\n\n");
        }

        // Evidence
        if (vuln.getEvidences() != null && !vuln.getEvidences().isEmpty()) {
            html.append("                <div class=\"evidence\">\n");
            html.append("                    <h4>Evidence</h4>\n");

            for (VulnerabilityReport.EvidenceReport evidence : vuln.getEvidences()) {
                html.append("                    <div class=\"evidence-item\">\n");
                html.append("                        <strong>Payload:</strong> <code>")
                        .append(escapeHtml(evidence.getPayload())).append("</code><br>\n");

                if (evidence.getObservation() != null) {
                    html.append("                        <strong>Observation:</strong> ")
                            .append(escapeHtml(evidence.getObservation())).append("<br>\n");
                }

                if (evidence.getResponseSnippet() != null && !evidence.getResponseSnippet().isEmpty()) {
                    html.append("                        <strong>Response:</strong><br>\n");
                    html.append("                        <div class=\"code-block\">")
                            .append(escapeHtml(evidence.getResponseSnippet()))
                            .append("</div>\n");
                }

                html.append("                    </div>\n");
            }

            html.append("                </div>\n\n");
        }

        // Recommendations
        if (vuln.getRecommendations() != null && !vuln.getRecommendations().isEmpty()) {
            html.append("                <div class=\"recommendations\">\n");
            html.append("                    <h4>✅ Remediation Steps</h4>\n");
            html.append("                    <ul>\n");

            for (String recommendation : vuln.getRecommendations()) {
                html.append("                        <li>").append(escapeHtml(recommendation))
                        .append("</li>\n");
            }

            html.append("                    </ul>\n");
            html.append("                </div>\n");
        }

        html.append("            </div>\n\n");
        return html.toString();
    }

    /**
     * Builds a detail row.
     */
    private String buildDetailRow(String label, String value) {
        return String.format("""
                    <div class="detail-row">
                        <div class="detail-label">%s:</div>
                        <div class="detail-value">%s</div>
                    </div>
""", label, value);
    }

    /**
     * Builds the footer.
     */
    private String buildFooter() {
        return """
        <div class="footer">
            <p><strong>SQL Injection Testing Framework v1.0.0</strong></p>
            <p>Generated by automated security testing tool</p>
            <p style="margin-top: 15px; font-size: 0.9em;">
                ⚠️ This tool is for authorized security testing only.<br>
                Unauthorized use may violate computer fraud and abuse laws.
            </p>
        </div>
    </div>
</body>
</html>
""";
    }

    /**
     * Escapes HTML special characters.
     */
    private String escapeHtml(String text) {
        if (text == null) return "";

        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
