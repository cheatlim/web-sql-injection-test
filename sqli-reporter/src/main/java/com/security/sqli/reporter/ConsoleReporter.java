package com.security.sqli.reporter;

import com.security.sqli.reporter.model.ScanResult;
import com.security.sqli.reporter.model.VulnerabilityReport;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;

import static org.fusesource.jansi.Ansi.ansi;

/**
 * Console reporter with colored output for scan results.
 */
public class ConsoleReporter {

    static {
        AnsiConsole.systemInstall();
    }

    public void printBanner() {
        System.out.println(ansi().fgBrightYellow().bold().a(
            "\n╔════════════════════════════════════════════════════════════════════╗\n" +
            "║           SQL Injection Testing Framework v1.0.0                  ║\n" +
            "║                                                                    ║\n" +
            "║  ⚠️  LEGAL WARNING - AUTHORIZED USE ONLY ⚠️                       ║\n" +
            "║                                                                    ║\n" +
            "║  This tool is designed exclusively for authorized security        ║\n" +
            "║  testing of systems you own or have explicit written permission   ║\n" +
            "║  to test. Unauthorized use may violate laws including the         ║\n" +
            "║  Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.  ║\n" +
            "║                                                                    ║\n" +
            "║  By using this tool, you acknowledge that you:                    ║\n" +
            "║  • Have proper authorization to test the target system            ║\n" +
            "║  • Accept full responsibility for your actions                    ║\n" +
            "║  • Understand the legal implications of unauthorized testing      ║\n" +
            "╚════════════════════════════════════════════════════════════════════╝\n"
        ).reset());
    }

    public void printScanStart(String url, String method) {
        System.out.println(ansi().fgBrightCyan().bold().a("\n[*] Starting SQL Injection Scan").reset());
        System.out.println(ansi().fgWhite().a("Target: ").fgBrightWhite().a(url).reset());
        System.out.println(ansi().fgWhite().a("Method: ").fgBrightWhite().a(method).reset());
        System.out.println();
    }

    public void printTestingParameter(String parameter, String testType) {
        System.out.println(ansi().fgYellow().a("[~] Testing parameter '")
                .fgBrightYellow().a(parameter)
                .fgYellow().a("' for ")
                .a(testType)
                .reset());
    }

    public void printParameterSafe(String parameter) {
        System.out.println(ansi().fgGreen().a("[✓] Parameter '")
                .fgBrightGreen().a(parameter)
                .fgGreen().a("' - No vulnerabilities found")
                .reset());
    }

    public void printVulnerabilityFound(String parameter, String type) {
        System.out.println(ansi().fgRed().bold().a("[!] Parameter '")
                .fgBrightRed().a(parameter)
                .fgRed().a("' - VULNERABLE - ")
                .a(type)
                .a(" detected")
                .reset());
    }

    public void printScanSummary(ScanResult result) {
        System.out.println(ansi().fgBrightCyan().bold().a("\n" + "═".repeat(70)).reset());
        System.out.println(ansi().fgBrightCyan().bold().a("SCAN SUMMARY").reset());
        System.out.println(ansi().fgBrightCyan().bold().a("═".repeat(70)).reset());

        System.out.println(ansi().fgWhite().a("Total Parameters Tested: ")
                .fgBrightWhite().a(result.getTotalParametersTested()).reset());
        System.out.println(ansi().fgWhite().a("Vulnerabilities Found: ")
                .fgBrightRed().bold().a(result.getVulnerabilityCount()).reset());
        System.out.println();

        // Severity breakdown
        System.out.println(ansi().fgWhite().a("  Critical: ")
                .fgBrightRed().bold().a(result.getCriticalCount()).reset());
        System.out.println(ansi().fgWhite().a("  High:     ")
                .fgRed().a(result.getHighCount()).reset());
        System.out.println(ansi().fgWhite().a("  Medium:   ")
                .fgYellow().a(result.getMediumCount()).reset());
        System.out.println(ansi().fgWhite().a("  Low:      ")
                .fgBlue().a(result.getLowCount()).reset());
        System.out.println();

        System.out.println(ansi().fgWhite().a("Scan Duration: ")
                .fgBrightWhite().a(String.format("%.2f", result.getDurationSeconds()))
                .a(" seconds").reset());
        System.out.println(ansi().fgWhite().a("Payloads Tested: ")
                .fgBrightWhite().a(result.getTotalPayloadsTested()).reset());
        System.out.println();
    }

    public void printVulnerabilityReport(VulnerabilityReport report) {
        System.out.println(ansi().fgBrightRed().bold().a("\n" + "═".repeat(70)).reset());
        System.out.println(ansi().fgBrightRed().bold().a("VULNERABILITY REPORT").reset());
        System.out.println(ansi().fgBrightRed().bold().a("═".repeat(70)).reset());
        System.out.println();

        System.out.println(ansi().fgBrightRed().bold().a("[")
                .a(report.getSeverity().toUpperCase())
                .a("] ")
                .a(report.getType())
                .reset());
        System.out.println();

        System.out.println(ansi().fgWhite().a("URL:        ").fgBrightWhite().a(report.getUrl()).reset());
        System.out.println(ansi().fgWhite().a("Parameter:  ").fgBrightWhite().a(report.getParameter()).reset());
        System.out.println(ansi().fgWhite().a("Method:     ").fgBrightWhite().a(report.getMethod()).reset());
        if (report.getDatabaseType() != null && !report.getDatabaseType().equals("UNKNOWN")) {
            System.out.println(ansi().fgWhite().a("Database:   ").fgBrightWhite().a(report.getDatabaseType()).reset());
        }
        System.out.println(ansi().fgWhite().a("Confidence: ").fgBrightWhite().a(report.getConfidence() + "%").reset());
        System.out.println();

        // Evidence
        if (report.getEvidences() != null && !report.getEvidences().isEmpty()) {
            System.out.println(ansi().fgBrightYellow().bold().a("EVIDENCE:").reset());
            for (VulnerabilityReport.EvidenceReport evidence : report.getEvidences()) {
                System.out.println(ansi().fgWhite().a("  Payload: ").fgYellow().a(evidence.getPayload()).reset());
                if (evidence.getObservation() != null) {
                    System.out.println(ansi().fgWhite().a("  → ").a(evidence.getObservation()).reset());
                }
                if (evidence.getResponseSnippet() != null && !evidence.getResponseSnippet().isEmpty()) {
                    System.out.println(ansi().fgGray().a("  Response: ").a(evidence.getResponseSnippet()).reset());
                }
            }
            System.out.println();
        }

        // Impact
        System.out.println(ansi().fgBrightYellow().bold().a("IMPACT:").reset());
        System.out.println(ansi().fgWhite().a("  • Attacker can extract entire database contents").reset());
        System.out.println(ansi().fgWhite().a("  • Can determine database structure").reset());
        System.out.println(ansi().fgWhite().a("  • Possible privilege escalation").reset());
        System.out.println(ansi().fgWhite().a("  • Data exfiltration and manipulation").reset());
        System.out.println();

        // Remediation
        if (report.getRecommendations() != null && !report.getRecommendations().isEmpty()) {
            System.out.println(ansi().fgBrightGreen().bold().a("REMEDIATION:").reset());
            for (String recommendation : report.getRecommendations()) {
                System.out.println(ansi().fgWhite().a("  ✓ ").a(recommendation).reset());
            }
            System.out.println();
        }

        // Code example
        System.out.println(ansi().fgBrightGreen().bold().a("SECURE CODE EXAMPLE:").reset());
        System.out.println(ansi().fgGray().a("  // ❌ Vulnerable").reset());
        System.out.println(ansi().fgRed().a("  String query = \"SELECT * FROM users WHERE id = '\" + id + \"'\";\n").reset());
        System.out.println(ansi().fgGray().a("  // ✅ Secure").reset());
        System.out.println(ansi().fgGreen().a("  String query = \"SELECT * FROM users WHERE id = ?\";\n").reset());
        System.out.println(ansi().fgGreen().a("  PreparedStatement stmt = conn.prepareStatement(query);\n").reset());
        System.out.println(ansi().fgGreen().a("  stmt.setInt(1, id);\n").reset());
        System.out.println();

        System.out.println(ansi().fgBrightCyan().bold().a("═".repeat(70)).reset());
        System.out.println();
    }

    public void printError(String message) {
        System.err.println(ansi().fgBrightRed().bold().a("[ERROR] ").a(message).reset());
    }

    public void printWarning(String message) {
        System.out.println(ansi().fgBrightYellow().a("[WARNING] ").a(message).reset());
    }

    public void printInfo(String message) {
        System.out.println(ansi().fgBrightCyan().a("[INFO] ").a(message).reset());
    }

    public void printSuccess(String message) {
        System.out.println(ansi().fgBrightGreen().a("[SUCCESS] ").a(message).reset());
    }
}
