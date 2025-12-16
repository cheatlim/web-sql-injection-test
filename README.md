# SQL Injection Testing Framework

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/java-17+-orange.svg)](https://www.oracle.com/java/)
[![Maven](https://img.shields.io/badge/maven-3.8+-red.svg)](https://maven.apache.org/)

An educational security testing tool for identifying SQL injection vulnerabilities in web applications through automated testing.

---

## ⚠️ LEGAL WARNING - READ CAREFULLY

```
╔════════════════════════════════════════════════════════════════════╗
║                    LEGAL NOTICE - IMPORTANT                        ║
║                                                                    ║
║  This tool is designed EXCLUSIVELY for:                           ║
║  • Authorized security testing of YOUR OWN systems                ║
║  • Educational purposes and learning about SQL injection          ║
║  • Testing applications with EXPLICIT WRITTEN PERMISSION          ║
║                                                                    ║
║  UNAUTHORIZED USE IS ILLEGAL AND MAY RESULT IN:                   ║
║  • Criminal prosecution under the CFAA (USA) or equivalent        ║
║  • Civil lawsuits and financial penalties                         ║
║  • Imprisonment                                                   ║
║                                                                    ║
║  By using this tool, you acknowledge that:                        ║
║  • You have proper authorization to test the target system        ║
║  • You accept full responsibility for your actions                ║
║  • The developers assume NO LIABILITY for misuse                  ║
╚════════════════════════════════════════════════════════════════════╝
```

---

## 📋 Overview

This framework helps developers and security professionals identify SQL injection vulnerabilities before malicious actors can exploit them. It supports multiple detection techniques and database types.

### Key Features

- **Multiple Detection Methods**
  - ✅ Error-based SQL injection
  - ✅ Boolean-based blind SQL injection (NEW!)
  - ✅ Time-based blind SQL injection (NEW!)
  - ✅ Union-based injection (NEW!)
  - Stacked queries detection

- **Multi-Database Support**
  - MySQL/MariaDB
  - PostgreSQL
  - Microsoft SQL Server
  - Oracle Database
  - SQLite
  - Automatic database fingerprinting

- **Advanced Parameter Testing** (NEW!)
  - Query parameters (GET)
  - Form data (POST)
  - JSON body parameters
  - XML body parameters
  - Headers and cookies

- **Professional Reporting**
  - Colored console output
  - HTML report generation (NEW!)
  - JSON report generation (NEW!)
  - Confidence scoring
  - Remediation guidance
  - Code examples

- **CI/CD Integration** (NEW!)
  - GitHub Actions workflow
  - GitLab CI/CD pipeline
  - Jenkins pipeline
  - Exit codes for automation
  - JSON output for parsing

---

## 🚀 Quick Start

### Prerequisites

- Java 17 or higher
- Maven 3.8 or higher

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sqli-tester.git
cd sqli-tester
```

2. Build the project:
```bash
mvn clean package
```

3. The executable JAR will be available at:
```bash
sqli-cli/target/sqli-tester.jar
```

### Basic Usage

**IMPORTANT:** You will be prompted to confirm authorization before any testing begins.

```bash
# Test a single URL
java -jar sqli-cli/target/sqli-tester.jar test --url "http://localhost:8080/api/users?id=1"

# Test with POST data
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/login" \
  --method POST \
  --data "username=admin&password=test"

# Deep scan with aggressive payloads
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/search?q=test" \
  --mode deep

# Test with authentication headers
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/data" \
  --header "Authorization=Bearer token123"

# Use with Burp Suite proxy
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/search?query=test" \
  --proxy http://localhost:8080

# Generate HTML report (NEW!)
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/users?id=1" \
  --output report.html

# Generate JSON report for CI/CD (NEW!)
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/users?id=1" \
  --output report.json

# Test JSON API endpoint (NEW!)
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/search" \
  --method POST \
  --data '{"query":"test","filters":{"category":"all"}}' \
  --header "Content-Type=application/json" \
  --output scan-results.html
```

---

## 📖 Documentation

### Command Line Options

```
Usage: sqli-tester test [OPTIONS]

Test a single URL for SQL injection vulnerabilities

Options:
  -u, --url <URL>              Target URL to test (required)
  -m, --method <METHOD>        HTTP method (GET, POST, PUT, etc.) [default: GET]
  -d, --data <DATA>            Request body data (for POST/PUT requests)
  -H, --header <KEY=VALUE>     Custom headers (can be used multiple times)
  -c, --cookie <KEY=VALUE>     Cookies (can be used multiple times)
  --proxy <URL>                Proxy URL (e.g., http://localhost:8080)
  --timeout <MS>               Request timeout in milliseconds [default: 30000]
  --mode <MODE>                Scan mode: quick or deep [default: quick]
  -y, --yes                    Skip authorization confirmation (NOT RECOMMENDED)
  -h, --help                   Show this help message
  -V, --version                Print version information
```

### Example Output

```
╔════════════════════════════════════════════════════════════════════╗
║           SQL Injection Testing Framework v1.0.0                  ║
║                                                                    ║
║  ⚠️  LEGAL WARNING - AUTHORIZED USE ONLY ⚠️                       ║
╚════════════════════════════════════════════════════════════════════╝

[*] Starting SQL Injection Scan
Target: http://localhost:8080/api/users
Method: GET

[~] Testing parameter 'id' for error-based injection
[!] Parameter 'id' - VULNERABLE - Error-Based SQL Injection detected

═══════════════════════════════════════════════════════════════════════
VULNERABILITY REPORT
═══════════════════════════════════════════════════════════════════════

[CRITICAL] Error-Based SQL Injection

URL:        http://localhost:8080/api/users
Parameter:  id
Method:     GET
Database:   MySQL
Confidence: 95%

EVIDENCE:
  Payload: '
  → Database error message detected in response
  Response: You have an error in your SQL syntax...

IMPACT:
  • Attacker can extract entire database contents
  • Can determine database structure
  • Possible privilege escalation
  • Data exfiltration and manipulation

REMEDIATION:
  ✓ Use parameterized queries (prepared statements)
  ✓ Implement input validation and sanitization
  ✓ Use ORM frameworks with proper escaping
  ✓ Disable detailed error messages in production
  ✓ Apply principle of least privilege to database accounts

SECURE CODE EXAMPLE:
  // ❌ Vulnerable
  String query = "SELECT * FROM users WHERE id = '" + id + "'";

  // ✅ Secure
  String query = "SELECT * FROM users WHERE id = ?";
  PreparedStatement stmt = conn.prepareStatement(query);
  stmt.setInt(1, id);

═══════════════════════════════════════════════════════════════════════
SCAN SUMMARY
═══════════════════════════════════════════════════════════════════════
Total Parameters Tested: 1
Vulnerabilities Found: 1

  Critical: 1
  High:     0
  Medium:   0
  Low:      0

Scan Duration: 2.34 seconds
Payloads Tested: 23
```

---

## 🏗️ Architecture

### Project Structure

```
sqli-tester/
├── sqli-core/              # Core detection engine
│   ├── http/               # HTTP client wrapper
│   ├── detector/           # Detection algorithms
│   └── model/              # Domain models
├── sqli-payloads/          # Payload library
│   └── payloads/           # Organized by technique and database
├── sqli-reporter/          # Report generation
│   ├── model/              # Report models
│   └── ConsoleReporter     # Colored console output
└── sqli-cli/               # Command-line interface
    ├── commands/           # CLI commands
    └── service/            # Orchestration services
```

### Detection Flow

```
Request → Payload Generator → Injector → Response Analyzer →
Verification → Evidence Collector → Report Generator
```

---

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
mvn test

# Run tests for specific module
mvn test -pl sqli-core

# Run with coverage
mvn clean verify
```

---

## 🔄 CI/CD Integration

The framework can be integrated into your CI/CD pipelines for automated security testing.

### GitHub Actions

See `.github/workflows/security-scan.yml` for a complete example:

```yaml
- name: Run SQL Injection Security Scan
  run: |
    java -jar sqli-cli/target/sqli-tester.jar test \
      --url "$TEST_URL/api/users?id=1" \
      --mode quick \
      --output reports/security-scan.json \
      --yes

- name: Check for vulnerabilities
  run: |
    VULN_COUNT=$(jq '.vulnerabilities | length' reports/security-scan.json)
    if [ "$VULN_COUNT" -gt 0 ]; then
      echo "❌ Security vulnerabilities detected!"
      exit 1
    fi
```

### GitLab CI/CD

See `.gitlab-ci.yml.example` for a complete pipeline configuration.

### Jenkins

See `Jenkinsfile.example` for a complete Jenkins Pipeline.

### Exit Codes

The tool returns appropriate exit codes for CI/CD integration:
- `0` - No vulnerabilities found
- `1` - Vulnerabilities detected or scan failed

### Report Formats for Automation

**JSON Output** (recommended for CI/CD):
```bash
java -jar sqli-tester.jar test \
  --url "http://api.example.com/endpoint" \
  --output results.json

# Parse results
jq '.vulnerabilities | length' results.json
jq '.vulnerabilities[] | select(.severity == "CRITICAL")' results.json
```

**HTML Output** (for human review):
```bash
java -jar sqli-tester.jar test \
  --url "http://api.example.com/endpoint" \
  --output results.html
```

---

## 🔒 Security Best Practices

### For Tool Users

1. **Always obtain written authorization** before testing any system
2. **Use safe mode first** (quick scan) before deep scanning
3. **Test in isolated environments** when possible
4. **Respect rate limits** to avoid DoS
5. **Document your testing activities** for compliance

### For Developers

1. **Use parameterized queries** (prepared statements)
2. **Implement input validation** with allowlists
3. **Apply least privilege** to database accounts
4. **Disable detailed error messages** in production
5. **Use ORM frameworks** with proper configuration
6. **Implement WAF rules** as defense-in-depth
7. **Regular security audits** and penetration testing

---

## 🎓 Educational Resources

### Understanding SQL Injection

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)

### Legal and Ethical Hacking

- [Computer Fraud and Abuse Act (CFAA)](https://www.justice.gov/jm/jm-9-48000-computer-fraud)
- [Responsible Disclosure Guidelines](https://www.bugcrowd.com/resources/responsible-disclosure-program/)
- [Ethical Hacking Resources](https://www.eccouncil.org/ethical-hacking/)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

**Note:** All contributions must maintain the educational and ethical focus of this project.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚖️ Responsible Disclosure

If you discover vulnerabilities in this tool itself, please report them responsibly:

1. **Do not** publicly disclose the vulnerability
2. Email details to: [security@example.com]
3. Allow reasonable time for a fix before disclosure

---

## 🙏 Acknowledgments

- OWASP for SQL injection research and documentation
- The security research community
- All contributors to this educational project

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/sqli-tester/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/sqli-tester/discussions)
- **Documentation:** [Wiki](https://github.com/yourusername/sqli-tester/wiki)

---

## ⚠️ Final Warning

**This tool is a weapon in the wrong hands.** Use it responsibly, ethically, and legally. The developers accept no responsibility for misuse. By using this tool, you agree to use it only for authorized testing and educational purposes.

**Remember:** With great power comes great responsibility.

---

**Stay ethical. Stay legal. Stay secure.** 🔒
