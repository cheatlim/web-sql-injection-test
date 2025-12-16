# SQL Injection Testing Framework - Usage Examples

⚠️ **IMPORTANT:** All examples assume you have proper authorization to test the target system.

## Table of Contents

1. [Basic Testing](#basic-testing)
2. [Advanced Testing](#advanced-testing)
3. [Testing Different Parameter Types](#testing-different-parameter-types)
4. [Integration with Burp Suite](#integration-with-burp-suite)
5. [Example Vulnerable Code](#example-vulnerable-code)

---

## Basic Testing

### Test a Simple GET Request

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/products?id=1"
```

### Test with Multiple Parameters

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/search?category=books&sort=price&page=1"
```

### Quick Scan Mode (Safe Payloads Only)

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/users?id=1" \
  --mode quick
```

### Deep Scan Mode (Comprehensive Testing)

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/users?id=1" \
  --mode deep
```

---

## Advanced Testing

### POST Request with Form Data

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/login" \
  --method POST \
  --data "username=admin&password=test123"
```

### POST Request with JSON Data

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/search" \
  --method POST \
  --data '{"query":"test","limit":10}' \
  --header "Content-Type=application/json"
```

### Testing with Authentication

```bash
# Bearer Token Authentication
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/profile?user_id=123" \
  --header "Authorization=Bearer eyJhbGciOiJIUzI1NiIs..."

# Basic Authentication
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/admin/users?id=1" \
  --header "Authorization=Basic YWRtaW46cGFzc3dvcmQ="
```

### Testing with Cookies

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/dashboard?page=1" \
  --cookie "session=abc123def456" \
  --cookie "user_pref=dark_mode"
```

### Testing with Custom Headers

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/data?filter=active" \
  --header "X-API-Key=secret123" \
  --header "X-Request-ID=req-001" \
  --header "User-Agent=SQLiTester/1.0"
```

---

## Testing Different Parameter Types

### Query Parameters (GET)

```bash
# Single parameter
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/user/profile?id=42"

# Multiple parameters
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/search?q=laptops&min_price=500&max_price=1500"
```

### Body Parameters (POST)

```bash
# Form data
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/comment/create" \
  --method POST \
  --data "post_id=123&comment=Nice article&author=John"

# JSON data
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/v1/orders" \
  --method POST \
  --data '{"product_id":"ABC123","quantity":1}' \
  --header "Content-Type=application/json"
```

### PUT Request

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/users/123" \
  --method PUT \
  --data '{"name":"John Doe","email":"john@example.com"}' \
  --header "Content-Type=application/json"
```

### DELETE Request

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/comments?id=456" \
  --method DELETE
```

---

## Integration with Burp Suite

### Using as Proxy Client

Test through Burp Suite to capture and manually verify requests:

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/search?q=test" \
  --proxy http://localhost:8080
```

**Burp Suite Configuration:**
1. Open Burp Suite
2. Go to Proxy → Options
3. Ensure proxy listener is on 127.0.0.1:8080
4. Run the command above
5. View intercepted requests in HTTP history

---

## Example Vulnerable Code

### Vulnerable Java Code (DO NOT USE IN PRODUCTION)

```java
// ❌ VULNERABLE - String concatenation
@GetMapping("/users")
public List<User> getUsers(@RequestParam String id) {
    String query = "SELECT * FROM users WHERE id = '" + id + "'";
    return jdbcTemplate.query(query, new UserRowMapper());
}

// ❌ VULNERABLE - String formatting
@GetMapping("/products")
public Product getProduct(@RequestParam String productId) {
    String query = String.format(
        "SELECT * FROM products WHERE product_id = '%s'",
        productId
    );
    return jdbcTemplate.queryForObject(query, new ProductRowMapper());
}
```

### How to Test These Vulnerabilities

```bash
# Test the vulnerable /users endpoint
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/users?id=1"

# Expected finding: Error-based SQL injection
# Payload: '
# Evidence: SQL syntax error in response
```

### Secure Code (USE THIS INSTEAD)

```java
// ✅ SECURE - Parameterized query with JdbcTemplate
@GetMapping("/users")
public List<User> getUsers(@RequestParam Long id) {
    String query = "SELECT * FROM users WHERE id = ?";
    return jdbcTemplate.query(query, new UserRowMapper(), id);
}

// ✅ SECURE - JPA with Spring Data
@GetMapping("/users")
public User getUser(@RequestParam Long id) {
    return userRepository.findById(id)
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));
}

// ✅ SECURE - Named parameters with NamedParameterJdbcTemplate
@GetMapping("/products")
public Product getProduct(@RequestParam String productId) {
    String query = "SELECT * FROM products WHERE product_id = :productId";
    Map<String, Object> params = Map.of("productId", productId);
    return namedParameterJdbcTemplate.queryForObject(
        query, params, new ProductRowMapper()
    );
}
```

---

## Testing Workflow Example

### Step 1: Initial Quick Scan

```bash
# Start with safe payloads
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/articles?id=1" \
  --mode quick
```

### Step 2: Deep Scan if Quick Scan Finds Issues

```bash
# If vulnerabilities found, run deeper scan
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/articles?id=1" \
  --mode deep
```

### Step 3: Manual Verification via Proxy

```bash
# Verify findings manually through Burp
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://localhost:8080/api/articles?id=1" \
  --proxy http://localhost:8080
```

### Step 4: Document and Report

After confirming the vulnerability:

1. Save the scan report
2. Document affected endpoints
3. Provide remediation recommendations
4. Report to development team
5. Verify fixes after patching

---

## Real-World Scenarios

### E-Commerce Product Search

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "https://shop.example.com/products/search?query=laptop&category=electronics" \
  --header "Cookie=session_id=xyz123"
```

### Blog Comment System

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "https://blog.example.com/api/comments" \
  --method POST \
  --data "post_id=42&author=John&comment=Great post!" \
  --header "X-CSRF-Token=abc123"
```

### User Profile Update

```bash
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "https://api.example.com/users/profile" \
  --method PUT \
  --data '{"user_id":123,"bio":"Developer"}' \
  --header "Content-Type=application/json" \
  --header "Authorization=Bearer token123"
```

---

## Interpreting Results

### No Vulnerabilities Found

```
[✓] Parameter 'id' - No vulnerabilities found

SCAN SUMMARY
Total Parameters Tested: 1
Vulnerabilities Found: 0
```

**Action:** Parameters appear safe, but consider additional manual testing.

### Vulnerability Detected

```
[!] Parameter 'id' - VULNERABLE - Error-Based SQL Injection detected

VULNERABILITY REPORT
[CRITICAL] Error-Based SQL Injection
URL:        http://localhost:8080/users
Parameter:  id
Confidence: 95%
```

**Action:**
1. Review the vulnerable code
2. Implement parameterized queries
3. Test the fix
4. Document the remediation

---

## Tips and Best Practices

1. **Start with Quick Scan:** Always begin with `--mode quick` to minimize risk
2. **Test in Staging First:** Never test production without approval
3. **Use Proxy for Verification:** Combine with Burp Suite for manual verification
4. **Document Everything:** Keep logs of all testing activities
5. **Rate Limiting:** Add delays between requests to avoid DoS
6. **Legal Authorization:** Always get written permission first

---

## Troubleshooting

### Connection Timeout

```bash
# Increase timeout
java -jar sqli-cli/target/sqli-tester.jar test \
  --url "http://slow-server.com/api/data?id=1" \
  --timeout 60000
```

### SSL/TLS Errors

For development/testing with self-signed certificates, ensure your Java trusts the certificate or use appropriate JVM flags (not recommended for production).

---

## Need Help?

- **Documentation:** See [README.md](README.md)
- **Issues:** [GitHub Issues](https://github.com/yourusername/sqli-tester/issues)
- **Security:** Report vulnerabilities privately to security@example.com

---

**Remember: Only test systems you own or have explicit written permission to test!** 🔒
