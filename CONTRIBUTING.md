# Contributing to SQL Injection Testing Framework

Thank you for your interest in contributing to this educational security testing tool! We welcome contributions that improve the framework while maintaining its ethical and educational focus.

## Code of Conduct

By participating in this project, you agree to:

1. Use the tool and contribute to it in an **ethical and legal manner**
2. Respect all applicable laws and regulations
3. Maintain the **educational focus** of the project
4. Be respectful and constructive in all interactions
5. Never contribute features designed for **malicious purposes**

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/yourusername/sqli-tester/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce the bug
   - Expected vs. actual behavior
   - Java version, OS, and other relevant details
   - Error messages and logs (if applicable)

### Suggesting Enhancements

1. Check existing [Issues](https://github.com/yourusername/sqli-tester/issues) and [Discussions](https://github.com/yourusername/sqli-tester/discussions)
2. Create a new issue with:
   - Clear description of the enhancement
   - Use cases and benefits
   - Potential implementation approach
   - Any security or legal considerations

### Pull Requests

1. **Fork** the repository
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Commit your changes** with clear messages:
   ```bash
   git commit -m "Add feature: description of feature"
   ```
7. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
8. **Create a Pull Request** with:
   - Clear description of changes
   - Reference to related issues
   - Test results
   - Screenshots (if applicable)

## Development Guidelines

### Code Style

- Follow standard Java conventions
- Use meaningful variable and method names
- Add JavaDoc comments for public APIs
- Keep methods focused and concise
- Maintain consistent formatting

### Testing

- Write unit tests for all new functionality
- Maintain or improve code coverage
- Test with multiple Java versions (17+)
- Include integration tests where appropriate

```bash
# Run all tests
mvn test

# Run tests with coverage
mvn clean verify
```

### Security Considerations

All contributions must:

1. **Include legal disclaimers** where appropriate
2. **Not bypass authorization checks** in the CLI
3. **Not add malicious payloads** designed solely for harm
4. **Maintain responsible disclosure** practices
5. **Follow security best practices** in code

### Documentation

- Update README.md for new features
- Add JavaDoc for public methods and classes
- Include usage examples
- Update CHANGELOG.md

## Project Structure

```
sqli-tester/
├── sqli-core/              # Core detection engine
├── sqli-payloads/          # Payload library
├── sqli-reporter/          # Report generation
└── sqli-cli/               # Command-line interface
```

## Acceptable Contributions

✅ **We welcome:**
- New detection techniques
- Additional database support
- Performance improvements
- Bug fixes
- Documentation improvements
- Test coverage improvements
- Reporting enhancements
- Educational resources

❌ **We do NOT accept:**
- Features designed for malicious use
- Bypasses for authorization checks
- Anti-detection/evasion focused solely on attacking
- Destructive payloads without safeguards
- Contributions that violate laws or ethics

## Legal Requirements

By contributing, you certify that:

1. You have the right to submit the contribution
2. You grant the project a perpetual, worldwide license to use your contribution
3. Your contribution does not violate any third-party rights
4. You understand this tool is for **authorized testing only**

## Review Process

1. All pull requests are reviewed by maintainers
2. We may request changes or clarifications
3. Once approved, changes will be merged
4. You'll be credited in the CONTRIBUTORS file

## Getting Help

- **Questions:** Use [GitHub Discussions](https://github.com/yourusername/sqli-tester/discussions)
- **Issues:** Use [GitHub Issues](https://github.com/yourusername/sqli-tester/issues)
- **Security:** Email security@example.com (do not create public issues)

## Recognition

All contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes for their contributions
- Project documentation

Thank you for helping make this educational tool better! 🙏

---

**Remember:** This project exists to help developers build more secure applications. All contributions should support this mission ethically and legally.
