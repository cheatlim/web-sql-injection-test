#!/bin/bash

# SQL Injection Testing Framework - Build Script
#
# LEGAL WARNING: This tool is for AUTHORIZED security testing only.
# Unauthorized use may violate computer fraud and abuse laws.

set -e

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║      SQL Injection Testing Framework - Build Script               ║"
echo "║                                                                    ║"
echo "║  Building tool for AUTHORIZED security testing only.              ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Check for Java
if ! command -v java &> /dev/null; then
    echo "❌ Java is not installed. Please install Java 17 or higher."
    exit 1
fi

# Check Java version
JAVA_VERSION=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}' | awk -F '.' '{print $1}')
if [ "$JAVA_VERSION" -lt 17 ]; then
    echo "❌ Java 17 or higher is required. Current version: $JAVA_VERSION"
    exit 1
fi

echo "✓ Java version: OK"

# Check for Maven
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven is not installed. Please install Maven 3.8 or higher."
    exit 1
fi

echo "✓ Maven: OK"
echo ""

# Clean and build
echo "🔨 Building project..."
mvn clean package -DskipTests

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build successful!"
    echo ""
    echo "📦 Executable JAR created at:"
    echo "   sqli-cli/target/sqli-tester.jar"
    echo ""
    echo "🚀 To run the tool:"
    echo "   java -jar sqli-cli/target/sqli-tester.jar test --url <target-url>"
    echo ""
    echo "⚠️  REMINDER: Only use on systems you own or have permission to test!"
else
    echo ""
    echo "❌ Build failed. Please check the error messages above."
    exit 1
fi
