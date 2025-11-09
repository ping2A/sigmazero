#!/bin/bash

# Test script for Sigma Evaluator

echo "================================"
echo "Testing Sigma Rule Evaluator"
echo "================================"
echo ""

# Check if binary exists
BINARY="./target/release/sigma-zero"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Building first..."
    ./build.sh
    if [ $? -ne 0 ]; then
        echo "Build failed. Cannot run tests."
        exit 1
    fi
fi

echo "Running example evaluation..."
echo ""

# Run the evaluator with example data
$BINARY -r ./examples/rules -l ./examples/logs -v

if [ $? -eq 0 ]; then
    echo ""
    echo "================================"
    echo "Test completed successfully!"
    echo "================================"
    echo ""
    echo "The evaluator should have detected several matches:"
    echo "  - Suspicious PowerShell execution with encoded command"
    echo "  - Connection to malicious domains"
    echo "  - Suspicious process executions (mimikatz, wscript)"
    echo "  - Privilege escalation attempts"
else
    echo ""
    echo "Test failed. Please check the error messages above."
    exit 1
fi

echo ""
echo "To run with different data:"
echo "  $BINARY -r <rules-dir> -l <logs-path>"
echo ""
echo "For more options:"
echo "  $BINARY --help"
