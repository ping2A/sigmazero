#!/bin/bash

# Build script for Sigma Evaluator

echo "================================"
echo "Building Sigma Rule Evaluator"
echo "================================"
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust is not installed."
    echo "Please install Rust from https://rustup.rs"
    exit 1
fi

echo "Rust version:"
rustc --version
echo ""

# Build in release mode
echo "Building in release mode (optimized)..."
cargo build --release

if [ $? -eq 0 ]; then
    echo ""
    echo "================================"
    echo "Build successful!"
    echo "================================"
    echo ""
    echo "Binary location: target/release/sigma-zero"
    echo ""
    echo "Run with:"
    echo "  ./target/release/sigma-zero --help"
    echo ""
    echo "Example usage:"
    echo "  ./target/release/sigma-zero -r ./examples/rules -l ./examples/logs"
else
    echo ""
    echo "Build failed. Please check the error messages above."
    exit 1
fi
