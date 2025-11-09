#!/bin/bash

# Convenience script for generating test logs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$SCRIPT_DIR/target/release/generate_logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Sigma Log Generator Helper            ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo

# Check if binary exists
if [ ! -f "$BIN_PATH" ]; then
    echo -e "${YELLOW}Binary not found. Building...${NC}"
    cd "$SCRIPT_DIR"
    cargo build --release --bin generate_logs
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Build failed!${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Build successful${NC}"
    echo
fi

# If no arguments, show menu
if [ $# -eq 0 ]; then
    echo "Select a preset or use custom options:"
    echo
    echo "  1) Small test (1,000 events, 20% malicious)"
    echo "  2) Medium test (10,000 events, 20% malicious)"
    echo "  3) Large test (100,000 events, 20% malicious)"
    echo "  4) Performance test (1,000,000 events, 20% malicious)"
    echo "  5) High malicious (10,000 events, 50% malicious)"
    echo "  6) Week simulation (50,000 events over 7 days, 15% malicious)"
    echo "  7) Custom (specify parameters)"
    echo
    read -p "Enter choice [1-7]: " choice
    
    case $choice in
        1)
            echo -e "${BLUE}Generating small test...${NC}"
            "$BIN_PATH" -n 1000 -m 0.2 -o small_test.json
            ;;
        2)
            echo -e "${BLUE}Generating medium test...${NC}"
            "$BIN_PATH" -n 10000 -m 0.2 -o medium_test.json
            ;;
        3)
            echo -e "${BLUE}Generating large test...${NC}"
            "$BIN_PATH" -n 100000 -m 0.2 -o large_test.json
            ;;
        4)
            echo -e "${BLUE}Generating performance test...${NC}"
            "$BIN_PATH" -n 1000000 -m 0.2 -o perf_test.json
            ;;
        5)
            echo -e "${BLUE}Generating high malicious test...${NC}"
            "$BIN_PATH" -n 10000 -m 0.5 -o high_malicious.json
            ;;
        6)
            echo -e "${BLUE}Generating week simulation...${NC}"
            "$BIN_PATH" -n 50000 -m 0.15 -t 168 -o week_simulation.json
            ;;
        7)
            echo
            read -p "Number of events: " num
            read -p "Malicious percentage (0.0-1.0): " mal
            read -p "Output file: " out
            read -p "Time span (hours): " time
            
            echo -e "${BLUE}Generating custom logs...${NC}"
            "$BIN_PATH" -n "$num" -m "$mal" -o "$out" -t "$time"
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
    
    echo
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}Log generation complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo
    echo "Test the logs with:"
    echo -e "${YELLOW}  ./target/release/sigma-zero -r examples/rules -l <generated_file>${NC}"
    echo
else
    # Pass arguments directly to the binary
    "$BIN_PATH" "$@"
fi
