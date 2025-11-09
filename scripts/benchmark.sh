#!/bin/bash

# Benchmark script for Sigma Evaluator

echo "================================"
echo "Sigma Evaluator Benchmark"
echo "================================"
echo ""

BINARY="./target/release/sigma-zero"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Building first..."
    ./build.sh
    if [ $? -ne 0 ]; then
        echo "Build failed. Cannot run benchmark."
        exit 1
    fi
fi

# Create benchmark directory
BENCH_DIR="./benchmark_data"
mkdir -p "$BENCH_DIR"

echo "Generating test data..."
echo ""

# Function to generate log entries
generate_logs() {
    local count=$1
    local output=$2
    
    echo "Generating $count log entries to $output..."
    
    {
        for i in $(seq 1 $count); do
            # Generate varied log entries
            case $((i % 5)) in
                0)
                    echo "{\"timestamp\": \"2025-11-06T$(printf %02d $((i % 24))):$(printf %02d $((i % 60))):$(printf %02d $((i % 60)))Z\", \"event_type\": \"process_creation\", \"process_name\": \"powershell.exe\", \"command_line\": \"powershell.exe -enc ABC$i\", \"user\": \"user$i\"}"
                    ;;
                1)
                    echo "{\"timestamp\": \"2025-11-06T$(printf %02d $((i % 24))):$(printf %02d $((i % 60))):$(printf %02d $((i % 60)))Z\", \"event_type\": \"network_connection\", \"destination_domain\": \"example$i.com\", \"destination_ip\": \"192.168.$((i % 255)).$((i % 255))\", \"port\": $((i % 65535))}"
                    ;;
                2)
                    echo "{\"timestamp\": \"2025-11-06T$(printf %02d $((i % 24))):$(printf %02d $((i % 60))):$(printf %02d $((i % 60)))Z\", \"event_type\": \"file_access\", \"file_path\": \"/tmp/file$i.txt\", \"user\": \"user$((i % 100))\"}"
                    ;;
                3)
                    echo "{\"timestamp\": \"2025-11-06T$(printf %02d $((i % 24))):$(printf %02d $((i % 60))):$(printf %02d $((i % 60)))Z\", \"event_type\": \"process_creation\", \"process_name\": \"cmd.exe\", \"command_line\": \"cmd.exe /c echo test$i\", \"user\": \"user$i\"}"
                    ;;
                4)
                    echo "{\"timestamp\": \"2025-11-06T$(printf %02d $((i % 24))):$(printf %02d $((i % 60))):$(printf %02d $((i % 60)))Z\", \"event_type\": \"authentication\", \"user\": \"admin$((i % 10))\", \"action\": \"login\", \"status\": \"success\"}"
                    ;;
            esac
        done
    } > "$output"
}

# Test with different sizes
SIZES=(1000 10000 100000)
WORKERS=(1 2 4 8)

echo "System Information:"
echo "  CPU cores: $(nproc)"
echo "  Available memory: $(free -h | awk '/^Mem:/ {print $2}')"
echo ""

for size in "${SIZES[@]}"; do
    LOG_FILE="$BENCH_DIR/logs_${size}.json"
    
    # Generate logs if they don't exist
    if [ ! -f "$LOG_FILE" ]; then
        generate_logs $size "$LOG_FILE"
    fi
    
    echo "----------------------------------------"
    echo "Benchmark: $size log entries"
    echo "----------------------------------------"
    
    for workers in "${WORKERS[@]}"; do
        echo -n "  Workers: $workers - "
        
        # Run benchmark and capture time
        START=$(date +%s.%N)
        
        $BINARY -r ./examples/rules -l "$LOG_FILE" -w $workers > /dev/null 2>&1
        
        END=$(date +%s.%N)
        ELAPSED=$(echo "$END - $START" | bc)
        
        # Calculate throughput
        THROUGHPUT=$(echo "scale=2; $size / $ELAPSED" | bc)
        
        echo "Time: ${ELAPSED}s | Throughput: ${THROUGHPUT} logs/sec"
    done
    
    echo ""
done

echo "================================"
echo "Benchmark Complete"
echo "================================"
echo ""
echo "Test data location: $BENCH_DIR"
echo ""
echo "Observations:"
echo "  - Throughput should increase with more workers (up to CPU core count)"
echo "  - Larger datasets benefit more from parallelization"
echo "  - Optimal worker count typically matches CPU core count"
echo ""
echo "To clean up test data:"
echo "  rm -rf $BENCH_DIR"
