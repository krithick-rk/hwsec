#!/bin/bash
set -e

echo "============================================"
echo "HWSEC Benchmark - All Safe Checks"
echo "============================================"
echo ""

BENCH_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL_COUNT=0
PASS_COUNT=0

run_case_tests() {
    local dir="$1"
    local label="$2"
    
    if [ ! -f "$dir/test_app.py" ]; then
        echo "  [SKIP] No test_app.py in $dir"
        return
    fi
    
    cd "$dir"
    
    if python3 -m pytest test_app.py -v 2>&1; then
        echo "  [PASS] $label"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  [FAIL] $label"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    cd "$BENCH_ROOT"
}

echo "--- Vulnerable Targets ---"
echo ""
echo "EASY:"
for dir in "$BENCH_ROOT"/benchmark_targets/easy/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    echo "  Testing: $name"
    run_case_tests "$dir" "$name"
done

echo ""
echo "MEDIUM:"
for dir in "$BENCH_ROOT"/benchmark_targets/medium/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    echo "  Testing: $name"
    run_case_tests "$dir" "$name"
done

echo ""
echo "HARD:"
for dir in "$BENCH_ROOT"/benchmark_targets/hard/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    echo "  Testing: $name"
    run_case_tests "$dir" "$name"
done

echo ""
echo "--- Fixed Solutions ---"
echo ""
echo "EASY FIXED:"
for dir in "$BENCH_ROOT"/solutions/easy/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    echo "  Testing: $name"
    run_case_tests "$dir" "$name"
done

echo ""
echo "MEDIUM FIXED:"
for dir in "$BENCH_ROOT"/solutions/medium/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    echo "  Testing: $name"
    run_case_tests "$dir" "$name"
done

echo ""
echo "HARD FIXED:"
for dir in "$BENCH_ROOT"/solutions/hard/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    echo "  Testing: $name"
    run_case_tests "$dir" "$name"
done

echo ""
echo "============================================"
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "============================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
