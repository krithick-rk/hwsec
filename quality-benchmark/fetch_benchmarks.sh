#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================"
echo "  HWSEC Quality Benchmark Automated Setup & Ingestion "
echo "======================================================"

echo "[*] Phase 1: Creating target directory structure..."
mkdir -p c/juliet c/bigvul c/diversevul
mkdir -p cpp/juliet cpp/bigvul cpp/diversevul
mkdir -p java/juliet java/owasp-benchmark java/vul4j java/webgoat java/vulnerableapp
mkdir -p go/go-test-bench
mkdir -p python/pygoat
mkdir -p cross-project/selected-real-projects
mkdir -p manifests

clone_repo() {
    local name="$1"
    local dir="$2"
    local repo="$3"

    echo ""
    echo " -> Processing $name ($dir)..."
    if [ -d "$dir/.git" ]; then
        echo "    [!] Skipping clone: $dir already initialized."
    else
        rm -rf "$dir"
        echo "    [*] Executing: git clone --depth 1 $repo $dir"
        git clone --depth 1 "$repo" "$dir"
        echo "    [+] Successfully cloned $name"
    fi
}

echo ""
echo "[*] Phase 2: Fetching automated public benchmark repositories..."
clone_repo "OWASP Benchmark Java" "java/owasp-benchmark" "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
clone_repo "Vul4J" "java/vul4j" "https://github.com/tuhh-softsec/vul4j.git"
clone_repo "OWASP WebGoat" "java/webgoat" "https://github.com/WebGoat/WebGoat.git"
clone_repo "SasanLabs VulnerableApp" "java/vulnerableapp" "https://github.com/SasanLabs/VulnerableApp.git"
clone_repo "Go Test Bench" "go/go-test-bench" "https://github.com/Contrast-Security-OSS/go-test-bench.git"
clone_repo "OWASP PyGoat" "python/pygoat" "https://github.com/adeyosemanputra/pygoat.git"

echo ""
echo "======================================================"
echo " AUTOMATED FETCH COMPLETE"
echo "======================================================"
echo "Please refer to MANUAL_SETUP.md for manual dataset downloads."
