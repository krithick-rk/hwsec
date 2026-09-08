$ErrorActionPreference = "Stop"

Write-Host "Creating subdirectories..." -ForegroundColor Cyan
$dirs = @(
    "c\juliet",
    "cpp\juliet",
    "java\juliet",
    "c\bigvul",
    "cpp\bigvul",
    "c\diversevul",
    "cpp\diversevul"
)
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# 1. NIST Juliet C/C++ v1.3 (~280 MB)
Write-Host "Downloading NIST Juliet C/C++ v1.3 (~280 MB)..." -ForegroundColor Yellow
$julietCppZip = "juliet_c_cpp.zip"
curl.exe -L -k -A "Mozilla/5.0" -o $julietCppZip "https://samate.nist.gov/SARD/test-suites/2017-10-01-juliet-c-cplusplus-v1-3.zip"

Write-Host "Extracting NIST Juliet C/C++..." -ForegroundColor Yellow
mkdir -p temp_juliet
tar.exe -xf $julietCppZip -C temp_juliet

if (Test-Path "temp_juliet\C") {
    Move-Item -Path "temp_juliet\C\*" -Destination "c\juliet\" -Force
    Move-Item -Path "temp_juliet\C++\*" -Destination "cpp\juliet\" -Force
} else {
    Move-Item -Path "temp_juliet\*" -Destination "c\juliet\" -Force
}
Remove-Item -Path "temp_juliet" -Recurse -Force
Remove-Item -Path $julietCppZip -Force

# 2. NIST Juliet Java v1.3 (~100 MB)
Write-Host "Downloading NIST Juliet Java v1.3 (~100 MB)..." -ForegroundColor Yellow
$julietJavaZip = "juliet_java.zip"
curl.exe -L -k -A "Mozilla/5.0" -o $julietJavaZip "https://samate.nist.gov/SARD/test-suites/2017-10-01-juliet-java-v1-3.zip"

Write-Host "Extracting NIST Juliet Java..." -ForegroundColor Yellow
tar.exe -xf $julietJavaZip -C "java\juliet"
Remove-Item -Path $julietJavaZip -Force

# 3. Big-Vul C/C++ Dataset (~300 MB)
Write-Host "Downloading Big-Vul C/C++ Dataset (~300 MB)..." -ForegroundColor Yellow
$bigvulCsv = "MSR_data_cleaned.csv"
curl.exe -L -o $bigvulCsv "https://zenodo.org/records/3745284/files/MSR_data_cleaned.csv?download=1"

Copy-Item -Path $bigvulCsv -Destination "c\bigvul\$bigvulCsv" -Force
Move-Item -Path $bigvulCsv -Destination "cpp\bigvul\$bigvulCsv" -Force

# 4. DiverseVul C/C++ Dataset (~500 MB)
Write-Host "Downloading DiverseVul C/C++ Dataset..." -ForegroundColor Yellow
$diversevulJson = "diversevul.json"
curl.exe -L -o $diversevulJson "https://zenodo.org/records/8086487/files/diversevul_20230702.json?download=1"

Copy-Item -Path $diversevulJson -Destination "c\diversevul\$diversevulJson" -Force
Move-Item -Path $diversevulJson -Destination "cpp\diversevul\$diversevulJson" -Force

Write-Host "All datasets successfully downloaded and placed!" -ForegroundColor Green