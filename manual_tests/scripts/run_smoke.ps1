# HWSEC Manual Smoke Test Script (Windows PowerShell)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         HWSEC Manual Smoke Test Walkthrough              " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$baseDir = Get-Location
$vunTarget = Join-Path $baseDir "manual_tests\targets\software\python\vulnerable"
$fixedTarget = Join-Path $baseDir "manual_tests\targets\software\python\fixed"
$outDir = Join-Path $baseDir "manual_tests\runs\smoke-run"

Write-Host "`n[*] 1. Running Zero-Key Deterministic Analysis on Vulnerable Target..." -ForegroundColor Yellow
node src/index.js analyze "$vunTarget" --output-dir "$outDir"

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Vulnerable target analysis completed successfully." -ForegroundColor Green
} else {
    Write-Host "[-] Smoke test failed on vulnerable target!" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] 2. Running Analysis on Fixed Target..." -ForegroundColor Yellow
node src/index.js analyze "$fixedTarget" --output-dir "$outDir"

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Fixed target analysis completed successfully." -ForegroundColor Green
} else {
    Write-Host "[-] Smoke test failed on fixed target!" -ForegroundColor Red
    exit 1
}

Write-Host "`n[=== SMOKE TEST SUITE PASSED SUCCESSFULLY ===]" -ForegroundColor Green
