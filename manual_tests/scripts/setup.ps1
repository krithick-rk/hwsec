# HWSEC Manual Test Environment Setup Script (Windows PowerShell)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       HWSEC Manual Test Environment Setup Check           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check Node.js
try {
    $nodeVer = node -v
    Write-Host "[+] Node.js detected: $nodeVer" -ForegroundColor Green
} catch {
    Write-Host "[-] Node.js NOT found! Please install Node.js v18+" -ForegroundColor Red
    exit 1
}

# Check optional compilers/tools
$tools = @(
    @{ Name = "Python 3"; Cmd = "python --version" },
    @{ Name = "GCC Compiler"; Cmd = "gcc --version" },
    @{ Name = "Java Runtime"; Cmd = "java -version" },
    @{ Name = "Icarus Verilog"; Cmd = "iverilog -V" },
    @{ Name = "Yosys"; Cmd = "yosys -V" }
)

Write-Host "`nOptional Execution Toolchain Capabilities:" -ForegroundColor Yellow
foreach ($t in $tools) {
    try {
        $out = Invoke-Expression $t.Cmd 2>&1 | Select-Object -First 1
        Write-Host "  * [AVAILABLE]   $($t.Name) ($out)" -ForegroundColor Green
    } catch {
        Write-Host "  * [UNAVAILABLE] $($t.Name) (Not found in PATH - fallback to mock/static)" -ForegroundColor DarkGray
    }
}

Write-Host "`n[+] Setup check complete. You can run 'run_smoke.ps1' or 'hwsec console'." -ForegroundColor Cyan
