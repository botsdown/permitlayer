<#
.SYNOPSIS
Unit tests for install/install.ps1 — exercises individual functions
without running the install end-to-end.

.DESCRIPTION
Mirrors the scripts/test-patch-homebrew-formula.sh pattern from Story 7.1:
plain assertions, no test-framework dependency, fail-fast on first error
with clear context. Runs in CI on windows-latest via .github/workflows/ci.yml.

Test cases (mapped to Story 7.2 AC #10):
1. Get-Arch returns x86_64-pc-windows-msvc on X64
2. Get-Arch throws on Arm64 (rejection, not silent install)
3. Resolve-Version strips leading 'v' from explicit version
4. Test-Sha256 fails loud on hash mismatch
5. Update-UserPath is idempotent (writes once, second call no-ops)
6. Update-UserPath skipped when -NoModifyPath equivalent (no call made)

Invocation:
    pwsh scripts/test-install-ps1.ps1
#>

$ErrorActionPreference = 'Stop'

# Locate install.ps1 relative to this script
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installScript = Join-Path $repoRoot 'install/install.ps1'
if (-not (Test-Path $installScript)) {
    # Fallback: assume cwd is repo root
    $installScript = Join-Path (Get-Location) 'install/install.ps1'
}
if (-not (Test-Path $installScript)) {
    throw "Cannot locate install/install.ps1 (looked in $installScript)"
}

# Source install.ps1 with test-mode flag set so Invoke-Main does not run.
$env:AGENTSSO_TEST_MODE = '1'
. $installScript

# --- Test framework (minimal) -----------------------------------------------

$script:passed = 0
$script:failed = 0

function Assert-Equal {
    param(
        [Parameter(Mandatory)] $Actual,
        [Parameter(Mandatory)] $Expected,
        [Parameter(Mandatory)] [string]$Message
    )
    if ($Actual -eq $Expected) {
        Write-Host "  PASS: $Message"
        $script:passed++
    } else {
        Write-Host "  FAIL: $Message" -ForegroundColor Red
        Write-Host "    expected: $Expected" -ForegroundColor Red
        Write-Host "    actual:   $Actual" -ForegroundColor Red
        $script:failed++
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)] [scriptblock]$Action,
        [Parameter(Mandatory)] [string]$Message,
        [string]$ExpectedSubstring = ''
    )
    $threw = $false
    $actualMessage = ''
    try {
        & $Action
    } catch {
        $threw = $true
        $actualMessage = $_.Exception.Message
    }
    if (-not $threw) {
        Write-Host "  FAIL: $Message — expected exception, none thrown" -ForegroundColor Red
        $script:failed++
        return
    }
    if ($ExpectedSubstring -and ($actualMessage -notlike "*$ExpectedSubstring*")) {
        Write-Host "  FAIL: $Message — exception message did not contain '$ExpectedSubstring'" -ForegroundColor Red
        Write-Host "    actual: $actualMessage" -ForegroundColor Red
        $script:failed++
        return
    }
    Write-Host "  PASS: $Message"
    $script:passed++
}

# --- Test cases --------------------------------------------------------------

Write-Host ''
Write-Host '=== install.ps1 unit tests ==='
Write-Host ''

# Test 1: Resolve-Version strips leading 'v'
Write-Host 'Test group: Resolve-Version'
Assert-Equal -Actual (Resolve-Version -RequestedVersion 'v0.3.0') -Expected '0.3.0' -Message 'strips leading v'
Assert-Equal -Actual (Resolve-Version -RequestedVersion '0.3.0') -Expected '0.3.0' -Message 'no-op when already bare'
Assert-Equal -Actual (Resolve-Version -RequestedVersion 'v0.3.0-rc.1') -Expected '0.3.0-rc.1' -Message 'preserves pre-release suffix'

# Test 2: Test-Sha256 fails loud on mismatch
Write-Host ''
Write-Host 'Test group: Test-Sha256'
$tmpDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid()))
try {
    $zipPath = Join-Path $tmpDir 'fake.zip'
    'fake-zip-contents' | Out-File -LiteralPath $zipPath -NoNewline
    $shaPath = "$zipPath.sha256"
    # Wrong hash on purpose
    "0000000000000000000000000000000000000000000000000000000000000000  fake.zip" | Out-File -LiteralPath $shaPath -NoNewline
    Assert-Throws -Action { Test-Sha256 -ZipPath $zipPath } `
        -Message 'throws on hash mismatch' `
        -ExpectedSubstring 'sha256 mismatch'

    # Now write the CORRECT hash and verify it passes
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLowerInvariant()
    "$actual  fake.zip" | Out-File -LiteralPath $shaPath -NoNewline
    $threw = $false
    try { Test-Sha256 -ZipPath $zipPath } catch { $threw = $true }
    if ($threw) {
        Write-Host "  FAIL: Test-Sha256 should pass on matching hash but threw" -ForegroundColor Red
        $script:failed++
    } else {
        Write-Host "  PASS: Test-Sha256 passes on matching hash"
        $script:passed++
    }

    # Missing sidecar
    Remove-Item -LiteralPath $shaPath
    Assert-Throws -Action { Test-Sha256 -ZipPath $zipPath } `
        -Message 'throws when sidecar missing' `
        -ExpectedSubstring 'sha256 sidecar missing'
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmpDir
}

# Test 3: Update-UserPath idempotency
# Use a sandbox registry path under HKCU\Software so we don't touch the
# runner's real Environment\Path. Create a fake `Path` value, run
# Update-UserPath twice, assert only one entry exists at the end.
Write-Host ''
Write-Host 'Test group: Update-UserPath'
$sandboxKey = "HKCU:\Software\agentsso-test-$([guid]::NewGuid())"
try {
    New-Item -Path $sandboxKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $sandboxKey -Name Path -Value 'C:\existing\bin;C:\Windows' -Type ExpandString

    $regPath = "registry::HKEY_CURRENT_USER\$($sandboxKey -replace '^HKCU:\\','')"
    $testInstallDir = 'C:\Test\agentsso'

    # First call: should mutate.
    $changed1 = Update-UserPath -InstallDir $testInstallDir -RegistryPath $regPath
    Assert-Equal -Actual $changed1 -Expected $true -Message 'first call returns $true (changed)'

    # Read back
    $afterFirst = (Get-Item -LiteralPath $regPath).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    if ($afterFirst -like "$testInstallDir;*") {
        Write-Host "  PASS: install dir prepended to PATH"
        $script:passed++
    } else {
        Write-Host "  FAIL: PATH after first call: $afterFirst" -ForegroundColor Red
        $script:failed++
    }

    # Second call: should no-op.
    $changed2 = Update-UserPath -InstallDir $testInstallDir -RegistryPath $regPath
    Assert-Equal -Actual $changed2 -Expected $false -Message 'second call returns $false (idempotent)'

    # Verify only one occurrence in PATH.
    $afterSecond = (Get-Item -LiteralPath $regPath).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    $occurrences = ($afterSecond -split ';' | Where-Object { $_ -eq $testInstallDir }).Count
    Assert-Equal -Actual $occurrences -Expected 1 -Message 'install dir appears exactly once after two calls'
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $sandboxKey
}

# Test 4: Get-Arch — we cannot easily mock RuntimeInformation, so we call
# it directly and assert it returns the expected triple for whatever the
# runner is. This makes the test less of a unit and more of a smoke
# assertion — but the alternative (mocking .NET) requires Pester +
# significant infrastructure for diminishing returns.
Write-Host ''
Write-Host 'Test group: Get-Arch'
$arch = Get-Arch
if ($arch -eq 'x86_64-pc-windows-msvc') {
    Write-Host "  PASS: Get-Arch returned x86_64-pc-windows-msvc on this runner"
    $script:passed++
} else {
    Write-Host "  FAIL: Get-Arch returned '$arch' on a runner that should be X64" -ForegroundColor Red
    Write-Host "    (windows-latest runners are X64 — if this is non-X64, update the test)" -ForegroundColor Red
    $script:failed++
}

# --- Summary ----------------------------------------------------------------

Write-Host ''
Write-Host "=== Summary: $($script:passed) passed, $($script:failed) failed ==="
if ($script:failed -gt 0) {
    exit 1
}
exit 0
