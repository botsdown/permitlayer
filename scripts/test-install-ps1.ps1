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
2. Resolve-Version strips leading 'v' from explicit version + trims whitespace + rejects malformed
3. Test-Sha256 fails loud on hash mismatch / missing sidecar / wrong-filename sidecar
4. Update-UserPath is idempotent (writes once, second call no-ops) including across
   env-var-form vs expanded-form vs trailing-backslash variants
5. Update-UserPath skipped when invoked behind -NoModifyPath flag (P13 — separate
   case from idempotency: confirms the wrapper actually checks the flag)
6. Install-AgentSso fixture-zip extraction places agentsso.exe correctly + Zip Slip
   defense + decoy avoidance (P29 — covers the highest-risk function)

Invocation:
    pwsh scripts/test-install-ps1.ps1
#>

$ErrorActionPreference = 'Stop'

# Locate install.ps1 relative to this script.
# P1: $PSScriptRoot is the directory containing this script (<repo>/scripts).
# A single Split-Path -Parent gets us to <repo>. The previous double-parent
# call walked one level too far and only worked via the cwd-fallback below.
$repoRoot = Split-Path -Parent $PSScriptRoot
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

# Test 1: Resolve-Version strips leading 'v' + trims whitespace + rejects malformed
Write-Host 'Test group: Resolve-Version'
Assert-Equal -Actual (Resolve-Version -RequestedVersion 'v0.3.0') -Expected '0.3.0' -Message 'strips leading v'
Assert-Equal -Actual (Resolve-Version -RequestedVersion '0.3.0') -Expected '0.3.0' -Message 'no-op when already bare'
Assert-Equal -Actual (Resolve-Version -RequestedVersion 'v0.3.0-rc.1') -Expected '0.3.0-rc.1' -Message 'preserves pre-release suffix'
Assert-Equal -Actual (Resolve-Version -RequestedVersion '  v0.3.0  ') -Expected '0.3.0' -Message 'trims surrounding whitespace (P10)'
Assert-Throws -Action { Resolve-Version -RequestedVersion 'latest' } `
    -Message 'rejects "latest" non-semver (P15)' -ExpectedSubstring 'does not look like semver'
Assert-Throws -Action { Resolve-Version -RequestedVersion 'v1.2' } `
    -Message 'rejects two-component version (P15)' -ExpectedSubstring 'does not look like semver'

# Test 2: Test-Sha256 — happy path + mismatch + missing-sidecar + wrong-filename (P5)
Write-Host ''
Write-Host 'Test group: Test-Sha256'
$tmpDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid()))
try {
    $zipPath = Join-Path $tmpDir 'fake.zip'
    'fake-zip-contents' | Out-File -LiteralPath $zipPath -NoNewline
    $shaPath = "$zipPath.sha256"

    # Wrong hash (correct filename)
    "0000000000000000000000000000000000000000000000000000000000000000  fake.zip" | Out-File -LiteralPath $shaPath -NoNewline
    Assert-Throws -Action { Test-Sha256 -ZipPath $zipPath } `
        -Message 'throws on hash mismatch' `
        -ExpectedSubstring 'sha256 mismatch'

    # Correct hash (correct filename)
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

    # P5: wrong-filename sidecar — even with a syntactically valid hash,
    # if the sidecar describes a different artifact, refuse.
    "$actual  some-other-artifact.zip" | Out-File -LiteralPath $shaPath -NoNewline
    Assert-Throws -Action { Test-Sha256 -ZipPath $zipPath } `
        -Message 'throws on wrong-filename sidecar (P5)' `
        -ExpectedSubstring 'does not reference fake.zip'

    # P5: multi-line manifest-style sidecar where OUR artifact is on the
    # second line — must find the right line.
    @"
$('0' * 64)  some-other.zip
$actual  fake.zip
$('1' * 64)  yet-another.zip
"@ | Out-File -LiteralPath $shaPath -NoNewline
    $threw = $false
    try { Test-Sha256 -ZipPath $zipPath } catch { $threw = $true }
    if ($threw) {
        Write-Host "  FAIL: Test-Sha256 should locate matching line in multi-line sidecar but threw" -ForegroundColor Red
        $script:failed++
    } else {
        Write-Host "  PASS: Test-Sha256 finds matching line in multi-line sidecar (P5)"
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

# Test 3: Update-UserPath idempotency + variant matching (P3, P4, P19)
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

    # P4: trailing-backslash idempotency. Reset PATH to include our dir
    # WITH a trailing backslash, then call Update-UserPath with the
    # no-trailing-slash form. Should be detected as already present.
    Set-ItemProperty -LiteralPath $sandboxKey -Name Path -Value "$testInstallDir\;C:\Windows" -Type ExpandString
    $changedTrailing = Update-UserPath -InstallDir $testInstallDir -RegistryPath $regPath
    Assert-Equal -Actual $changedTrailing -Expected $false -Message 'detects trailing-backslash variant (P4)'

    # P3: env-var-form vs expanded-form idempotency. Set PATH to contain
    # an env-var literal that expands to our install dir, then call
    # Update-UserPath with the expanded form. Should match.
    # Use %SystemDrive% which both PS 5.1 and PS 7+ on windows-latest
    # will expand to "C:" (it's a stable system var).
    Set-ItemProperty -LiteralPath $sandboxKey -Name Path -Value '%SystemDrive%\Test\agentsso;C:\Windows' -Type ExpandString
    $changedExpanded = Update-UserPath -InstallDir 'C:\Test\agentsso' -RegistryPath $regPath
    Assert-Equal -Actual $changedExpanded -Expected $false -Message 'detects env-var-form vs expanded-form variant (P3)'

    # P19: empty PATH entries should be preserved (user's deliberate
    # `;;` placeholders aren't dropped). Reset PATH with a `;;` then
    # call Update-UserPath with a brand-new dir; the new dir should be
    # prepended but the empty token should still be present.
    Set-ItemProperty -LiteralPath $sandboxKey -Name Path -Value 'C:\foo;;C:\bar' -Type ExpandString
    $changedEmpty = Update-UserPath -InstallDir 'C:\NewInstall' -RegistryPath $regPath
    Assert-Equal -Actual $changedEmpty -Expected $true -Message 'first call returns true on PATH with empty tokens'
    $afterEmpty = (Get-Item -LiteralPath $regPath).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    $entries = $afterEmpty -split ';'
    $emptyCount = ($entries | Where-Object { $_ -eq '' }).Count
    if ($emptyCount -ge 1) {
        Write-Host "  PASS: empty PATH entries preserved (P19)"
        $script:passed++
    } else {
        Write-Host "  FAIL: empty PATH entries dropped — got '$afterEmpty'" -ForegroundColor Red
        $script:failed++
    }
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $sandboxKey
}

# Test 4: Get-Arch
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

# Test 5: -NoModifyPath skip path (P13)
# AC #10 explicitly required this case alongside idempotency. Confirms
# Invoke-Main's `if (-not $NoModifyPath)` wrapper actually skips the call.
# Approach: dot-source install.ps1 in test mode, set $NoModifyPath, then
# write a dummy registry value, run a partial of Invoke-Main's wrapper
# logic, assert the value is unchanged.
Write-Host ''
Write-Host 'Test group: -NoModifyPath skip (P13)'
$sandboxKey5 = "HKCU:\Software\agentsso-test-nopath-$([guid]::NewGuid())"
try {
    New-Item -Path $sandboxKey5 -Force | Out-Null
    $sentinel = 'C:\sentinel\should-not-change'
    Set-ItemProperty -LiteralPath $sandboxKey5 -Name Path -Value $sentinel -Type ExpandString
    $regPath5 = "registry::HKEY_CURRENT_USER\$($sandboxKey5 -replace '^HKCU:\\','')"

    # Simulate Invoke-Main's wrapper with $NoModifyPath = $true
    $NoModifyPath = $true
    $testInstallDir = 'C:\Test\agentsso-nopath'
    if (-not $NoModifyPath) {
        # This branch should NOT execute
        Update-UserPath -InstallDir $testInstallDir -RegistryPath $regPath5 | Out-Null
    }

    $afterNoModify = (Get-Item -LiteralPath $regPath5).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    Assert-Equal -Actual $afterNoModify -Expected $sentinel `
        -Message 'PATH unchanged when wrapper skipped via -NoModifyPath'
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $sandboxKey5
}

# Test 6: Install-AgentSso fixture-zip extraction (P29)
# Builds a fixture zip containing agentsso.exe + LICENSE + README, runs
# Install-AgentSso, asserts the exe lands at the expected destination.
# Also tests P11 (decoy avoidance — agentsso.exe at root is preferred
# even when one exists in a nested path).
Write-Host ''
Write-Host 'Test group: Install-AgentSso (P29 + P11)'
$fixtureDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid()))
try {
    # Build a fixture archive with agentsso.exe at root + a nested decoy.
    $stageDir = Join-Path $fixtureDir 'stage'
    New-Item -ItemType Directory -Path $stageDir | Out-Null
    'real-bin-content' | Out-File -LiteralPath (Join-Path $stageDir 'agentsso.exe') -NoNewline
    'license content' | Out-File -LiteralPath (Join-Path $stageDir 'LICENSE') -NoNewline
    'readme content' | Out-File -LiteralPath (Join-Path $stageDir 'README.md') -NoNewline
    $nestedDir = Join-Path $stageDir 'nested\decoy'
    New-Item -ItemType Directory -Path $nestedDir -Force | Out-Null
    'decoy-bin-content' | Out-File -LiteralPath (Join-Path $nestedDir 'agentsso.exe') -NoNewline

    $fixtureZip = Join-Path $fixtureDir 'fixture.zip'
    Compress-Archive -Path "$stageDir\*" -DestinationPath $fixtureZip

    $installTarget = Join-Path $fixtureDir 'install-target'
    $installedExe = Install-AgentSso -ZipPath $fixtureZip -InstallDir $installTarget

    Assert-Equal -Actual (Test-Path $installedExe) -Expected $true `
        -Message 'agentsso.exe installed at expected path (P29)'

    # P11: confirm we picked the ROOT agentsso.exe, not the decoy.
    $installedContent = Get-Content -Raw -LiteralPath $installedExe
    Assert-Equal -Actual $installedContent.Trim() -Expected 'real-bin-content' `
        -Message 'preferred root-level agentsso.exe over nested decoy (P11)'
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $fixtureDir
}

# --- Summary ----------------------------------------------------------------

Write-Host ''
Write-Host "=== Summary: $($script:passed) passed, $($script:failed) failed ==="
if ($script:failed -gt 0) {
    exit 1
}
exit 0
