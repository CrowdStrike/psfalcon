param([string]$SourcePath = (Join-Path $PSScriptRoot '..\public\psf-config.ps1'))
$ErrorActionPreference = 'Stop'
$Tokens = $null; $Errors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $SourcePath).Path, [ref]$Tokens, [ref]$Errors)
if ($Errors.Count) { throw 'Source does not parse.' }
$Export = @($Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $Node.Name -eq 'Export-FalconConfig'
}, $true))
if ($Export.Count -ne 1) { throw 'Expected one Export-FalconConfig definition.' }
. ([scriptblock]::Create($Export[0].Extent.Text))
# Test doubles replace API and environment helpers; export and ZIP I/O remain real.
function Get-FalconCcid { [CmdletBinding()]param(); 'a' * 32 }
function Confirm-CidValue { param($Value); $Value }
function Test-OutFile { param($Path); @{} }
function Write-Log { param($Component, $Message) }
function Get-FalconPreventionPolicy {
    param($Filter, [switch]$All, [switch]$Detailed)
    if ($Filter -eq "platform_name:'Windows'") { $Policies }
}
function Get-FalconHostGroup {
    param([switch]$All, [switch]$Detailed)
    $Calls.Groups++
    # CID-less dependency records deliberately exercise the existing fallback.
    foreach ($Id in @('g1', 'g2')) { [pscustomobject]@{ id = $Id } }
}
$Root = Join-Path ([System.IO.Path]::GetTempPath()) ('psfalcon-regression-' + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $Root
$Failures = 0
foreach ($Case in @('mixed', 'customer', 'parent', 'child', 'unscoped', 'order', 'shared')) {
    $Dir = Join-Path $Root $Case
    $null = New-Item -ItemType Directory -Path $Dir
    $Field = if ($Case -eq 'customer') { 'customer_id' } else { 'cid' }
    $First = [ordered]@{ id = 'p1'; groups = @('g1') }
    $Second = [ordered]@{ id = 'p2'; groups = @('g2') }
    if ($Case -ne 'unscoped') {
        $First[$Field] = 'a' * 32
        $Second[$Field] = 'b' * 32
    }
    if ($Case -in @('order', 'shared')) { $Second[$Field] = 'a' * 32 }
    if ($Case -eq 'shared') { $Second.groups = @('g1') }
    $Policies = @([pscustomobject]$First, [pscustomobject]$Second)
    if ($Case -eq 'parent') { $Policies = @($Policies[0]) }
    if ($Case -eq 'child') { $Policies = @($Policies[1]) }
    $ExpectedPolicies = if ($Case -eq 'child') { '' } elseif (
        $Case -in @('unscoped', 'order', 'shared')) { 'p1,p2' } else { 'p1' }
    $ExpectedGroups = if ($Case -eq 'child') { '' } elseif (
        $Case -in @('unscoped', 'order')) { 'g1,g2' } else { 'g1' }
    $Calls = @{ Groups = 0 }
    Push-Location $Dir
    try {
        $null = Export-FalconConfig -Select PreventionPolicy -Confirm:$false
        $Zips = @(Get-ChildItem -Filter '*.zip')
        if ($Case -eq 'child') {
            if ($Zips.Count -or $Calls.Groups) { throw 'Child-only input caused export/dependency work.' }
        } else {
            if ($Zips.Count -ne 1) { throw 'Expected exactly one ZIP.' }
            Expand-Archive -LiteralPath $Zips[0].FullName -DestinationPath '.\expanded'
            $P = @(Get-Content '.\expanded\PreventionPolicy.json' -Raw | ConvertFrom-Json)
            $G = @(Get-Content '.\expanded\HostGroup.json' -Raw | ConvertFrom-Json)
            if (($P.id -join ',') -ne $ExpectedPolicies) { throw "Policy selection/order mismatch: got [$($P.id -join ',')] want [$ExpectedPolicies]." }
            if (($G.id -join ',') -ne $ExpectedGroups) { throw "Dependency selection mismatch: got [$($G.id -join ',')] want [$ExpectedGroups]." }
            if ($Calls.Groups -ne 1) { throw 'Expected one host-group retrieval.' }
            if (@(Get-ChildItem '.\expanded' -File).Count -ne 2) { throw 'Unexpected archive contents.' }
        }
        Write-Host "PASS $Case"
    } catch {
        $Failures++
        Write-Host "FAIL ${Case}: $($_.Exception.Message)"
    } finally { Pop-Location }
}
Write-Host "Evidence: $Root"
if ($Failures) { throw "$Failures regression case(s) failed." }
Write-Host 'PASS: all 7 regression cases'