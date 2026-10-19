<#
.SYNOPSIS
  Probe the local reverse-engineering / decompilation toolchain.

.DESCRIPTION
  Read-only discovery helper for the DSH `reverse-engineering` skill. It never
  installs anything and never touches a target binary: it only asks the system
  which tools exist, where they live, and (when possible) their version, then
  prints install hints for the ones that are missing.

  Exit code is always 0 so a missing toolchain never looks like a failed command.

.PARAMETER NoVersions
  Skip version probing (faster; useful on slow or locked-down hosts).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\probe-tools.ps1
#>
[CmdletBinding()]
param([switch]$NoVersions)

$ErrorActionPreference = 'SilentlyContinue'

function Resolve-Tool([string]$Name) {
    $c = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($c) { return $c.Source }
    return $null
}

function Resolve-First([string[]]$Candidates) {
    foreach ($c in $Candidates) {
        if ([string]::IsNullOrEmpty($c)) { continue }
        if (Test-Path -LiteralPath $c) { return $c }
    }
    return $null
}

function Find-ChildTool([string[]]$Parents, [string]$Filter, [string]$Leaf) {
    foreach ($parent in $Parents) {
        if ([string]::IsNullOrEmpty($parent) -or -not (Test-Path -LiteralPath $parent)) { continue }
        $dirs = Get-ChildItem -LiteralPath $parent -Directory -Filter $Filter -ErrorAction SilentlyContinue
        foreach ($d in $dirs) {
            $p = Join-Path $d.FullName $Leaf
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }
    return $null
}

function Get-ToolVersion([string]$Path, [string[]]$Arguments) {
    if ($NoVersions -or [string]::IsNullOrEmpty($Path)) { return '' }
    # Never execute a GUI launcher just to read its version.
    if ($null -eq $Arguments -or $Arguments.Count -eq 0) { return '' }
    try {
        $raw = & $Path @Arguments 2>&1
        $line = $raw | Where-Object { $_ -ne $null -and "$_".Trim().Length -gt 0 } |
            Select-Object -First 1
        if (-not $line) { return '' }
        $text = ("$_".Trim() -replace '\s+', ' ')
        if ($text.Length -gt 62) { $text = $text.Substring(0, 59) + '...' }
        return $text
    } catch {
        return ''
    }
}

# --- Android SDK discovery ------------------------------------------------
$sdkRoot = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } elseif ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $null }
$sdkGuesses = @(
    $sdkRoot,
    (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Android\Sdk')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

function Get-SdkBuildTool([string]$Leaf) {
    foreach ($sdk in $sdkGuesses) {
        $buildTools = Join-Path $sdk 'build-tools'
        if (-not (Test-Path -LiteralPath $buildTools)) { continue }
        foreach ($d in (Get-ChildItem -LiteralPath $buildTools -Directory -ErrorAction SilentlyContinue)) {
            $p = Join-Path $d.FullName $Leaf
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }
    return $null
}

$androidExtras = @{
    'adb'       = @(foreach ($sdk in $sdkGuesses) { Join-Path $sdk 'platform-tools\adb.exe' })
    'apksigner' = @(Get-SdkBuildTool 'apksigner.bat')
    'aapt2'     = @(Get-SdkBuildTool 'aapt2.exe')
}

# --- fallback locations for tools that are not on PATH --------------------
$programDirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)})

$knownExtras = @{
    'java'            = @(
        (Find-ChildTool @($env:JAVA_HOME) '*' 'bin\java.exe')
        (Find-ChildTool @("$env:ProgramFiles\Eclipse Adoptium", "$env:ProgramFiles\Java", "$env:ProgramFiles\Microsoft") 'jdk*' 'bin\java.exe')
        (Find-ChildTool @("$env:LOCALAPPDATA\Programs\Eclipse Adoptium", "$env:LOCALAPPDATA\Programs\Microsoft") 'jdk*' 'bin\java.exe')
        (Find-ChildTool @("$env:USERPROFILE\.jdks") 'jdk*' 'bin\java.exe')
    )
    'analyzeHeadless' = @(
        (Find-ChildTool @($programDirs + @($env:LOCALAPPDATA, $env:USERPROFILE)) 'ghidra*' 'support\analyzeHeadless.bat')
    )
    'ghidraRun'       = @(
        (Find-ChildTool @($programDirs + @($env:LOCALAPPDATA, $env:USERPROFILE)) 'ghidra*' 'ghidraRun.bat')
    )
    'ida64'           = @(
        (Find-ChildTool @($programDirs + @($env:USERPROFILE)) 'IDA*' 'ida64.exe')
    )
    'jadx'            = @(
        (Find-ChildTool @("$env:LOCALAPPDATA\Programs", $env:USERPROFILE) 'jadx*' 'bin\jadx.bat')
        (Find-ChildTool @($env:USERPROFILE) 'jadx*' 'jadx.bat')
    )
    'apktool'         = @(
        (Find-ChildTool @("$env:LOCALAPPDATA\Programs") 'apktool*' 'apktool.bat')
        (Find-ChildTool @($env:USERPROFILE) 'apktool*' 'apktool.bat')
    )
    'frida'           = @(
        (Find-ChildTool @("$env:LOCALAPPDATA\Programs\Python") 'Python*' 'Scripts\frida.exe')
    )
    'frida-ps'        = @(
        (Find-ChildTool @("$env:LOCALAPPDATA\Programs\Python") 'Python*' 'Scripts\frida-ps.exe')
    )
    'ilspycmd'        = @(
        (Find-ChildTool @("$env:USERPROFILE\.dotnet\tools") '*' 'ilspycmd.exe')
    )
    '7z'              = @('C:\Program Files\7-Zip\7z.exe', 'C:\Program Files (x86)\7-Zip\7z.exe')
    'adb'             = $androidExtras['adb']
    'apksigner'       = $androidExtras['apksigner']
    'aapt2'           = $androidExtras['aapt2']
}

# --- tool table -----------------------------------------------------------
$tools = @(
    [pscustomobject]@{ Name='jadx';          Cat='Android'; Args=@('--version'); Hint='https://github.com/skylot/jadx/releases' }
    [pscustomobject]@{ Name='apktool';       Cat='Android'; Args=@('--version'); Hint='https://apktool.org/docs/install' }
    [pscustomobject]@{ Name='aapt2';         Cat='Android'; Args=@('version');   Hint='Android SDK build-tools' }
    [pscustomobject]@{ Name='apksigner';     Cat='Android'; Args=@('--version'); Hint='Android SDK build-tools' }
    [pscustomobject]@{ Name='adb';           Cat='Android'; Args=@('version');   Hint='https://developer.android.com/tools/releases/platform-tools' }
    [pscustomobject]@{ Name='frida';         Cat='Android'; Args=@('--version'); Hint='pip install frida-tools (match frida-server version)' }
    [pscustomobject]@{ Name='frida-ps';      Cat='Android'; Args=@('--version'); Hint='pip install frida-tools' }
    [pscustomobject]@{ Name='objection';     Cat='Android'; Args=@('version');   Hint='pip install objection' }
    [pscustomobject]@{ Name='baksmali';      Cat='Android'; Args=@('--version'); Hint='https://github.com/JesusFreke/smali' }
    [pscustomobject]@{ Name='java';          Cat='Java';    Args=@('-version');  Hint='JRE 17+ (Temurin or Microsoft OpenJDK)' }
    [pscustomobject]@{ Name='javap';         Cat='Java';    Args=@('-version');  Hint='ships with a JDK' }
    [pscustomobject]@{ Name='jar';           Cat='Java';    Args=@('--version'); Hint='ships with a JDK' }
    [pscustomobject]@{ Name='jdeps';         Cat='Java';    Args=@('--version'); Hint='ships with a JDK' }
    [pscustomobject]@{ Name='dotnet';        Cat='DotNet';  Args=@('--version'); Hint='https://dot.net' }
    [pscustomobject]@{ Name='ilspycmd';      Cat='DotNet';  Args=@('--version'); Hint='dotnet tool install --global ilspycmd' }
    [pscustomobject]@{ Name='de4dot';        Cat='DotNet';  Args=@('--help');    Hint='https://github.com/de4dot/de4dot (authorized samples only)' }
    [pscustomobject]@{ Name='ghidraRun';     Cat='Native';  Args=@();            Hint='https://github.com/NationalSecurityAgency/ghidra/releases' }
    [pscustomobject]@{ Name='analyzeHeadless'; Cat='Native'; Args=@();           Hint='Ghidra support\analyzeHeadless.bat' }
    [pscustomobject]@{ Name='rizin';         Cat='Native';  Args=@('-v');        Hint='https://rizin.re/download' }
    [pscustomobject]@{ Name='radare2';       Cat='Native';  Args=@('-v');        Hint='https://rada.re/n/' }
    [pscustomobject]@{ Name='ida64';         Cat='Native';  Args=@();            Hint='IDA Pro (licensed install)' }
    [pscustomobject]@{ Name='objdump';       Cat='Native';  Args=@('--version'); Hint='WinLibs / mingw-w64 / MSYS2 binutils' }
    [pscustomobject]@{ Name='readelf';       Cat='Native';  Args=@('--version'); Hint='MSYS2 binutils' }
    [pscustomobject]@{ Name='nm';            Cat='Native';  Args=@('--version'); Hint='MSYS2 binutils' }
    [pscustomobject]@{ Name='strings';       Cat='Native';  Args=@('--version'); Hint='WinLibs / mingw-w64 / MSYS2 binutils' }
    [pscustomobject]@{ Name='upx';           Cat='Native';  Args=@('--version'); Hint='https://upx.github.io' }
    [pscustomobject]@{ Name='binwalk';       Cat='Native';  Args=@('--help');    Hint='pip install binwalk (POSIX mostly)' }
    [pscustomobject]@{ Name='7z';            Cat='Support'; Args=@();            Hint='https://7-zip.org' }
    [pscustomobject]@{ Name='python';        Cat='Support'; Args=@('--version'); Hint='https://python.org' }
    [pscustomobject]@{ Name='pip';           Cat='Support'; Args=@('--version'); Hint='ships with Python' }
    [pscustomobject]@{ Name='node';          Cat='Support'; Args=@('--version'); Hint='https://nodejs.org' }
    [pscustomobject]@{ Name='git';           Cat='Support'; Args=@('--version'); Hint='https://git-scm.com' }
)

$rows = foreach ($t in $tools) {
    $path = Resolve-Tool $t.Name
    if (-not $path -and $knownExtras.ContainsKey($t.Name)) {
        $path = Resolve-First $knownExtras[$t.Name]
    }
    [pscustomobject]@{
        Tool    = $t.Name
        Cat     = $t.Cat
        Path    = $path
        Version = Get-ToolVersion $path $t.Args
        Hint    = $t.Hint
    }
}

# --- report ---------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$hostLine = '{0} {1} | PowerShell {2} | {3}' -f $os.Caption, $os.Version, $PSVersionTable.PSVersion, (Get-Date -Format 'yyyy-MM-dd HH:mm')
$sdkText = if ($sdkRoot) { $sdkRoot } else { '(ANDROID_HOME/ANDROID_SDK_ROOT not set)' }

Write-Output '== DSH reverse-engineering toolkit probe =='
Write-Output ("Host: " + $hostLine)
Write-Output ("Android SDK: " + $sdkText)
Write-Output ''

$installed = 0
$missing = 0
foreach ($cat in @('Android', 'Java', 'DotNet', 'Native', 'Support')) {
    Write-Output ("[{0}]" -f $cat)
    foreach ($r in ($rows | Where-Object { $_.Cat -eq $cat })) {
        if ($r.Path) {
            $installed++
            $version = if ($r.Version) { $r.Version } else { '' }
            Write-Output ("  {0,-14} OK    {1,-30} {2}" -f $r.Tool, $version, $r.Path)
        } else {
            $missing++
            Write-Output ("  {0,-14} MISS  {1}" -f $r.Tool, $r.Hint)
        }
    }
    Write-Output ''
}

Write-Output ("Summary: {0} installed, {1} missing (of {2} checked)." -f $installed, $missing, $rows.Count)
if ($missing -gt 0) {
    Write-Output ''
    Write-Output 'Ask the user before installing anything; the hints above are suggestions only.'
    Write-Output 'If jadx/apktool are present but java is MISS, they cannot run: install a JRE 17+ first.'
}
exit 0
