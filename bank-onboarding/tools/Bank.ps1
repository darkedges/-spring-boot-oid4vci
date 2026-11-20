[CmdletBinding()]
param([ValidateSet('help','env','doctor','setup','keys','passport-key','db-up','db-down','run','start','phone','build','test')][string] $Task = 'help')
$ErrorActionPreference = 'Stop'
$script:BankRoot = Split-Path $PSScriptRoot -Parent

function Import-BankEnv {
    param([string] $Path = (Join-Path $script:BankRoot '.env'))
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $lineNumber = 0
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $lineNumber++
        if ($line -match '^\s*(#.*)?$') { continue }
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$') { throw "Invalid .env assignment at line $lineNumber." }
        $name = $Matches[1]; $value = $Matches[2].Trim()
        if ($value.StartsWith('"') -or $value.StartsWith("'")) {
            if ($value.Length -lt 2 -or $value[-1] -ne $value[0]) { throw "Unclosed .env quote at line $lineNumber." }
            $value = $value.Substring(1, $value.Length - 2)
        }
        # Literal values only: no expression execution, expansion, or inline comments.
        # Blank entries leave defaults, Terraform discovery and secure prompts available.
        if ($value -and -not [Environment]::GetEnvironmentVariable($name, 'Process')) {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}
function Initialize-BankEnv {
    $target = Join-Path $script:BankRoot '.env'
    if (Test-Path -LiteralPath $target) { Write-Host 'Keeping existing .env'; return }
    Copy-Item -LiteralPath (Join-Path $script:BankRoot '.env.example') -Destination $target
    Write-Host 'Created .env. Edit it locally before starting the bank.'
}
function Read-MailPassword {
    if ($env:BANK_MAIL_ENABLED -eq 'true' -and -not $env:BANK_SMTP_PASSWORD) {
        $password = Read-Host 'Mailgun SMTP password' -AsSecureString
        $env:BANK_SMTP_PASSWORD = [Net.NetworkCredential]::new('', $password).Password
        if (-not $env:BANK_SMTP_PASSWORD) { throw 'SMTP password is required when mail is enabled.' }
    }
}

function Invoke-Checked {
    param([string] $Executable, [string[]] $Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed with exit code $LASTEXITCODE." }
}
function Assert-Java {
    $java = if ($env:BANK_JAVA) { $env:BANK_JAVA } elseif ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/java' } else { 'java' }
    $version = (& $java -version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $version -notmatch 'version "(?<major>\d+)') { throw 'Cannot determine Java version. Set JAVA_HOME to JDK 21+ or BANK_JAVA to its java executable.' }
    if ([int]$Matches.major -lt 21) { throw 'Java 21+ is required. Set JAVA_HOME or BANK_JAVA to a newer JDK.' }
    return $java
}
function Get-AdbExecutable {
    if ($env:BANK_ADB) { return $env:BANK_ADB }
    $onPath = Get-Command adb -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $sdkDirectories = @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT)
    if ($env:LOCALAPPDATA) { $sdkDirectories += Join-Path $env:LOCALAPPDATA 'Android/Sdk' }
    foreach ($sdk in $sdkDirectories) {
        if ($sdk) {
            foreach ($name in @('platform-tools/adb.exe', 'platform-tools/adb')) {
                $candidate = Join-Path $sdk $name
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
            }
        }
    }
    throw 'adb was not found. Set ANDROID_HOME or BANK_ADB to your Android SDK/adb installation.'
}
function Initialize-KeyPaths {
    $directory = $env:BANK_SECRET_DIR
    if (-not $directory) {
        $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local/share' }
        $directory = Join-Path $base 'ExampleBank'
    }
    if (-not $env:BANK_PRIVATE_JWK_FILE) { $env:BANK_PRIVATE_JWK_FILE = Join-Path $directory 'bank-private.jwk' }
    if (-not $env:PASSPORT_PUBLIC_JWK_FILE) { $env:PASSPORT_PUBLIC_JWK_FILE = Join-Path $directory 'passport-public.jwk' }
}
function Initialize-BankKey {
    Initialize-KeyPaths
    if (Test-Path -LiteralPath $env:BANK_PRIVATE_JWK_FILE) { Write-Host "Keeping existing bank key: $env:BANK_PRIVATE_JWK_FILE"; return }
    $java = Assert-Java
    [IO.Directory]::CreateDirectory((Split-Path ([IO.Path]::GetFullPath($env:BANK_PRIVATE_JWK_FILE)) -Parent)) | Out-Null
    Invoke-Checked $java @((Join-Path $PSScriptRoot 'GenerateBankKey.java'), $env:BANK_PRIVATE_JWK_FILE)
}
function Initialize-PassportKey {
    Initialize-KeyPaths
    if (Test-Path -LiteralPath $env:PASSPORT_PUBLIC_JWK_FILE) { Write-Host "Keeping existing passport trust key: $env:PASSPORT_PUBLIC_JWK_FILE"; return }
    $issuer = if ($env:PASSPORT_ISSUER) { $env:PASSPORT_ISSUER.TrimEnd('/') } else { 'https://issuer.zkp.au' }
    $uri = [Uri]"$issuer/jwks"
    if ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $uri.IsLoopback)) { throw 'Fetch the passport key over HTTPS, or localhost for local development.' }
    $jwks = Invoke-RestMethod -Uri $uri -UserAgent 'ExampleBank-Onboarding/0.1' -TimeoutSec 20
    $keys = @($jwks.keys | Where-Object { $_.kty -eq 'EC' -and $_.crv -eq 'P-256' -and (-not $_.use -or $_.use -eq 'sig') -and (-not $_.alg -or $_.alg -eq 'ES256') })
    if ($env:PASSPORT_KEY_ID) { $keys = @($keys | Where-Object { $_.kid -eq $env:PASSPORT_KEY_ID }) }
    if ($keys.Count -ne 1) {
        $ids = ($keys | ForEach-Object { $_.kid }) -join ', '
        throw "Expected one passport signing key; found $($keys.Count) ($ids). Set PASSPORT_KEY_ID or install a verified single public JWK manually."
    }
    $key = $keys[0]
    if (-not $key.x -or -not $key.y) { throw 'Passport JWK has no public EC coordinates.' }
    # Persist public members only, even if a remote response contains other fields.
    $public = @{ kty = 'EC'; crv = 'P-256'; x = $key.x; y = $key.y }
    if ($key.kid) { $public.kid = $key.kid }
    $path = [IO.Path]::GetFullPath($env:PASSPORT_PUBLIC_JWK_FILE)
    [IO.Directory]::CreateDirectory((Split-Path $path -Parent)) | Out-Null
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $bytes = [Text.Encoding]::UTF8.GetBytes(($public | ConvertTo-Json) + "`n"); $stream.Write($bytes, 0, $bytes.Length) }
    finally { $stream.Dispose() }
    Write-Host "Pinned passport key '$($key.kid)' from $issuer in $path"
}
function Get-AppliedBankClientSecret {
    param([string] $TerraformDirectory, [string] $ClientId)
    try {
        # Terraform handles local or remote backends; capture all state, never print it.
        $stateJson = & terraform "-chdir=$TerraformDirectory" state pull 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $state = ($stateJson -join "`n") | ConvertFrom-Json
        foreach ($resource in $state.resources) {
            if ($resource.mode -ne 'managed' -or $resource.type -ne 'pingfederate_oauth_client' -or $resource.name -ne 'bank_hr' -or $resource.module) { continue }
            foreach ($instance in $resource.instances) {
                if ($instance.attributes.client_id -eq $ClientId -and $instance.attributes.client_auth.secret) {
                    return [string]$instance.attributes.client_auth.secret
                }
            }
        }
    } catch { return $null }
    return $null
}
function Get-ConfiguredBankClientSecret {
    param([string] $TerraformDirectory)
    try {
        # Let Terraform parse HCL, tfvars.json, auto.tfvars and TF_VAR precedence.
        # Base64 keeps console string rendering safe for arbitrary secret characters.
        $expression = 'base64encode(nonsensitive(var.client_secret))'
        $encodedJson = $expression | & terraform "-chdir=$TerraformDirectory" console -no-color 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $encoded = ($encodedJson -join "`n") | ConvertFrom-Json
        if ($encoded -isnot [string] -or -not $encoded) { return $null }
        return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
    } catch { return $null }
}
function Import-BankSettings {
    $tfDirectory = if ($env:BANK_TERRAFORM_DIR) { $env:BANK_TERRAFORM_DIR } else { Join-Path $script:BankRoot 'terraform/pingfederate' }
    if (@('BANK_OIDC_CLIENT_ID','BANK_OIDC_ISSUER','BANK_BASE_URL') | Where-Object { -not [Environment]::GetEnvironmentVariable($_, 'Process') }) {
    $json = & terraform "-chdir=$tfDirectory" output -json bank_environment
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read Terraform outputs. Apply the HR project first, or set BANK_TERRAFORM_DIR.' }
    $settings = ($json -join "`n") | ConvertFrom-Json
    foreach ($name in @('BANK_OIDC_CLIENT_ID','BANK_OIDC_ISSUER','BANK_BASE_URL')) {
        if (-not $settings.$name) { throw "Terraform output is missing $name." }
        if (-not [Environment]::GetEnvironmentVariable($name, 'Process')) { [Environment]::SetEnvironmentVariable($name, [string]$settings.$name, 'Process') }
    }
    }
    if (-not $env:BANK_OIDC_CLIENT_SECRET) {
        $env:BANK_OIDC_CLIENT_SECRET = Get-AppliedBankClientSecret $tfDirectory $env:BANK_OIDC_CLIENT_ID
    }
    if (-not $env:BANK_OIDC_CLIENT_SECRET) {
        $env:BANK_OIDC_CLIENT_SECRET = Get-ConfiguredBankClientSecret $tfDirectory
    }
    if (-not $env:BANK_OIDC_CLIENT_SECRET) {
        $secret = Read-Host 'Existing bank OIDC client secret (the value applied by Terraform)' -AsSecureString
        $env:BANK_OIDC_CLIENT_SECRET = [Net.NetworkCredential]::new('', $secret).Password
    }
    if (-not $env:BANK_OIDC_CLIENT_SECRET) { throw 'Bank OIDC client secret is required.' }
}
function Initialize-DatabaseConnection {
    if (-not $env:BANK_DATABASE_PORT) { $env:BANK_DATABASE_PORT = '15432' }
    $port = 0
    if (-not [int]::TryParse($env:BANK_DATABASE_PORT, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw 'BANK_DATABASE_PORT must be an integer between 1 and 65535.'
    }
    # Set the URL for existing packaged JARs too, while preserving an explicit override.
    if (-not $env:BANK_DATABASE_URL) {
        $env:BANK_DATABASE_URL = "jdbc:postgresql://localhost:$port/bank"
    }
}
function Read-DatabasePassword {
    if (-not $env:BANK_DATABASE_PASSWORD) {
        $password = Read-Host 'Bank database password (reuse the existing database password)' -AsSecureString
        $env:BANK_DATABASE_PASSWORD = [Net.NetworkCredential]::new('', $password).Password
    }
    if (-not $env:BANK_DATABASE_PASSWORD) { throw 'Database password is required.' }
}
function Start-Database {
    Initialize-DatabaseConnection
    Read-DatabasePassword
    Invoke-Checked 'docker' @('compose','-f',(Join-Path $script:BankRoot 'docker-compose.yml'),'up','-d','--wait','--wait-timeout','60')
}
function New-BankRuntimeJar {
    param([string] $SourceJar)
    Add-Type -AssemblyName System.IO.Compression
    # Hold a read-only handle while validating and copying, preventing concurrent writes.
    $source = [IO.File]::Open([IO.Path]::GetFullPath($SourceJar), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $archive = [IO.Compression.ZipArchive]::new($source, [IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            if (-not $archive.GetEntry('BOOT-INF/classes/com/darkedges/bank/BankApplication.class') -or
                -not ($archive.Entries | Where-Object { $_.FullName -like 'BOOT-INF/lib/logback-classic-*.jar' })) {
                throw 'Selected bank JAR is not an executable Spring Boot package. Stop the old portal and run make build, or set BANK_JAR to the packaged diagnostic JAR.'
            }
        } finally { $archive.Dispose() }
        $root = $env:BANK_RUNTIME_DIR
        if (-not $root) {
            $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local/share' }
            $root = Join-Path $base 'ExampleBank/runtime'
        }
        $directory = Join-Path ([IO.Path]::GetFullPath($root)) ([guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        $target = Join-Path $directory 'bank-onboarding.jar'
        $destination = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        try { $source.Position = 0; $source.CopyTo($destination) }
        finally { $destination.Dispose() }
        return $target
    } finally { $source.Dispose() }
}
function Start-Bank {
    param([switch] $SettingsLoaded)
    $java = Assert-Java
    if (-not $SettingsLoaded) { Import-BankSettings }
    Initialize-KeyPaths
    Initialize-DatabaseConnection
    Read-DatabasePassword
    foreach ($file in @($env:BANK_PRIVATE_JWK_FILE, $env:PASSPORT_PUBLIC_JWK_FILE)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing key file: $file. Run make setup first." }
    }
    $jar = if ($env:BANK_JAR) { $env:BANK_JAR } else { Join-Path $script:BankRoot 'target/bank-onboarding-0.1.0-SNAPSHOT.jar' }
    if (-not (Test-Path -LiteralPath $jar)) { throw 'Bank JAR is missing. Run make build first.' }
    Read-MailPassword
    Write-Host "Starting bank portal: $env:BANK_BASE_URL/hr (Ctrl+C to stop)"
    $runtimeJar = New-BankRuntimeJar $jar
    try { Invoke-Checked $java @('-jar', $runtimeJar) }
    finally {
        # Exact files created by this invocation only; never recursively delete runtime data.
        Remove-Item -LiteralPath $runtimeJar -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Split-Path $runtimeJar -Parent) -ErrorAction SilentlyContinue
    }
}
function Invoke-BankBuild {
    param([switch] $TestOnly)
    $java = Assert-Java
    $resolvedJava = (Get-Command $java -ErrorAction Stop).Source
    $env:JAVA_HOME = Split-Path (Split-Path $resolvedJava -Parent) -Parent
    $maven = if ($env:BANK_MVN) { $env:BANK_MVN } else { 'mvn' }
    $cache = if ($env:BANK_MAVEN_REPO) { @("-Dmaven.repo.local=$env:BANK_MAVEN_REPO") } else { @() }
    $vpPom = Join-Path (Split-Path (Split-Path $script:BankRoot -Parent) -Parent) 'oid4vp/pom.xml'
    Invoke-Checked $maven (@('-f', $vpPom, 'install', '-DskipTests') + $cache)
    $goal = if ($TestOnly) { 'test' } else { 'package' }
    Invoke-Checked $maven (@('-f',(Join-Path (Split-Path $script:BankRoot -Parent) 'pom.xml'),'-pl','bank-onboarding','-am',$goal) + $cache)
}
function Invoke-BankTask {
    param([string] $Name)
    switch ($Name) {
        'help' {
            Write-Host "make setup        Generate missing bank key and pin missing passport public key`nmake start        Setup keys, start PostgreSQL, load Terraform settings, run portal`nmake run          Load settings and run against an existing database`nmake db-up        Start PostgreSQL and wait for readiness`nmake db-down      Stop PostgreSQL and retain its data volume`nmake phone        Forward phone localhost:8094 over USB`nmake keys         Generate bank signing key only if missing`nmake passport-key Pin passport issuer public key only if missing`nmake build        Build sibling libraries and package bank with tests`nmake test         Build sibling dependencies and run bank/reactor tests`nmake doctor       Check Java and command availability`n`nSelect Java with JAVA_HOME (JDK 21+) or BANK_JAVA. Secrets come from the`ncalling shell, local .env, or secure prompts. Use make env to create .env. Run make phone`nin another terminal while make start is serving the portal."
        }
        'env' { Initialize-BankEnv }
        'doctor' {
            $java = Assert-Java
            Write-Host "Java: $java"
            foreach ($command in @('terraform','docker','mvn','adb')) {
                $found = Get-Command $command -ErrorAction SilentlyContinue
                Write-Host "${command}: $(if ($found) { $found.Source } else { 'not on PATH' })"
            }
        }
        'setup' { Initialize-BankKey; Initialize-PassportKey }
        'keys' { Initialize-BankKey }
        'passport-key' { Initialize-PassportKey }
        'db-up' { Start-Database }
        'db-down' { Read-DatabasePassword; Invoke-Checked 'docker' @('compose','-f',(Join-Path $script:BankRoot 'docker-compose.yml'),'stop') }
        'run' { Start-Bank }
        'start' { Assert-Java | Out-Null; Import-BankSettings; Initialize-BankKey; Initialize-PassportKey; Start-Database; Start-Bank -SettingsLoaded }
        'phone' { Invoke-Checked (Get-AdbExecutable) @('reverse','tcp:8094','tcp:8094') }
        'build' { Invoke-BankBuild }
        'test' { Invoke-BankBuild -TestOnly }
        default { throw "Unknown task: $Name" }
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    try { Import-BankEnv; Invoke-BankTask $Task }
    catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
