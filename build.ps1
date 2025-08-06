# build.ps1

param (
    [string]$semver,
    [string]$uind,
    [string]$channel,
    [switch]$binaryPatch,
    [string]$patchForUind,
    [string]$patchComparePath,
    [string]$os,
    [string]$arch,
    [string]$notes,
    [switch]$auto,
    [string]$out,
    [switch]$noCrossCompile,
    [string]$addDeploy,
    [string]$deployURL,
    [string]$ghUpMetaRepo,
    [switch]$doDebugLdflags,
    [switch]$help
)

# --- Configuration ---
$publicKeyFile = "./signing/public.pem"
$privateKeyFile = "./signing/private.pem"
$outputPath = "./builds"
$appName = "updatetest" # Name of your Go executable

# --- Help Text ---
if ($help) {
    Write-Host @"
Usage: .\build.ps1 [options]

Options:
  -semver "<string>"             Semantic version (e.g., 1.2.3)
  -uind <int>                    Unique update index (integer)
  -channel "<string>"            Deployment channel (e.g., release, dev)
  -binaryPatch                   Indicates this is a binary patch (default: no)
  -os "<string>"                 Target OS (windows, linux, darwin)
  -arch "<string>"               Target architecture (amd64, arm64)
  -notes "<string>"              Release notes
  -auto                          Uses default target OS/arch and disables binary patch
  -out "<filepath>"              Output JSON to file
  -noCrossCompile                Tells golang not to use cross-compilation by not adding GOOS and GOARCH env vars
  -addDeploy "<filepath>"        Add this entry to the following deploy.json under its channel
  -deployURL "<string>"          URL for the deploy.json, where most channels fetch updates from
  -ghUpMetaRepo "<owner>/<repo>" GitHub repository for "git." channels to fetch github releases from
  -debugLdflags                  Prints debug ldflags for the Go build
  -help                          Show this help message

Notes:
  If any parameter is missing, you will be prompted for it.
  Use --auto to skip prompts for target OS/arch and binary patch.

Examples:
  .\build.ps1 -semver "1.2.3" -uind 5 -channel "release"
  .\build.ps1 -semver "1.2.3" -uind 5 -channel "release" --auto
  .\build.ps1 -semver "1.2.3" -uind 5 -channel "dev" --binary-patch
  .\build.ps1 -semver "1.2.3" -uind 5 -channel "dev" -out "./entry.json"
"@
    exit
}

# --- Helper Functions ---

function Generate-KeyPair {
    param (
        [string]$privateKeyPath,
        [string]$publicKeyPath
    )
    # Private
    $re_made_private_key = $false
    if (-not (Test-Path $privateKeyPath)) {
        Write-Host "Generating new ECDSA private key..." -ForegroundColor Yellow
        try {
            & openssl ecparam -genkey -name prime256v1 -noout -out $privateKeyPath
            Write-Host "Private key saved to: $privateKeyPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to generate private key. Make sure OpenSSL is installed and in your PATH."
            exit 1
        }
        $re_made_private_key = $true
    } else {
        Write-Host "Private key already exists: $privateKeyPath" -ForegroundColor Cyan
    }
    # Public
    if (-not (Test-Path $publicKeyPath) -or $re_made_private_key) {
        # If $re_made_private_key is true, check if public key exists if so delete it
        if ($re_made_private_key -and (Test-Path $publicKeyPath)) {
            Remove-Item $publicKeyPath -Force
            Write-Host "Invalidated and removed existing public key: $publicKeyPath" -ForegroundColor Yellow
        }
        # If public key doesn't exist or we just created a new private key, generate public key
        Write-Host "Generating public key from private key..." -ForegroundColor Yellow
        try {
            & openssl ec -in $privateKeyPath -pubout -out $publicKeyPath
            Write-Host "Public key saved to: $publicKeyPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to generate public key. Make sure OpenSSL is installed and in your PATH."
            exit 1
        }
    } else {
        Write-Host "Public key already exists: $publicKeyPath" -ForegroundColor Cyan
    }
}

function LFNormalizePemFile {
    param (
        [string]$pemFilePath
    )
    if (-not (Test-Path $pemFilePath)) {
        throw "PEM file not found: $pemFilePath"
    }
    # Read the PEM file, normalize line endings to LF, and write back
    $content = Get-Content -Path $pemFilePath -Raw
    $normalizedContent = $content -replace "`r`n", "`n" # Normalize to LF
    Set-Content -Path $pemFilePath -Value $normalizedContent -Encoding UTF8
    Write-Host "Normalized PEM file: $pemFilePath" -ForegroundColor Green	
}

function Get-BinaryChecksum {
    param (
        [string]$filePath
    )
    if (-not (Test-Path $filePath)) {
        throw "File not found: $filePath"
    }
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $hashBytes = $hasher.ComputeHash($fileStream)
    $fileStream.Close()
    return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLower() # Convert to lowercase hex string
}

function Sign-Binary {
    param (
        [string]$filePath,
        [string]$privateKeyPath
    )
    if (-not (Test-Path $filePath)) {
        throw "File not found: $filePath"
    }
    if (-not (Test-Path $privateKeyPath)) {
        throw "Private key file not found: $privateKeyPath"
    }

    $signatureFilePath = "$filePath.sig"

    Write-Host "Signing binary..." -ForegroundColor Cyan
    try {
        # Run openssl to sign the file using SHA256 and ECDSA
        & openssl dgst -sha256 -sign $privateKeyPath -out $signatureFilePath $filePath

        if (-not (Test-Path $signatureFilePath)) {
            throw "Signature file was not created."
        }

        # Read signature file as bytes
        $sigBytes = [System.IO.File]::ReadAllBytes($signatureFilePath)

        # Encode to base64 using PowerShell
        $base64Signature = [Convert]::ToBase64String($sigBytes)

        # Delete the temporary signature file
        Remove-Item $signatureFilePath -Force

        return $base64Signature
    } catch {
        Write-Error "Failed to sign binary: $($_.Exception.Message)"
        exit 1
    }
}


function Generate-BSDiffPatch {
    param (
        [string]$oldFile,
        [string]$newFile,
        [string]$patchFile
    )
    Write-Host "Creating bsdiff patch from '$oldFile' to '$newFile' as '$patchFile'..." -ForegroundColor Cyan
    try {
        # This requires `bsdiff` and `bspatch` executables to be in your PATH
        # You can get them from: http://www.daemonology.net/bsdiff/
        & bsdiff "$oldFile" "$newFile" "$patchFile" -ErrorAction Stop
        Write-Host "BSDiff patch created successfully: $patchFile" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create bsdiff patch. Make sure bsdiff is installed and in your PATH. Error: $($_.Exception.Message)"
        exit 1
    }
}

function Validate-UIND {
    param(
        [string]$inputUind
    )
    if ([int]::TryParse($inputUind, [ref]$null)) {
        return [int]$inputUind
    }
    else {
        Write-Host "Provided UIND '$inputUind' is not a valid integer." -ForegroundColor Red
        return $null
    }
}

# https://jonathancrozier.com/blog/formatting-json-with-proper-indentation-using-powershell
function Format-Json
{
    <#
    .SYNOPSIS
        Applies proper formatting to a JSON string with the specified indentation.
 
    .DESCRIPTION
        The `Format-Json` function takes a JSON string as input and formats it with the specified level of indentation. 
        The function processes each line of the JSON string, adjusting the indentation level based on the structure of the JSON.
 
    .PARAMETER Json
        The JSON string to be formatted.
        This parameter is mandatory and accepts input from the pipeline.
 
    .PARAMETER Indentation
        Specifies the number of spaces to use for each indentation level.
        The value must be between 1 and 1024. 
        The default value is 2.
 
    .EXAMPLE
        $formattedJson = Get-Content -Path 'config.json' | Format-Json -Indentation 4
        This example reads the JSON content from a file named 'config.json', formats it with an 
        indentation level of 4 spaces, and stores the result in the `$formattedJson` variable.
 
    .EXAMPLE
        @'
        {
            "EnableSSL":  true,
            "MaxThreads":  8,
            "ConnectionStrings":  {
                                      "DefaultConnection":  "Server=SERVER_NAME;Database=DATABASE_NAME;Trusted_Connection=True;"
                                  }
        }
        '@ | Format-Json
        This example formats an inline JSON string with the default indentation level of 2 spaces.
 
    .NOTES
        This function assumes that the input string is valid JSON.
    #>
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]$Json,
 
        [ValidateRange(1, 1024)]
        [Int]$Indentation = 2
    )
 
    $lines = $Json -split '\n'
 
    $indentLevel = 0
 
    $result = $lines | ForEach-Object `
    {
        if ($_ -match "[\}\]]")
        {
            $indentLevel--
        }
 
        $line = (' ' * $indentLevel * $Indentation) + $_.TrimStart().Replace(":  ", ": ")
 
        if ($_ -match "[\{\[]")
        {
            $indentLevel++
        }
 
        return $line
    }
 
    return $result -join "`n"
}

# --- Main Script ---

# 1. Generate Key Pair if it doesn't exist
Generate-KeyPair $privateKeyFile $publicKeyFile

# 2. Get User Input
# semver
if (-not $semver) {
    $semver = Read-Host "Enter application semantic version (e.g., 1.0.0)"
}

# uind - must be integer
while (-not $uind) {
    $input = Read-Host "Enter unique update index (integer, e.g., 1, 2, 3)"
    $validUind = Validate-UIND $input
    if ($validUind -ne $null) {
        $uind = $validUind
    }
}

if ($uind -isnot [int]) {
    # try to validate CLI uind param if string
    $validUind = Validate-UIND $uind
    if ($validUind -eq $null) {
        # Prompt until valid integer
        while ($true) {
            $input = Read-Host "Enter unique update index (integer, e.g., 1, 2, 3)"
            $validUind = Validate-UIND $input
            if ($validUind -ne $null) {
                $uind = $validUind
                break
            }
        }
    }
    else {
        $uind = $validUind
    }
}

# channel
if (-not $channel) {
    $channel = Read-Host "Enter deployment channel (e.g., release, dev)"
}

# binary patch & target
$generatePatch = $false
if ($auto) {
    # If auto, use default values for targetOS, targetArch and isPatch = no
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $targetOS = $os ? $os : $env:OS.ToLower().Replace("windows_nt", "windows")
        $targetArch = $arch ? $arch : $env:PROCESSOR_ARCHITECTURE.ToLower()
    } else {
        $targetOS = "windows"
        $targetArch = "amd64"
    }
    $generatePatch = $false
    $patchForUind = $null
    $patchComparePath = $null
}
else {
    if ($binaryPatch.IsPresent) {
        $generatePatch = $true
    }
    else {
        # Prompt for binary patch if no flag given
        $resp = Read-Host "Is this a binary patch? (y/n)"
        $generatePatch = $resp -eq 'y'
    }
    if ($patchForUind) {
        $patchForUind = Validate-UIND $patchForUind
    } else {
        $patchForUindString = Read-Host "Enter the UIND of the version this patch is FOR (the old version's UIND)"
        $patchForUind = Validate-UIND $patchForUindString
    }
    # if $patchForUind is $null it was invalid while-prompt until valid
    if (-not $patchForUind) {
        while ($true) {
            $inputPatchFor = Read-Host "Enter the UIND of the version this patch is FOR (the old version's UIND)"
            $patchForUind = Validate-UIND $inputPatchFor
            if ($patchForUind -ne $null) {
                break
            }
        }
    }

    if (-not $patchComparePath) {
        $patchComparePath = Read-Host "Enter path to the previous version's binary for patch generation (e.g., ./builds/your_app_v1.0.0.exe)"
    }
    # If the $patchComparePath does not exist while-prompt it until it does
    while (-not (Test-Path $patchComparePath)) {
        Write-Host "Previous binary not found at: $patchComparePath. Please enter a valid path." -ForegroundColor Red
        $patchComparePath = Read-Host "Enter path to the previous version's binary for patch generation (e.g., ./builds/your_app_v1.0.0.exe)"
    }

    # Prompt targetOS and targetArch if not provided
    if (-not $os) {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $defaultOS = $env:OS.ToLower().Replace("windows_nt", "windows")
            $targetOS = Read-Host "Enter target OS (windows, linux, darwin). Current OS is $defaultOS"
            if ([string]::IsNullOrEmpty($targetOS)) {
                $targetOS = $defaultOS
            }
        } else {
            $targetOS = "windows" # Default to windows for Windows PowerShell
        }
    }
    else {
        $targetOS = $os
    }

    if (-not $arch) {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $defaultArch = $env:PROCESSOR_ARCHITECTURE.ToLower()
            $targetArch = Read-Host "Enter target architecture (amd64, arm64). Current Arch is $defaultArch"
            if ([string]::IsNullOrEmpty($targetArch)) {
                $targetArch = $defaultArch
            }
        } else {
            $targetArch = "amd64" # Default to amd64 for Windows PowerShell
        }
    }
    else {
        $targetArch = $arch
    }
}

# deployURL
if (-not $deployURL) {
    $deployURL = Read-Host "Enter the URL for the deploy.json (e.g., https://example.com/deploy.json)"
}

write-host $ghUpMetaRepo

# if ghUpMetaRepo is not set and ghUpMetaRepo is not emptystring and channel begins with "git."
if (-not $ghUpMetaRepo -and $ghUpMetaRepo -ne "" -and $channel -like "git.*") {
    $ghUpMetaRepo = Read-Host "Enter the github repository where github release channels are posted. (e.g., sbamboo/go-update-test)"
}


$goOsEnv = "GOOS=$targetOS"
$goArchEnv = "GOARCH=$targetArch"

# build time and commit hash
$buildTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
try {
    $commitHash = git rev-parse HEAD
}
catch {
    Write-Warning "Git not found or not a git repo; setting commit hash to 'unknown'"
    $commitHash = "unknown"
}

# 3. Create Output Directory
if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath | Out-Null
}

# 4. Build the Go Application
$binaryName = "$appName"
$platformKey = "$targetOS-$targetArch" # e.g., "windows-amd64"

$binaryName += "_v$semver"
$binaryName += "_$channel"
$binaryName += "_$platformKey"

if ($targetOS -eq "windows") { $binaryName += ".exe" }

$outputBinaryPath = Join-Path $outputPath $binaryName
$ldFlags = "-X 'main.AppVersion=$semver' -X 'main.AppUIND=$uind' -X 'main.AppChannel=$channel' -X 'main.AppBuildTime=$buildTime' -X 'main.AppCommitHash=$commitHash' -X 'main.AppDeployURL=$deployURL'"

# if $ghUpMetaRepo is set and not "", add it to ldflags
if ($ghUpMetaRepo -and $ghUpMetaRepo -ne "") {
    $ldFlags += " -X 'main.AppGhUpMetaRepo=$ghUpMetaRepo'"
}

if ($doDebugLdflags) {
    Write-Host "Debug ldflags:`n$ldFlags" -ForegroundColor Cyan
}

Write-Host "Building Go application..." -ForegroundColor Green
try {
    # Ensure current directory is the project root where go.mod is
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    Push-Location $scriptDir

    if ($noCrossCompile) {
        Set-Item -Path Env:GOOS -Value $targetOS
        Set-Item -Path Env:GOARCH -Value $targetArch
    }

    go build -ldflags "$ldFlags" -o $outputBinaryPath .
    if ($LASTEXITCODE -ne 0) {
        throw "Go build failed."
    }
    Write-Host "Build successful: $outputBinaryPath" -ForegroundColor Green
}
catch {
    Write-Error "Go build failed: $($_.Exception.Message)"
    exit 1
}
finally {
    Pop-Location # Restore previous location
    if ($noCrossCompile) {
        Remove-Item -Path Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item -Path Env:GOARCH -ErrorAction SilentlyContinue
    }
}

# 5. Calculate Checksum
$checksum = Get-BinaryChecksum $outputBinaryPath
Write-Host "Checksum (SHA256): $checksum" -ForegroundColor Green

# 6. Sign the Binary
$signature = Sign-Binary $outputBinaryPath $privateKeyFile
Write-Host "Signature: $signature" -ForegroundColor Green

# 7. Handle Patch Creation (if applicable)
$patchPublishURL = $null
$patchChecksum = $null
$patchSignature = $null
$patchFileName = $null
$patchFilePath = $null

if ($generatePatch) {
    # Make patch file path
    # <filename>_<uind>t<patchForUind>.patch
    $patchFile = $binaryName.Replace(".exe", "")
    if ($patchForUind) {
        $patchFileName += "_$uind"+"t$patchForUind.patch"
    } else {
        $patchFileName += "_$uind"+"t.patch"
    }
    $patchFilePath = Join-Path $outputPath $patchFileName

    # Generate the patch file
    Generate-BSDiffPatch "$patchComparePath" "$outputBinaryPath" "$patchFilePath"

    # Calculate Checksum for Patch
    $patchChecksum = Get-BinaryChecksum $patchFilePath
    Write-Host "Patch File Checksum (SHA256): $patchChecksum" -ForegroundColor Green

    # Sign the Patch File
    $patchSignature = Sign-Binary $patchFilePath $privateKeyFile
    Write-Host "Patch File Signature: $patchSignature" -ForegroundColor Green

    $patchPublishURL = "https://github.com/sbamboo/go-update-test/raw/refs/heads/main/builds/$patchFileName"

    #$patchFileName = "$binaryName.patch"
    #$patchFilePath = Join-Path $outputPath $patchFileName
    #Compress-File $previousBinaryPath $outputBinaryPath # bsdiff expects old_file new_file patch_file
    #Move-Item -Path $outputBinaryPath -Destination $patchFilePath # The output of bsdiff is usually the new file, need to rename it for the patch.
    # If bsdiff expects `bsdiff old_file new_file patch_output_file`, adjust this.
    # For now, assuming it generates directly into new_file after compression like `gzip`
    # Let's adjust this to correctly generate a separate patch file.
    # The `bsdiff` command typically takes `old_file new_file patch_file`.
    # We need to make a copy of $outputBinaryPath before running bsdiff, if the new binary is not the same as the patch output.

    # Correct way to generate a patch file:
    #$tempNewBinary = Join-Path $outputPath "temp_$binaryName"
    #Copy-Item $outputBinaryPath $tempNewBinary
    #$patchFileActual = Join-Path $outputPath "$($binaryName).patch"
    #Write-Host "Generating patch file: $patchFileActual from $previousBinaryPath to $tempNewBinary..." -ForegroundColor Cyan
    #try {
    #    & bsdiff "$previousBinaryPath" "$tempNewBinary" "$patchFileActual" -ErrorAction Stop
    #}
    #catch {
    #    Write-Error "Failed to generate bsdiff patch. Error: $($_.Exception.Message)"
    #    exit 1
    #}
    #Remove-Item $tempNewBinary # Clean up temp new binary

    #$patchURL = "https://github.com/sbamboo/go-update-test/raw/refs/heads/main/builds/$patchFileName"
}

$binaryPublishURL = "https://github.com/sbamboo/go-update-test/raw/refs/heads/main/builds/$binaryName"

# 8. Release notes
if (-not $notes) {
    $notes = Read-Host "Enter release notes"
}

# 9. Print JSON for deploy.json
$sourceInfo = @{
    is_patch        = $generatePatch
    url             = $binaryPublishURL
    checksum        = $checksum
    signature       = $signature
    patch_url       = $patchPublishURL # Will be null if not generating patch
    patch_checksum  = $patchChecksum # Will be null if not generating patch
    patch_signature = $patchSignature # Will be null if not generating patch
}

# if $patchForUind is null or empty string set it to $null else set it to int-convert
if (-not $patchForUind -or $patchForUind -eq "") {
    $sourceInfo.patch_for = $null
} else {
    $sourceInfo.patch_for = [int]$patchForUind
}

$sourcesMap = @{}
$sourcesMap[$platformKey] = $sourceInfo

$releaseEntry = @{
    uind      = [int]$uind
    semver    = $semver
    released  = $buildTime
    notes     = $notes
    sources   = $sourcesMap
}

$jsonEntry = ConvertTo-Json -InputObject $releaseEntry -Compress

Write-Host "`n--- Add this to your deploy.json ---" -ForegroundColor Yellow
Write-Host "Channel: $channel" -ForegroundColor Yellow
Write-Host $jsonEntry
Write-Host "-----------------------------------`n"

if ($out) {
    try {
        $jsonEntry | Out-File -FilePath $out -Encoding UTF8
        Write-Host "JSON written to $out" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to write JSON to file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($addDeploy) {
    if (-not (Test-Path $addDeploy)) {
        Write-Error "File not found: $addDeploy"
        exit 1
    }

    try {
        $deployContent = Get-Content $addDeploy -Raw | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to read or parse JSON from $addDeploy"
        exit 1
    }

    # Validate structure
    if ($null -eq $deployContent.format -or $null -eq $deployContent.channels) {
        Write-Error "Invalid deploy file format: missing 'format' or 'channels' keys."
        exit 1
    }

    # Convert channels to real hashtable if needed
    $channels = @{}
    foreach ($prop in $deployContent.channels.PSObject.Properties) {
        $channels[$prop.Name] = $prop.Value
    }

    # Add channel if missing
    if (-not $channels.ContainsKey($channel)) {
        $channels[$channel] = @()
    }

    # Append release entry
    $channels[$channel] += $releaseEntry

    # Reconstruct the object
    $deployContent.channels = $channels

    try {
        $deployContent | ConvertTo-Json -Depth 10 | Format-Json -Indentation 4 | Out-File -FilePath $addDeploy -Encoding UTF8
        Write-Host "Updated deploy file: $addDeploy" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to write updated deploy file: $($_.Exception.Message)"
        exit 1
    }
}

Write-Host "Remember to commit '$outputBinaryPath' (and patch '$patchFilePath' if applicable) and update 'deploy.json' in your repository." -ForegroundColor Green
