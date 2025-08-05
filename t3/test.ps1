# CD to .\ folder based on the current script location (<currentScript>)
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Delete ./private.key if exists
if (Test-Path -Path "./private.key") {
    Remove-Item -Path "./private.key" -Force
}

# Delete ./public.key if exists
if (Test-Path -Path "./public.key") {
    Remove-Item -Path "./public.key" -Force
}

# Delete ./builds folder
Remove-Item -Path "./builds" -Recurse -Force

# Replace ./deploy.json content with
#```
# {
#     "format": 1,
#     "channels": {
#         "release": [],
#         "dev": []
#     }
# }
#```
$deployJsonContent = @"
{
    "format": 1,
    "channels": {
        "release": [],
        "dev": []
    }
}
"@
Set-Content -Path "./deploy.json" -Value $deployJsonContent -Force

# Run builds script for four versions
.\build.ps1 -semver 0.0.0 -uind 1 -channel dev -notes "The first commit (dev)" -auto -noCrossCompile -addDeploy .\deploy.json
.\build.ps1 -semver 0.0.0 -uind 2 -channel release -notes "The first commit" -auto -noCrossCompile -addDeploy .\deploy.json
.\build.ps1 -semver 0.0.1 -uind 3 -channel dev -notes "The second commit (dev)" -auto -noCrossCompile -addDeploy .\deploy.json
.\build.ps1 -semver 0.0.1 -uind 4 -channel release -notes "The second commit" -auto -noCrossCompile -addDeploy .\deploy.json

# If exists delete the .\workspace folder
if (Test-Path -Path "./workspace") {
    Remove-Item -Path "./workspace" -Recurse -Force
}

# Create .\workspace folder
New-Item -Path "./workspace" -ItemType Directory -Force | Out-Null

# Copy .\builds\updatetest_v0.0.0_dev_windows-amd64.exe and .\builds\updatetest_v0.0.0_release_windows-amd64.exe to .\workspace
Copy-Item -Path "./builds/updatetest_v0.0.0_dev_windows-amd64.exe" -Destination "./workspace/updatetest_v0.0.0_dev_windows-amd64.exe" -Force
Copy-Item -Path "./builds/updatetest_v0.0.0_release_windows-amd64.exe" -Destination "./workspace/updatetest_v0.0.0_release_windows-amd64.exe" -Force

# CD to .\workspace folder based on the current script location (<currentScript>\workspace)
Set-Location -Path (Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath "workspace")