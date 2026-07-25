param(
    [ValidateSet("contracts", "offline", "full", "live")]
    [string]$Mode = "contracts"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ($Mode -ne "live") {
    $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $VenvPython) {
        $PythonExe = $VenvPython
        $PythonPrefix = @()
    }
    elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $PythonExe = (Get-Command python).Source
        $PythonPrefix = @()
    }
    elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $PythonExe = (Get-Command py).Source
        $PythonPrefix = @("-3")
    }
    else {
        throw "Python 3 was not found. Create .venv and install requirements.txt plus requirements-dev.txt."
    }
}

Push-Location $RepoRoot
try {
    switch ($Mode) {
        "contracts" {
            & $PythonExe @PythonPrefix -m services.validation.agent_harness
        }
        "offline" {
            & $PythonExe @PythonPrefix -m pytest -q tests/agents tests/knowledge
        }
        "full" {
            & $PythonExe @PythonPrefix -m pytest -q
        }
        "live" {
            docker compose config --quiet
            docker compose ps
            docker compose exec -T orchestrator python -m services.validation.agent_harness
        }
    }
    if ($LASTEXITCODE -ne 0) {
        throw "THOS agent validation failed in '$Mode' mode."
    }
}
finally {
    Pop-Location
}
