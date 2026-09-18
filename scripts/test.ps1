# Unit tests on Windows, then real Linux components through an existing WSL Ubuntu.
# No installation or network calls to the pool.
$ErrorActionPreference = 'Stop'
$projectPath = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectPath
try {
    python -m unittest discover -s tests -p 'test_*.py' -v
    if ($LASTEXITCODE -ne 0) { throw 'Testes Python falharam.' }
    $convertedPath = wsl -d Ubuntu --exec wslpath -u ($projectPath.Replace('\', '/'))
    if ($LASTEXITCODE -ne 0 -or -not $convertedPath) { throw 'Nao foi possivel localizar o projeto no WSL Ubuntu.' }
    $linuxProject = $convertedPath.Trim()
    wsl -d Ubuntu --exec bash "$linuxProject/scripts/test.sh"
    if ($LASTEXITCODE -ne 0) { throw 'Testes/validacao Linux falharam.' }
} finally {
    Pop-Location
}
