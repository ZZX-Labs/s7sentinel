$ErrorActionPreference = "Stop"
Write-Output "[1/4] unit tests"
python -m unittest discover -s tests -v
Write-Output "[2/4] compile check"
python -m compileall -q s7sentinel
Write-Output "[3/4] lint"
ruff check s7sentinel tests
Write-Output "[4/4] build"
python -m build
