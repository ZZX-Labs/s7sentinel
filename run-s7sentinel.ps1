$ErrorActionPreference = "Stop"
python -m s7sentinel.cli @args
exit $LASTEXITCODE
