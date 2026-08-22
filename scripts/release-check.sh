#!/usr/bin/env sh
set -eu
printf '%s\n' '[1/4] unit tests'
python -m unittest discover -s tests -v
printf '%s\n' '[2/4] compile check'
python -m compileall -q s7sentinel
printf '%s\n' '[3/4] lint'
ruff check s7sentinel tests
printf '%s\n' '[4/4] build'
python -m build
