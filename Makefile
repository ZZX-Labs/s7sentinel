.PHONY: test lint build check clean

test:
	python -m unittest discover -s tests -v

lint:
	ruff check s7sentinel tests

build:
	python -m build

check: test lint
	python -m compileall -q s7sentinel

clean:
	python -c "import shutil; [shutil.rmtree(p, ignore_errors=True) for p in ('build','dist','s7sentinel.egg-info')]"
