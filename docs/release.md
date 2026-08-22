# Release Process

1. Update version in `s7sentinel/__init__.py` and `pyproject.toml`.
2. Update `CHANGELOG.md`.
3. Run `python -m unittest discover -s tests -v`.
4. Run `ruff check s7sentinel tests`.
5. Run `python -m compileall -q s7sentinel`.
6. Run `python -m build`.
7. Inspect wheel/sdist contents.
8. Create a signed or annotated Git tag `vX.Y.Z`.
9. Push the tag; GitHub Actions will build and attach artifacts to the release workflow.
10. Publish release notes from the changelog and call out security-impacting changes explicitly.

Release automation intentionally does not publish to PyPI by default. Package-registry publication should be enabled only after the project owner configures trusted publishing and provenance requirements.
