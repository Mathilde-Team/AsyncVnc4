.PHONY: test

# Même seuil et mêmes contrôles que le job Qualité, sans valeur recopiée.
test:
	uv run coverage erase
	uv run coverage run --parallel-mode -m unittest test_asyncvnc2 test_reseau_local test_decodage_video test_couverture_branches test_verifier_couverture -v
	uv run coverage combine --keep
	uv run coverage report
	uv run coverage json -o coverage.json
	uv run python scripts/verifier_couverture.py coverage.json
