PYTHON ?= python3
VERSION := $(shell $(PYTHON) -c 'import passbro; print(passbro.__version__)')

.PHONY: test build clean

test:
	$(PYTHON) -m unittest

# Single-file executable: dist/passbro.pyz (needs python3-pykeepass at runtime).
build:
	rm -rf build dist
	mkdir -p build/app dist
	cp -r passbro build/app/
	find build/app -name __pycache__ -prune -exec rm -rf {} +
	$(PYTHON) -m zipapp build/app -m passbro.cli:main -p '/usr/bin/env python3' -o dist/passbro.pyz
	@echo "built dist/passbro.pyz $(VERSION)"

clean:
	rm -rf build dist
