VENV           = .venv
VENV_PYTHON    = $(VENV)/bin/python3
SYSTEM_PYTHON  = $(shell which python3)

# If virtualenv exists, use it. If not, find python using PATH
PYTHON         = $(or $(wildcard $(VENV_PYTHON)), $(SYSTEM_PYTHON))


all: 
	@echo "Please choose specific target option"


.PHONY: build
build: clean
	$(PYTHON) -m build


.PHONY: clean
clean:
	rm -rf bip39toolkit.egg-info/
	rm -rf build/
	rm -rf dist/
	#rm -rf doc/
	rm -rf __pycache__/
	rm -rf tests/__pycache__/
	rm -rf .pytest_cache/
	rm -rf .coverage.*


.PHONY: coverage
coverage:
	$(PYTHON) -m pytest --cov-report html:doc/coverage-report --cov bip39toolkit tests/


.PHONY: test
test: 
	$(PYTHON) -m pytest


.PHONY: upload
upload:
	# Upload to https://pypi.org
	$(PYTHON) -m twine upload dist/*


.PHONY: upload-test
upload-test:
	# Upload to https://test.pypi.org
	# Login according to: https://packaging.python.org/tutorials/packaging-projects/
	$(PYTHON) -m twine upload --repository testpypi dist/*


.PHONY: venv
venv:
	$(SYSTEM_PYTHON) -m venv .venv
	.venv/bin/python3 -m pip install --upgrade pip
	.venv/bin/python3 -m pip install -r requirements-dev.txt
