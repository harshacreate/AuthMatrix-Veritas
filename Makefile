.PHONY: help setup test run workbench serve-vuln serve-secure clean

help:
	@echo "setup         - install dependencies"
	@echo "test          - run the pytest suite"
	@echo "run           - run the authorization probe report (route/role metrics)"
	@echo "workbench     - launch the interactive web workbench on 127.0.0.1:8070"
	@echo "serve-vuln    - serve the vulnerable app on 127.0.0.1:8000"
	@echo "serve-secure  - serve the secure app on 127.0.0.1:8001"

setup:
	python3 -m pip install -r requirements.txt

test:
	python3 -m pytest -q

run:
	python3 -m authz_tests.runner

workbench:
	python3 -m workbench.app

serve-vuln:
	python3 -m uvicorn sample_api.vulnerable:app --host 127.0.0.1 --port 8000

serve-secure:
	python3 -m uvicorn sample_api.secure:app --host 127.0.0.1 --port 8001

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache
