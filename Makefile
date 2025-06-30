env = env PATH="${bin}:$$PATH"

venv:
	poetry install

clean_venv:
	poetry env remove --all

run:
	poetry run python -m app.main

setup-secrets:
	scripts/./setup-secrets.sh

setup: venv setup-secrets
	cp app.conf.example app.conf
	cp mock_register.json.example mock_register.json
	cp saml/idp/settings.json.example saml/idp/settings.json

lint:
	poetry run pylint app
	poetry run black --check app tests

audit:
	poetry run bandit -r app

fix:
	poetry run black app tests

test: venv setup
	poetry run pytest --cov --cov-report=term --cov-report=xml

type-check:
	poetry run mypy

check-all: fix lint type-check test audit
