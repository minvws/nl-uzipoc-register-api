env = env PATH="${bin}:$$PATH"

venv: .venv/touchfile ## Create virtual environment
.venv/touchfile: ## Includes workaround for https://github.com/xmlsec/python-xmlsec/issues/320
	test -d .venv || python3 -m venv .venv
	. .venv/bin/activate; pip install -U pip
	. .venv/bin/activate; pip install pip-tools
	. .venv/bin/activate && ${env} pip-compile --extra dev
	. .venv/bin/activate && ${env} pip-sync
	. .venv/bin/activate && ${env} pip install -e .
	. .venv/bin/activate && ${env} pip install --no-binary lxml==4.9.3 lxml==4.9.3 --force-reinstall
	. .venv/bin/activate && ${env} pip install --no-binary xmlsec==1.3.14 xmlsec==1.3.14 --force-reinstall
	touch .venv/touchfile

clean_venv: ## Remove virtual environment
	@echo "Cleaning venv"
	@rm -rf .venv

run:
	. .venv/bin/activate && ${env} python -m app.main

pip-sync: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} pip-compile --extra dev
	. .venv/bin/activate && ${env} pip-sync
	. .venv/bin/activate && ${env} pip install -e .

setup-secrets:
	rm -rf
	scripts/./setup-secrets.sh

setup: venv setup-secrets
	cp app.conf.example app.conf
	cp mock_register.json.example mock_register.json
	cp saml/idp/settings.json.example saml/idp/settings.json

lint:
	. .venv/bin/activate && ${env} pylint app
	. .venv/bin/activate && ${env} black --check app

audit:
	. .venv/bin/activate && ${env} bandit app

fix:
	. .venv/bin/activate && $(env) black app tests

test: venv setup
	. .venv/bin/activate && ${env} pytest tests

type-check:
	. .venv/bin/activate && ${env} MYPYPATH=stubs/ mypy --disallow-untyped-defs --show-error-codes app

coverage:
	. .venv/bin/activate && ${env} coverage run -m pytest tests && coverage report && coverage html

check-all: fix lint type-check test audit
