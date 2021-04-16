.ONESHELL:

FLASK	= flask
FLASK.opt	= --host 0.0.0.0
APP	= App
F.log	= $(wildcard *.log)
PYTEST	= pytest --log-level=debug --capture=tee-sys

.PHONY: run
run:
	export FLASK_APP=$(APP).py
	export FLASK_ENV=development
	$(FLASK) routes
	$(FLASK) run $(FLASK.opt) > $(APP).log 2>&1 &
	echo "flask running, see $(APP).log"

.PHONY: log
log:
	tail -f $(APP).log

.PHONY: stop
stop:
	-pkill flask

.PHONY: check
check:
	$(PYTEST)

.PHONY: coverage
coverage:
	coverage run -m $(PYTEST)
	coverage html FlaskSimpleAuth.py

.PHONY: clean
clean: stop
	$(RM) -r __pycache__ htmlcov .mypy_cache
	$(RM) $(F.log) .coverage
