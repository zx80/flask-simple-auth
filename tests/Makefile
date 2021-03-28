.ONESHELL:

FLASK	= flask
FLASK.opt	= --host 0.0.0.0
APP	= App
F.log	= $(wildcard *.log)

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
	pytest --log-level=debug --capture=tee-sys

.PHONY: coverage
coverage:
	coverage run -m pytest --log-level=debug --capture=tee-sys
	coverage html FlaskSimpleAuth/__init__.py

.PHONY: clean
clean: stop
	$(RM) -r __pycache__ htmlcov
	$(RM) $(F.log) .coverage
