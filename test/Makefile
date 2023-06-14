.ONESHELL:

FLASK	= flask
FLASK.opt	= --host 0.0.0.0
APP	= App
F.log	= $(wildcard *.log)
PYTEST	= pytest --log-level=debug --capture=tee-sys
# -k test…
PYTOPT	=

.PHONY: run
run:
	export FLASK_APP=$(APP).py FLASK_DEBUG=1
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
	$(PYTEST) $(PYTOPT)

.PHONY: coverage
coverage:
	coverage run -m $(PYTEST) $(PYTOPT)
	$(MAKE) -C ../demo check.coverage
	coverage html ../FlaskSimpleAuth.py
	coverage report --fail-under=100 --include='*/FlaskSimpleAuth.py'

# not very usefull
# .PHONY: profile
# profile:
# 	python -m cProfile -s tottime $(PYTEST) $(PYTOPT)

.PHONY: clean
clean: stop
	$(RM) -r __pycache__ htmlcov .mypy_cache
	$(RM) $(F.log) .coverage
