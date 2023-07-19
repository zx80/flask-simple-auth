SHELL   = /bin/bash
.ONESHELL:

PYTHON  = python3
VENV    = venv

# switch to pg or pg2 to test with postgres and psycopg
DB	= db

#
# CLEAN
#

.PHONY: clean clean.venv
clean: stop
	$(RM) *.tmp
	$(RM) -r __pycache__ .mypy_cache
	$(RM) stuff.db stuff.pg app.pid app.log users.sql
	pkill flask || true
	dropdb stuff || true

clean.venv: clean
	$(RM) -r venv

#
# VENV
#

venv:
	$(PYTHON) -m venv venv
	source venv/bin/activate
	pip install -e ..[password,tests,jwt]
	pip install anodb psycopg psycopg2 pydantic
	pip install pytest

#
# DATABASE
#

SCHEME	= bcrypt
CREDS	= foo:bla bla:foo

users.sql:
	./pass.py $(SCHEME) $(CREDS) > $@

stuff.db: users.sql
	sqlite3 $@ < create-db.sql
	sqlite3 $@ < data.sql
	sqlite3 $@ < users.sql

stuff.pg: users.sql
	createdb stuff
	psql stuff < create-pg.sql
	psql stuff < data.sql
	psql stuff < users.sql
	touch $@

.PHONY: stuff.pg2
stuff.pg2: stuff.pg

#
# RUN
#

APP	= app

.PHONY: stop run run.db run.pg run.pg2 log log.db log.pg log.pg2

app.pid: stuff.$(DB)
	[ "$(ENV)" ] && source $(VENV)/bin/activate
	export APP_CONFIG=$(APP)-$(DB).conf
	type flask || exit 1
	flask --app=$(APP).py --debug run > app.log 2>&1 &
	echo $$! > $@

stop:
	[ -f app.pid ] && kill $(shell cat app.pid)
	exit 0

run: app.pid
	sleep 1  # wait for flask to start
	curl -si -X GET http://0.0.0.0:5000/now
	echo

%.run:
	$(MAKE) APP=$* run

# make flask-restful-todos-init.demo
# make flask-restful-todos-fsa.demo
%.demo: $(VENV)
	demo=$*
	demo=$${demo/-fsa/}
	export DEMO_CONFIG=$*.conf
	export DEMO_SECRET="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
	$(MAKE) $*.run
	script="./$$demo-curl.sh"
	[ -x $$script ] && $$script

# NOTE colortail could be nice here
log: run
	tail -f app.log

run.db:
	$(MAKE) DB=db run

run.pg:
	$(MAKE) DB=pg run

run.pg2:
	$(MAKE) DB=pg2 run

log.db:
	$(MAKE) DB=db log

log.pg:
	$(MAKE) DB=pg log

log.pg2:
	$(MAKE) DB=pg2 log

#
# TESTS
#

F.py	= $(wildcard *.py)
PYTEST  = pytest --log-level=debug --capture=tee-sys
PYTOPT	=

.PHONY: check
check: check.pytest

.PHONY: check.pytest
check.pytest: stuff.$(DB)
	export FLASK_APP=app.py FLASK_DEBUG=1 APP_CONFIG=app-$(DB).conf
	$(PYTEST) $(PYTOPT) test_demo.py

.PHONY: check.mypy
check.mypy:
	mypy --ignore-missing-imports $(F.py)

.PHONY: check.flake8
check.flake8:
	flake8 --ignore=E227,E402,E501 $(F.py)

.PHONY: check.pg
check.pg:
	$(MAKE) DB=pg check

.PHONY: check.pg2
check.pg2:
	$(MAKE) DB=pg2 check

.PHONY: check.db
check.db:
	$(MAKE) DB=db check

.PHONY: check.pgall
check.pgall:
	$(MAKE) check.pg
	$(MAKE) check.pg2

.PHONY: check.all
check.all:
	$(MAKE) check.db
	$(MAKE) check.pgall

# coverage with tests of github actions
COVER_DATA  = ../test/.coverage

.PHONY: check.coverage
check.coverage: stuff.$(DB)
	export FLASK_APP=app.py FLASK_DEBUG=1 APP_CONFIG=app-$(DB).conf
	coverage run -a --data-file=$(COVER_DATA) -m $(PYTEST) $(PYTOPT) test_demo.py

