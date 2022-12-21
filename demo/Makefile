.ONESHELL:

# switch to pg or pg2 to test with postgres and psycopg
DB	= db

#
# CLEAN
#

.PHONY: clean clean.venv
clean: stop
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
	python3 -m venv venv
	. venv/bin/activate
	pip install -e ..
	pip install passlib bcrypt anodb psycopg psycopg2
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
	export APP_CONFIG=$(APP)-$(DB).conf TODOS_CONFIG=todos.conf
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

# make todos-fsa.demo
# make todos-frf.demo
%.demo:
	$(MAKE) $*.run
	./curl-todos.sh

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

PYTEST  = pytest --log-level=debug --capture=tee-sys
PYTOPT	=

.PHONY: check.mypy check.flake8 check check.db check.pg check.pg2 check.all check.pgall

check: stuff.$(DB)
	export FLASK_APP=app.py FLASK_DEBUG=1 APP_CONFIG=app-$(DB).conf
	$(PYTEST) $(PYTOPT) test_demo.py

# source files
F.py	= $(wildcard *.py)

check.mypy:
	mypy --ignore-missing-imports $(F.py)

check.flake8:
	flake8 --ignore=E402,E501 $(F.py)

check.pg:
	$(MAKE) DB=pg check

check.pg2:
	$(MAKE) DB=pg2 check

check.db:
	$(MAKE) DB=db check

check.all:
	$(MAKE) check.db
	$(MAKE) check.pgall

check.pgall:
	$(MAKE) check.pg
	$(MAKE) check.pg2
