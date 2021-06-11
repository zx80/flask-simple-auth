.ONESHELL:

# switch to pg to test with postgres
DB	= db

# cleaning
.PHONY: clean clean-venv
clean: stop
	$(RM) -r __pycache__ .mypy_cache
	$(RM) stuff.db stuff.pg app.pid app.log users.sql
	pkill flask || true

clean-venv:
	$(RM) -r venv

# running the application
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

app.pid: stuff.$(DB)
	export FLASK_APP=app.py FLASK_ENV=development APP_CONFIG=app-$(DB).conf
	flask run > app.log 2>&1 &
	echo $$! > $@

venv:
	python3 -m venv venv
	. venv/bin/activate
	pip install -e ..
	pip install passlib bcrypt anodb psycopg2-binary
	pip install pytest

.PHONY: stop run run-pg check check-pg log

PYTEST  = pytest --log-level=debug --capture=tee-sys
check: stuff.$(DB)
	export FLASK_APP=app.py FLASK_ENV=development APP_CONFIG=app-$(DB).conf
	$(PYTEST) test_demo.py

check-pg:
	$(MAKE) DB=pg check

stop:
	[ -f app.pid ] && kill $(shell cat app.pid)
	exit 0

run: app.pid
	sleep 1  # wait for flask to start
	curl -i -X GET http://0.0.0.0:5000/now
	echo

run-pg:
	$(MAKE) DB=pg run

log: run
	tail -f app.log
