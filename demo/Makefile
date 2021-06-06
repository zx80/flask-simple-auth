.ONESHELL:

# cleaning
.PHONY: clean clean-venv
clean: stop
	$(RM) -r __pycache__
	$(RM) stuff.db app.pid app.log users.sql
	pkill flask || true

clean-venv:
	$(RM) -r venv

# running the application
SCHEME	= bcrypt
CREDS	= foo:bla bla:foo
users.sql:
	./pass.py $(SCHEME) $(CREDS) > $@

stuff.db: users.sql
	sqlite3 $@ < create.sql
	sqlite3 $@ < data.sql
	sqlite3 $@ < users.sql

app.pid: stuff.db
	export FLASK_APP=app.py FLASK_ENV=development APP_CONFIG=app.conf
	flask run > app.log 2>&1 &
	echo $$! > $@

venv:
	python3 -m venv venv
	. venv/bin/activate
	pip install -e ..
	pip install passlib bcrypt anodb
	pip install pytest

.PHONY: stop run log check

PYTEST  = pytest --log-level=debug --capture=tee-sys
check: stuff.db
	export FLASK_APP=app.py FLASK_ENV=development APP_CONFIG=app.conf
	$(PYTEST) test_demo.py

stop:
	[ -f app.pid ] && kill $(shell cat app.pid)
	exit 0

run: app.pid
	sleep 1  # wait for flask to start
	curl -i -X GET http://0.0.0.0:5000/now
	echo

log: run
	tail -f app.log
