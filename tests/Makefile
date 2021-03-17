.ONESHELL:

FLASK	= flask
FLASK.opt	= --host 0.0.0.0
F.log	= App.log

.PHONY: run
run:
	export FLASK_APP=App.py
	export FLASK_ENV=development
	$(FLASK) routes
	$(FLASK) run $(FLASK.opt) > $(F.log) 2>&1 &
	echo "flask running, see $(F.log)"

.PHONY: stop
stop:
	-pkill flask

.PHONY: clean
clean: stop
	$(RM) -r __pycache__
	$(RM) $(F.log)
