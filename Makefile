# convenient makefile

SHELL	= /bin/bash
.ONESHELL:

MODULE	= FlaskSimpleAuth

F.md	= $(wildcard *.md)
F.pdf	= $(F.md:%.md=%.pdf)

PYTHON	= python
PIP		= venv/bin/pip

.PHONY: check check.mypy check.flake8 check.test check.demo
check.mypy: install
	. venv/bin/activate
	mypy $(MODULE).py

check.flake8: install
	. venv/bin/activate
	flake8 --ignore=E402,E501,F401 $(MODULE).py

check.test:
	$(MAKE) -C test check

check.demo:
	$(MAKE) -C demo check.pgall

check: install
	. venv/bin/activate
	type $(PYTHON)
	$(MAKE) check.mypy
	$(MAKE) check.flake8
	$(MAKE) check.test && \
	$(MAKE) check.demo

.PHONY: clean clean.venv
clean:
	$(RM) -r __pycache__ */__pycache__ *.egg-info dist build .mypy_cache .pytest_cache
	$(RM) $(F.pdf)
	$(MAKE) -C test clean
	$(MAKE) -C demo clean

clean.venv: clean
	$(RM) -r venv
	$(MAKE) -C demo clean.venv

.PHONY: install
install: $(MODULE).egg-info

# for local testing
venv:
	$(PYTHON) -m venv venv
	$(PIP) install wheel mypy flake8 pytest coverage requests ipython \
	  passlib bcrypt pyjwt cryptography flask_httpauth flask_cors anodb \
	  psycopg psycopg2 cachetools types-cachetools pymemcache redis types-redis

$(MODULE).egg-info: venv
	$(PIP) install -e .

# generate source and built distribution
dist:
	$(PYTHON) setup.py sdist bdist_wheel

.PHONY: publish
publish: dist
	# provide pypi login/pw or token somewhere…
	twine upload --repository $(MODULE) dist/*

# generate pdf doc
MD2PDF  = pandoc -f markdown -t latex -V papersize:a4 -V geometry:hmargin=2.5cm -V geometry:vmargin=3cm

%.pdf: %.md
	$(MD2PDF) -o $@ $<
