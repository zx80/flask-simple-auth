# convenient makefile

SHELL	= /bin/bash
.ONESHELL:

MODULE	= FlaskSimpleAuth

F.md	= $(wildcard *.md)
F.pdf	= $(F.md:%.md=%.pdf)

# PYTHON	= /snap/bin/pypy3
# PYTHON	= python3
PYTHON	= python
PIP		= venv/bin/pip

.PHONY: check.mypy
check.mypy: dev
	source venv/bin/activate
	mypy $(MODULE).py

.PHONY: check.pyright
check.pyright: dev
	source venv/bin/activate
	pyright $(MODULE).py

.PHONY: check.black
check.black: dev
	source venv/bin/activate
	black --check $(MODULE).py

IGNORE  = E227,E402,E501,E721,F401,F811

.PHONY: check.flake8
check.flake8: dev
	source venv/bin/activate
	flake8 --ignore=E127,E129,W504,$(IGNORE) $(MODULE).py

.PHONY: check.ruff
check.ruff: dev
	source venv/bin/activate
	ruff check --ignore=$(IGNORE) $(MODULE).py

.PHONY: check.pytest
check.pytest: dev
	source venv/bin/activate
	$(MAKE) -C test check

.PHONY: check.coverage
check.coverage: dev
	source venv/bin/activate
	$(MAKE) -C test coverage

# MD013: line length
.PHONY: check.docs
check.docs: dev
	source venv/bin/activate
	pymarkdown -d MD013 scan *.md */*.md
	sphinx-lint docs/

# just run the demo
.PHONY: check.demo
check.demo: dev
	source venv/bin/activate
	$(MAKE) -C demo check.pgall

STYLE	= flake8

.NOTPARALLEL: check.pytest check.coverage check.demo

.PHONY: check
check: check.pyright check.ruff check.$(STYLE) check.docs check.pytest check.demo check.coverage

.PHONY: clean
clean:
	$(RM) -r __pycache__ */__pycache__ dist build .mypy_cache .pytest_cache
	$(RM) $(F.pdf)
	$(MAKE) -C test clean
	$(MAKE) -C demo clean
	$(MAKE) -C docs clean

.PHONY: clean.venv
clean.venv: clean
	$(RM) -r venv *.egg-info
	$(MAKE) -C demo clean.venv

.PHONY: clean.dev
clean.dev: clean.venv

DEPS    = demo,password,jwt,cors,httpauth

# for local testing
venv:
	$(PYTHON) -m venv venv
	$(PIP) install -U pip
	$(PIP) install -e .[$(DEPS)]

venv/.dev: venv
	$(PIP) install -e .[dev,doc,tests,ldap]
	$(PIP) install python-ldap
	touch $@

.PHONY: dev
dev: venv/.dev

$(MODULE).egg-info: venv
	$(PIP) install -e .

# generate source and built distribution
dist: dev
	source venv/bin/activate
	$(PYTHON) -m build

.PHONY: publish
publish: dist
	# provide pypi login/pw or token somewhere…
	echo venv/bin/twine upload dist/*

# generate pdf doc
MD2PDF  = pandoc -f markdown -t latex -V papersize:a4 -V geometry:hmargin=2.5cm -V geometry:vmargin=3cm

%.pdf: %.md
	$(MD2PDF) -o $@ $<
