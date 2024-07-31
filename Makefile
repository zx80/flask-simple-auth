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
check.mypy: venv
	source venv/bin/activate
	mypy $(MODULE).py

.PHONY: check.pyright
check.pyright: venv
	source venv/bin/activate
	pyright $(MODULE).py

.PHONY: check.black
check.black: venv
	source venv/bin/activate
	black --check $(MODULE).py

IGNORE  = E227,E402,E501,E721,F401,F811

.PHONY: check.flake8
check.flake8: venv
	source venv/bin/activate
	flake8 --ignore=E127,W504,$(IGNORE) $(MODULE).py

.PHONY: check.ruff
check.ruff: venv
	source venv/bin/activate
	ruff check --ignore=$(IGNORE) $(MODULE).py

.PHONY: check.pytest
check.pytest: venv
	source venv/bin/activate
	$(MAKE) -C test check

.PHONY: check.coverage
check.coverage: venv
	source venv/bin/activate
	$(MAKE) -C test coverage

# MD013: line length
.PHONY: check.docs
check.docs:
	source venv/bin/activate
	pymarkdown -d MD013 scan *.md */*.md
	sphinx-lint docs/

# just run the demo
.PHONY: check.demo
check.demo: venv
	source venv/bin/activate
	$(MAKE) -C demo check.pgall

STYLE	= flake8

.PHONY: check
check: venv
	source venv/bin/activate
	type $(PYTHON)
	$(MAKE) check.pyright
	$(MAKE) check.ruff
	$(MAKE) check.docs
	$(MAKE) check.$(STYLE)
	$(MAKE) check.pytest && \
	$(MAKE) check.demo && \
	$(MAKE) check.coverage

.PHONY: clean clean.venv
clean:
	$(RM) -r __pycache__ */__pycache__ dist build .mypy_cache .pytest_cache
	$(RM) $(F.pdf)
	$(MAKE) -C test clean
	$(MAKE) -C demo clean
	$(MAKE) -C docs clean

clean.venv: clean
	$(RM) -r venv *.egg-info
	$(MAKE) -C demo clean.venv

# for local testing
venv:
	$(PYTHON) -m venv venv
	$(PIP) install -U pip
	$(PIP) install -e .[dev,doc,tests,demo,password,jwt,cors,httpauth]

.PHONY: venv.dev
venv.dev: venv

$(MODULE).egg-info: venv
	$(PIP) install -e .

# generate source and built distribution
dist: venv
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
