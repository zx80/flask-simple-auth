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

.PHONY: check check.mypy check.flake8 check.black check.pytest check.demo check.coverage check.pymarkdown
check.mypy: venv
	source venv/bin/activate
	mypy --implicit-optional $(MODULE).py

check.flake8: venv
	source venv/bin/activate
	flake8 --ignore=E127,E227,E402,E501,E721,F401,W504 $(MODULE).py

check.black: venv
	source venv/bin/activate
	black --check $(MODULE).py

check.pytest: venv
	$(MAKE) -C test check

check.coverage: venv
	$(MAKE) -C test coverage

check.pymarkdown:
	pymarkdown scan *.md

# just run the demo
check.demo: venv
	$(MAKE) -C demo check.pgall

STYLE	= flake8

check: venv
	source venv/bin/activate
	type $(PYTHON)
	$(MAKE) check.mypy
	$(MAKE) check.pymarkdown
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

clean.venv: clean
	$(RM) -r venv *.egg-info
	$(MAKE) -C demo clean.venv

# for local testing
venv:
	$(PYTHON) -m venv venv
	$(PIP) install -U pip
	$(PIP) install -e .[dev,tests,demo,password,jwt,cors,httpauth]

.PHONY: venv.dev
venv.dev: venv

$(MODULE).egg-info: venv
	$(PIP) install -e .

# generate source and built distribution
dist:
	$(PYTHON) -m build

.PHONY: publish
publish: dist
	# provide pypi login/pw or token somewhere…
	echo twine upload dist/*

# generate pdf doc
MD2PDF  = pandoc -f markdown -t latex -V papersize:a4 -V geometry:hmargin=2.5cm -V geometry:vmargin=3cm

%.pdf: %.md
	$(MD2PDF) -o $@ $<
