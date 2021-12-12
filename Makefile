# convenient makefile

.ONESHELL:
MODULE	= FlaskSimpleAuth.py
F.md	= $(wildcard *.md)
F.pdf	= $(F.md:%.md=%.pdf)

.PHONY: check
check: venv
	. venv/bin/activate
	type python3
	mypy $(MODULE)
	flake8 --ignore=E402,E501,F401 $(MODULE)
	$(MAKE) -C test check
	$(MAKE) -C demo check

.PHONY: clean clean-venv
clean:
	$(RM) -r __pycache__ */__pycache__ *.egg-info dist build .mypy_cache .pytest_cache $(F.pdf)
	$(MAKE) -C test clean
	$(MAKE) -C demo clean

clean-venv: clean
	$(RM) -r venv

.PHONY: install
install:
	pip3 install -e .

# for local testing
venv:
	python3 -m venv venv
	venv/bin/pip3 install -e .
	venv/bin/pip3 install wheel mypy flake8 pytest coverage requests ipython \
	  passlib bcrypt pyjwt cryptography flask_httpauth flask_cors anodb \
	  psycopg psycopg2

# generate source and built distribution
dist:
	python3 setup.py sdist bdist_wheel

.PHONY: publish
publish: dist
	# provide pypi login/pw or token somewhere…
	twine upload --repository FlaskSimpleAuth dist/*

# generate pdf doc
MD2PDF  = pandoc -f markdown -t latex -V papersize:a4 -V geometry:hmargin=2.5cm -V geometry:vmargin=3cm

%.pdf: %.md
	$(MD2PDF) -o $@ $<
