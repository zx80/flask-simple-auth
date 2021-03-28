# convenient makefile

.ONESHELL:

.PHONY: check
check: venv
	. venv/bin/activate
	type python3
	mypy FlaskSimpleAuth.py
	flake8 --ignore=E501,F401 FlaskSimpleAuth.py
	# to select some tests: -k pattern
	pytest --log-level=debug --capture=tee-sys tests

.PHONY: clean clean-venv
clean:
	$(RM) -r __pycache__ */__pycache__ *.egg-info dist build .mypy_cache .pytest_cache

clean-venv: clean
	$(RM) -r venv

.PHONY: install
install:
	pip3 install -e .

# for local testing
venv:
	python3 -m venv venv
	venv/bin/pip3 install wheel mypy flake8 pytest coverage requests ipython
	venv/bin/pip3 install passlib bcrypt pyjwt cryptography flask_httpauth
	venv/bin/pip3 install -e .

# generate source and built distribution
dist:
	python3 setup.py sdist bdist_wheel

.PHONY: publish
publish: dist
	# provide pypi login/pw or token somewhere…
	twine upload dist/*
