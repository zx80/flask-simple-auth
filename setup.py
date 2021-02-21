from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="FlaskSimpleAuth",
    version="0.1.0",
    packages=find_packages(),
    author="Fabien Coelho",
    author_email="flask.auth@coelho.net",
    url="https://github.com/zx80/flask-simple-auth",
    install_requires=[],
    description="Simple authentication for Flask, emphasizing configurability",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Programming Language :: Python",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
