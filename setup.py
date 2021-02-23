from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="FlaskSimpleAuth",
    version="1.3.0",
    packages=find_packages(),
    author="Fabien Coelho",
    author_email="flask.auth@coelho.net",
    url="https://github.com/zx80/flask-simple-auth",
    install_requires=["passlib"],
    description="Simple authentication for Flask, emphasizing configurability",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Programming Language :: Python",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
