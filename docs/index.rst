Welcome to FlaskSimpleAuth's documentation!
===========================================

FlaskSimpleAuth is a Flask wrapper to add a declarative security layer to
your routes with authentification, authorization and parameter management.

.. image:: https://github.com/zx80/flask-simple-auth/actions/workflows/fsa.yml/badge.svg?branch=master&style=flat
   :alt: Status
   :target: https://github.com/zx80/flask-simple-auth/actions/

.. image:: https://img.shields.io/badge/tests-79%20✓-success
   :alt: Tests

.. image:: https://img.shields.io/badge/coverage-100%25-success
   :alt: Coverage

.. image:: https://img.shields.io/github/issues/zx80/flask-simple-auth?style=flat)
   :alt: Issues
   :target: https://github.com/zx80/flask-simple-auth/issues

.. image:: https://img.shields.io/badge/python-3-informational
   :alt: Python

.. image:: https://img.shields.io/pypi/v/FlaskSimpleAuth
   :alt: Version
   :target:: https//pypi.org/project/FlaskSimpleAuth/

.. image:: https://img.shields.io/badge/badges-8-informational
   :alt: Badges

.. image:: https://img.shields.io/pypi/l/flasksimpleauth?style=flat
   :alt: License
   :target: https://creativecommons.org/publicdomain/zero/1.0/

In the following Flask application, two routes are implemented.

- the first route allows *ALL* authenticated users to access the store list.
- the second route allows an authenticated *user* which is a *manager* of
  *store* number *sid* is allowed to add the quantity of product to
  the store inventory.

In this code, there is *no* clue about how users are authenticated, this is set
from the configuration.
Only authorizations are declared on the route with the mandatory ``authorize``
parameter.
How these are checked is also set from the configuration.
HTTP or JSON parameters are automatically converted to the expected type.

.. code:: python
   # file "app.py"
   import FlaskSimpleAuth as fsa

   app = fsa.Flask("acme")
   app.config.from_envvar("ACME_CONFIG")

   @app.get("/store", authorize="ALL")
   def get_store():
       # return the list of stores
       return fsa.jsonify(...), 200

   @app.post("/store/<sid>", authorize=("store", "sid", "manager"))
   def post_store(sid: int, product: str, quantity: int):
       # product is added in quantity to store sid
       return "", 201

Here is an example of configuration for the above application:
Users are identified either with a JWT token or with a basic authentification.

.. code:: python
   # acme configuration
   import os

   FSA_AUTH = ["token", "basic"]
   FSA_TOKEN_TYPE = "jwt"
   FSA_TOKEN_SECRET = os.environ["ACME_SECRET"]

In this example, the framework needs two callbacks: one for retrieving the
salted hashed password for a user, and one for telling whether a user can
access a given store in a particular role.

.. code:: python
   # authentication and authorization callbacks
   @app.get_user_pass
   def get_user_pass(user: str) -> str|None:
       return ...  # hashed password retrieved from database

   @app.object_perms("store")
   def store_permission(sid: int, user: str, role: str) -> bool|None:
       return ...  # tell wether user can access store sid in role

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   Introduction <README>
   Documentation <DOCUMENTATION>
   Versions <VERSIONS>
   API <autoapi/FlaskSimpleAuth/>

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
