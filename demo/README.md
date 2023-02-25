# FlaskSimpleAuth Demonstration Application

This app demonstrates a [REST](https://en.wikipedia.org/wiki/Representational_state_transfer)
API implementation with [Flask](https://palletsprojects.com/p/flask/) extension
[FlaskSimpleAuth](https://pypi.org/project/FlaskSimpleAuth/) used for authentication,
authorization and parameter management, and sharing database object which handles the
connection and queries using [AnoDB](https://pypi.org/project/anodb/),
[AioSQL](https://pypi.org/project/aiosql/) and [SQLite](https://sqlite.org)
or [Postgres](https://postgresql.org).


## Main Application

The application is structured around [app.py](app.py) which is configured from
[app-db.conf](app-db.conf) (for SQLite) or
[app-pg.conf](app-pg.conf) (for Postgres).

Database management is put in [database.py](database.py) which handles the `db`
shared object, initialized from the application.
See later [Database](#database) section for details.

Authentication and authorization hooks are declared in [auth.py](auth.py)
and rely on the database for storing user credentials.

There are two open routes: `GET /now` returns the current time from the database
thus checking that all is running, and `GET /who` returns the authenticated user
if there is any, else `null`.

Other routes are splitted in four blueprints which all use the shared database
object:
 - [`stuff.py`](stuff.py) defines `/stuff` routes which simply stores string in the
   `Stuff` table.
 - [`users.py`](users.py) defines `/users` routes for user management by admins.
 - [`scare.py`](scare.py) defines `/scare` routes for user self-care, that is
   self registration, obtaining authentication tokens, changing one's password
   and deleting oneself, all this in under *30* lines of code.
 - [`types_path.py`](types_path.py) defines `/types` routes which demonstrates
   parameter types management.
 - [`oauth.py`](oauth.py) defines `/oauth` routes to demonstrates OAuth usage,
   that is authorizations granted by some external issuer and delivered using
   a token.

The next sections describe the convenient features which distinguish this
demo compared to what would be required if only Flask was being used.


## Application Authentication

The application uses *fsa* tokens or *HTTP basic* authentication… but there
is no single trace of that in the application code. **THIS IS A GOOD THING**.
The authentication requirements can be changed without editing any line
of code, just by updating the configurations in [app.conf](app.conf):

 - Do you want parameter-based authentication? Set `FSA_AUTH` to `param`.
 - Do you rather want the application to inherit the authentication performed
   by the web server? Set `FSA_AUTH` to `httpd`.
 - Do you want passwords stored with another scheme? Adjust `FSA_PASSWORD_SCHEME`
   to anything `passlib` provides.
 - Do you want *JWT* authentication tokens? Set `FSA_TOKEN_TYPE` to `jwt`.
 - Do you want tokens carried by a *bearer* authentication header?
   Set `FSA_TOKEN_CARRIER` to `bearer`.

FlaskSimpleAuth passwords are retrieved with the `get_user_pass` hook,
which must be provided.
The `pass.py` script allows to generate initial credentials for the
demo application.
The astute query behind `get_user_pass` allows the user to authenticate
themselves either using their login or their email.


## Application Authorization

Authorization are declared on each route with the `authorize` parameter.

Further permissions are checked within route functions, for instance
the `PATCH /scare` route for changing one's password rejects a user if the
provided old password (`opass`) is not validated.

FlaskSimpleAuth roles (groups) are checked with the `user_in_group` hook,
which must be provided.

The `GET` and `DELETE` methods on `/users/<login>` are controlled with
a finer grain permission model: both admins and the user themselves can access
the route, which is controlled through a domain-specific function registered
with the `object_perms` hook.


## API Parameters

The application retrieve API parameters transparently and turns them
into typed function parameters at the python level. The application code
does not need to dive into `request`, which does not appear anywhere.
Parameters may come from `args`, `form` or `json`, the application
does not need to care.

For instance in [users.py](users.py), the `PATCH /users/<login>` route
includes a mandatory `login` url string parameter to identify the user,
and two optional `pass` string and `admin` boolean parameters to describe
expected changes.

The [types\_path.py](types_path.py) blueprint illustrates getting
various parameter types, including the convenient `JsonData` types
which converts a string to a JSON data structure.


## Database

Flask, because Python memory management requires a global lock (GIL) which
is a pain, enforces a one thread process which relies on global
variables instead of functions parameters (eg `request`, `app`, `g`).
Thus database interactions follow this disputable model and are managed by
a global object named `db` in the demo application.

When trying to split their application in distinct files, the user quickly
bumps into a reference sharing and initialization chicken-and-egg problem,
which is solved thanks to the `Reference` object provided by `FlaskSimpleAuth`:
the class provides method access indirections so that the order of imports
and initialization does not matter.

The database catalogue must be initialized before starting the application.
This is done by running [create-db.sql](create-db.sql) for SQLite or
[create-pg.sql](create-pg.sql) for Postgres to create the two tables,
[data.sql](data.sql) for initial application data, and
`users.sql` generated with script [pass.py](pass.py)
for initial application users.

 - database interactions are methods associated to the `db` object, which
   under the hood are mapped to SQL queries defined in [queries.sql](queries.sql).
 - [database.py](database.py) holds the global `db` object, including its
   initialization by `init_app`. The initialization consists in loading the
   queries and creating a persistent database connection.
 - the configuration parameters are declared in [app-db.conf](app-db.conf)
   or [app-pg.conf](app-pg.conf) with 4 `DB_*` directives which provide the
   engine name, connection, queries and options.
 - the initialization is performed when [app.py](app.py) calls the
   [database.py](database.py) `init_app` function, which is a clean application
   pattern to ensure that it is done once, but which also allows to share the
   database python file between applications.
 - the global shared `db` object is used locally in [app.py](app.py), but also in
   [auth.py](auth.py) for user authentification and authorization hooks, and in the
   3 blueprints [scare.py](scare.py), [users.py](users.py) and [stuff.py](stuff.py),
   only at the price of a trivial one liner:

   ```python
   from database import db
   ```

If someone wants to change the underlying DB, the SQL files may need to be updated
for the SQL variant syntax, as the `DB_*` configuration directives for driver
and connection management.
Compare [create-db.sql](create-db.sql) vs [create-pg.sql](create-pg.sql)
and [app-db.conf](app-db.conf) vs [app-pg.conf](app-pg.conf).


## Demo Run

A [Makefile](Makefile) is provided to ease running the demo application.
Make macro `DB` can be set to `db` for SQLite, `pg2` and `pg` for Postgres
with `psycopg` driver version 2 and 3.

 - `make venv` generates a suitable virtual environment.
 - `make check` runs `pytest` on the demonstration with SQLite.
 - `make DB=pg check` to run tests with Postgres using the psycopg 3 driver.
 - `make DB=pg run` starts the demo application, with logs in `app.log` and
    process id in `app.pid`.
 - `make DB=pg log` runs and tails logs.
 - `make stop` stops the application.
 - `make clean` cleans generated files.
 - `make clean.venv` removes the virtual environment.

See example `curl` commands in [curl-demo.sh](curl-demo.sh).

## Todos Application

The simplistic `todos` application from Flask-RESTful documentation is proposed
in two flavors:

- [`todos-frf.py`](todos-frf.py) is a copy of the
  [initial version](https://github.com/flask-restful/flask-restful/blob/master/examples/todo.py).
- [`todos-fsa.py`](todos-fsa.py) is a reimplementation with *Flask Simple Auth*
  which is shorter, simpler and IMO more elegant, that is better.
  It is initialized with file [`todos.conf`](todos.conf).

The [`curl-todos.sh`](curl-todos.sh) script provides simple `curl` requests
to test all methods and paths.
To test this applications, run `make todos-fsa.demo`.
