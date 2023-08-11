# FlaskSimpleAuth Recipees

Here are a few task-oriented recipees with
[FlaskSimpleAuth](https://pypi.org/project/flasksimpleauth/).
Feel free to submit your questions!

## Installation

### How-to install FlaskSimpleAuth?

FlaskSimpleAuth is a Python module available from [PyPI](https://pypi.org/project/FlaskSimpleAuth/).
Install it, for instance with `pip`, with the required dependencies:

```shell
pip install FlaskSimpleAuth[password,jwt,cors,redis]
```

## Authentication

For details, see the relevant
[authentication](https://zx80.github.io/flask-simple-auth/DOCUMENTATION.html#authentication-schemes)
section in the documentation.

### How-to configure basic authentication?

HTTP Basic authentication is a login and password authentication encoded in
*base64* into an `Authorization` HTTP header.

- set `FSA_AUTH` to `basic` or to contain `basic`, or have a route with
  a `auth="basic"` parameter.
- register a `get_user_pass` hook.
- simple authentication routes are triggered with `authorize="ALL"`

### How-to configure parameter authentication?

This is login and password authentication passed as HTTP or JSON parameters.

- set `FSA_AUTH` to `param` or to contain `param`, or have a route with
  a `auth="param"` parameter.
- the name of the expected two parameters are set with `FSA_PARAM_USER` and
  `FSA_PARAM_PASS`.
- register a `get_user_pass` hook.
- simple authentication routes are triggered with `authorize="ALL"`

### How-to configure token authentication?

It is enabled by default.

If you do not really need JWT compatibility, keep the default `fsa` token type
(`FSA_TOKEN_TYPE`) which is human readable, unlike JWT.

### How to disable token authentication?

- set `FSA_AUTH` to the list of authentication schemes, which must
  *not* contain `token`.
- set `FSA_TOKEN_TYPE` to `None`.

### How-to get the current user login as a string?

There are several equivalent options:

- call `app.current_user()` on an authenticated route.
- use a special `CurrentUser` parameter type on a route to retrieve the user name.
- call `app.get_user()` on any route, an authentification will be attempted.

### How-to get the current user as an object?

You must build the object yourself, based on the string user name.

- with a function of your making:
  ```python
  def get_user_object():
      return UserObject(app.current_user())
  ```
- for convenience, this function can be registered as a special parameter
  associated to the type:
  ```python
  app.special_parameter(UserObject, lambda _: get_user_object())

  @app.route("/...", authorize="ALL")
  def route_dotdotdot(user: UserObject)
      ...
  ```

### How-to store login and passwords?

Passwords must be stored as cryptographic salted hash, so as to deter hackers
from recovering passwords too easily of the user database is leaked.

FlaskSimpleAuth provides state-of-the-art settings by default using `bcrypt`
with *4* rounds (about 2⁴ hash calls) and ident `2y`. Keep that unless you really
have a strong opinion against it.

The number of rounds is kept as low as allowed by the library because
cryptographic password functions are very expensive, eg with *12* rounds,
which is `passlib` default, results in *several 100 ms* computation time,
which for a server is astronomically high.

Method `app.hash_password(…)` applies hashes the passwords according to the
current configuration. The `get_user_pass` hook will work as expected if it
returns such a value stored from a previous call.

### How-to implement my own authentication scheme?

- create a hooks which returns the login based on the app and request:
  ```python
  def xyz_authentication(app, req):
      # investigate the request and return the login or None for 401
      return ...
  ```
- register this hook as an authentication scheme:
  ```python
  app.authentication("xyz", xyz_authentication)
  ```
- use this new authentication method in `FSA_AUTH` or maybe on some route with
  an `auth="xyz"` parameter.

### How-to test authentication and authorizations without any password?

Use `FSA_AUTH="fake"` and pass the expected login as a request parameter
(`FSA_FAKE_LOGIN`, defaults to `LOGIN`).

Fake authentication is **only** allowed for *localhost* connections and cannot
be deployed on a real server.

### How-to use LDAP/AD authentication?

The AD password checking model is pretty strange, as it requires to send the
clear password to the authentication server to check whether it is accepted.
To do that:

- create a new password checking function which will do that.
  ```python
  def check_login_password_with_AD_server(login: str, password: str) -> bool|None:
      import ldap
      # connect to server... send login/pass... look for result...
      return ...
  ```
  - on `True`: the password is accepted
  - on `False`: it is not
  - on `None`: 401 (no such user)
  - if unhappy: raise an `ErrorResponse` exception
- register this hook
  ```python
  app.password_check(check_login_password_with_AD_server)
  ```
- you do not need to have a `get_user_pass` hook if this is the sole password
  scheme used by your application.

### How-to use multi-factor authentication (MFA)?

The idea is to rely on an intermediate *token* with a temporary *realm* to validate
that an authenfication method has succeeded, and that another must still be checked.

- create a route with the *first* auth method, eg a login/password basic authentication.
  ```python
  @app.get("/login1", authorize="ALL", auth="basic")
  def get_login1(user: fsa.CurrentUser):
      # trigger sending an email or SMS for a code
      send_temporary_code_to_user(user)
      # 10 minutes token provided with this basic authentication
      return app.create_token(user, realm="login1", delay=10.0), 200
  ```
- create a route protected by the previous token, and check the email or SMS
  code provided by the user at this stage.
  ```python
  @app.get("/login2", authorize="ALL", auth="token", realm="login1")
  def get_login2(user: fsa.CurrentUser, code: str):
      if not check_code_validity(user, code):
          return "invalid validation code", 401
      # else return the final token
      return app.create_token(user), 200
  ```
- Only allow token authentication on other routes with `FSA_AUTH = "token"`.

See [MFA demo](https://github.com/zx80/flask-simple-auth/blob/main/demo/mfa.py).

## Authorization

For details, see the relevant
[authorization](https://zx80.github.io/flask-simple-auth/DOCUMENTATION.html#authorization)
section in the documentation.

### How-to close a route?

Use `authorize="NONE"` as a route parameter.
This will trigger a 403 forbidden response.

### How-to open a route?

Use `authorize="ANY"` as a route parameter.
*ANY*one can execute the route, without authentication.

### How-to just authenticate a route?

Use `authorize="ALL"` as a route parameter.
*ALL* authenticated users can execute the route.

### How-to use group authorizations?

Group authorizations are permissions based on belonging to a group.
For that, you must:

- create a callback to check whether a user belongs to a group:
  ```python
  def user_in_group(login: str, group: str) -> bool:
      return ... # whether user belong to the group
  ```
- register this callback as a `user_in_group` hook:
  ```python
  app.user_in_group(user_in_group)
  ```
- declare that the group authorization is required on a route definition:
  ```python
  @app.route("/admin-access", authorize="admin")
  def ...
  ```
- for detecting group name typos, declare existing groups in the configuration:
  ```python
  FSA_AUTHZ_GROUPS = [ "admin", "client", "manager", ... ]
  ```

### How-to use object authorizations?

In most application, access permissions depend on some kind of relationship to
the data, e.g. someone may read a message because they are either the recipient
or the sender of this particular message.

- object authorization require a per-domain callback which tells whether an
  *id*entified object of the domain can be access by a *user* in a *role*.
  ```python
  # domain "stuff" permission callback
  def stuff_permissions(stuff_id: int, login: str, role: str):
      return ...
  ```
- this callback must be registered to the application
  ```python
  app.object_perms("stuff", stuff_permissions)
  ```
  Registering can also be done with `object_perms` used as a decorator or
  through the `FSA_OBJECT_PERMS` directive.
- a function must require these permission by setting `authorize` to a tuple,
  with the domain, the name of the variable which identifies the object, and
  the role.
  ```python
  @app.patch("/stuff/<id>", authorize=("stuff", "id", "update")
  def patch_stuff_id(id: int, ...):
      return ...
  ```
  Convenient defaults are provided: the first parameter for the identifier,
  *None* for the role.

### How-to use oauth authorizations?

### How-to ?

## Parameters

### How-to use pydantic or dataclasses in requests and responses?

### How-to ?

## Miscellaneous

### How-to allow non-TLS connections?

The default configuration emphasizes security, so non TLS connections are
rejected, unless running on *localhost* for tests.
To allow non-TLS connections, set `FSA_SECURE = False`.

### How-to use a shared REDIS cache?

FlaskSimpleAuth uses [`redis`](https://pypi.org/project/redis/) to deal with redis.

- if necessary, install the module: `pip install redis`
- set `FSA_CACHE = "redis"`
- set `FSA_CACHE_OPTS` so that the application can connect to the cache, eg:
  ```python
  FSA_CACHE_OPTS = { "host": "my.redis.server", "port": 6379 }
  ```
- if the service is shared, set `FSA_CACHE_PREFIX` to the application name to
  avoid cache entry collisions:
  ```python
  FSA_CACHE_PREFIX = "acme."
  ```
