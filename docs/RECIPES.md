# FlaskSimpleAuth Recipes

Here are a few task-oriented recipes with
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
  a `authn="basic"` parameter.
- register a `get_user_pass` hook.
- simple authentication routes are triggered with `authz="AUTH"`

### How-to configure parameter authentication?

This is login and password authentication passed as HTTP or JSON parameters.

- set `FSA_AUTH` to `param` or to contain `param`, or have a route with
  a `authn="param"` parameter.
- the name of the expected two parameters are set with `FSA_PARAM_USER` and
  `FSA_PARAM_PASS`.
- register a `get_user_pass` hook.
- simple authentication routes are triggered with `authz="AUTH"`

### How-to configure token authentication?

It is enabled by default if `FSA_MODE` is a scalar.
It can be enabled explicitely with `FSA_MODE` as a list which
contains `token`.

If you do not really need [JWT](https://jwt.io/) compatibility, keep the
default `fsa` token type (`FSA_TOKEN_TYPE`) which is human readable, unlike JWT.

### How to disable token authentication?

- set `FSA_AUTH` to the list of authentication schemes, which must
  *not* contain `token`.
- set `FSA_TOKEN_TYPE` to `None`.

### How-to get the current user login as a string?

There are several equivalent options:

- use a special `CurrentUser` parameter type on a route to retrieve the user name.
- call `app.current_user()` on an authenticated route.
- call `app.get_user()` on any route, an authentification will be attempted.

### How-to get the current user as an object?

You must build the object yourself, based on the string user name.

- with a function of your making associated to the target type:

  ```python
  @app.special_parameter(UserObject)
  def get_user_object(_: str, user: CurrentUser) -> UserObject:
      return UserObject(login=user)
  ```

- the simply associate the type to a route parameter:

  ```python
  @app.route("/...", authz="AUTH")
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

You need to create a callback to handle your scheme:

- create a function which returns the login based on the app and request:

  ```python
  def xyz_authentication(app, req):
      # investigate the request and return the login or None for 401
      # possibly raise an ErrorResponse with fsa.err(…)
      return ...
  ```

- register this callback as an authentication scheme:

  ```python
  app.authentication("xyz", xyz_authentication)
  ```

- use this new authentication method in `FSA_AUTH` or maybe on some route with
  an `authn="xyz"` parameter.

### How-to test authentication and authorizations without any password?

Use `FSA_AUTH="fake"` and pass the expected login as a request parameter
(`FSA_FAKE_LOGIN`, defaults to `LOGIN`).

Fake authentication is **only** allowed for *localhost* connections and cannot
be deployed on a real server.

### How-to use LDAP/AD authentication?

The AD password checking model is pretty strange, as it requires to send the
clear password to the authentication server to check whether it is accepted.
To do that at the library level:

- create a new password checking function:

  ```python
  def check_login_password_with_AD_server(login: str, password: str) -> bool|None:
      import ldap
      # connect to server... send login/pass... look for result...
      return ...
  ```

  - on `True`: the password is accepted
  - on `False`: it is not
  - on `None`: 401 (no such user)
  - if unhappy: raise an `ErrorResponse` exception with `fsa.err(...)`
- register this hook

  ```python
  app.password_check(check_login_password_with_AD_server)
  ```

- you do not need to have a `get_user_pass` hook if this is the sole password
  scheme used by your application.

Alternatively, this could be implemented at the application level with one
route which checks the credentials and provides a token which will be used
afterwards:

- create the token route:

  ```python
  # this route is open in the sense that it takes charge of checking credentials
  @app.post("/token-ad", authz="OPEN", authn="none")
  def get_token_ad(username: str, password: str):
      if not check_login_password_with_AD_server(username, password):
          fsa.err("invalid AD credentials", 401)
      return {"token": app.create_token(username)}, 201
  ```

- use `FSA_AUTH_DEFAULT="token"` so that all other routes require the token.

### How-to use multi-factor authentication (MFA)?

The idea is to rely on an intermediate *token* with a temporary *realm* to validate
that an authenfication method has succeeded, and that another must still be checked.
Here is a _simplistic_ outline:

- create a route with the *first* authentication method, eg a login/password
  basic authentication.

  ```python
  @app.get("/login", authz="AUTH", authn="basic")
  def get_login(user: fsa.CurrentUser):
      # trigger sending an email or SMS for a code
      generate_and_send_temporary_code_to_user(user)
      # return a 10 minutes token
      return app.create_token(user, realm="app-mfa", delay=10.0), 200
  ```

- create a route protected by the previous token, and check the email or SMS
  code provided by the user at this stage.

  ```python
  @app.post("/code", authz="AUTH", authn="token", realm="app-mfa")
  def post_code(user: fsa.CurrentUser, code: str):
      if not check_code_validity(user, code):
          return "invalid validation code", 401
      # TODO invalidate code to thwart replay attacks
      # else return the final token
      return app.create_token(user), 200
  ```

- only allow token authentication on other routes, eg with
  `FSA_AUTH_DEFAULT = "token"`.

See [MFA demo](https://github.com/zx80/flask-simple-auth/blob/main/demo/mfa.py)
with both random temporary codes and time-based OTP.

Beware that the security of MFA schemes requires additional configurations
against replay or enumeration attacks.

### How to ensure that no route is without authentication?

With belt and suspenders:

- do not use `authz="OPEN"` on _any_ route.
- use an explicit `FSA_AUTH` list setting **without** `none`.
- use `FSA_AUTH_DEFAULT="token"`.

### How-to ... authentication?

## Authorization

For details, see the relevant
[authorization](https://zx80.github.io/flask-simple-auth/DOCUMENTATION.html#authorization)
section in the documentation.

### How-to (temporarily) close a route?

Use `authz="CLOSE"` as a route parameter to trigger a 403 forbidden response.

This can be added in a list of authorizations (`authz=[…, "CLOSE"]`)
and will supersede all other settings for this route.

### How-to open a route?

Use `authz="OPEN"` as a route parameter, **and** allow authentication `none`
by adding it to `FSA_AUTH`.
Depending on `FSA_AUTH_DEFAULT`, you may have to add `authn="none"` on the route
so that this (non) authentication is allowed.
Anyone can execute such routes, without authentication.

### How-to just authenticate a route?

Use `authz="AUTH"` as a route parameter.
All authenticated users can execute the route.

### How-to use simple group authorizations?

Group authorizations are permissions based on belonging to a group.
For that, you must:

- create a callback to check whether a user belongs to a group:

  ```python
  def user_is_admin(login: str) -> bool:
      return ... # whether user belong to the admin group
  ```

- register this callback as a `group_check` hook:

  ```python
  app.group_check("admin", user_is_admin)
  ```

- declare that the group authorization is required on a route definition:

  ```python
  @app.route("/admin", authz="admin")
  def ...
  ```

### How-to factor-out all group authorizations?

Use the generic `user_in_group` hook instead of per-group checks.

### How-to use object authorizations?

In most application, access permissions depend on some kind of relationship to
the data, e.g. someone may read a message because they are either the recipient
or the sender of this particular message.

- object authorizations require a per-domain callback which tells whether an
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
- a function must require these permission by setting `authz` to a tuple,
  with the domain, the name of the variable which identifies the object, and
  the role.

  ```python
  @app.patch("/stuff/<id>", authz=("stuff", "id", "update"))
  def patch_stuff_id(id: int, ...):
      return ...
  ```

  Convenient defaults are provided: the first parameter for the identifier,
  *None* for the role.

### How-to use oauth authorizations?

### How-to ... authorizations?

## Parameters

### How-to use pydantic or dataclasses in requests and responses?

Pydantic and dataclass classes are well integrated both for input parameters
and route outputs:

- request parameters work out of the box with through JSON:

  ```python
  import pydantic

  # this also works with pydantic and standard dataclasses
  class User(pydantic.BaseModel):
      login: str
      firstname: str
      lastname: str

  @app.post("/users", authz="ADMIN")
  def post_users(user: User):
      # user.login, user.firtname, user.lastname…
      return "", 201
  ```

- responses must be processed through FlaskSimpleAuth's `jsonify`:

  ```python
  @app.get("/users/<uid>", authz="ADMIN")
  def get_users_uid(uid: int):
      user: User = whatever(uid)
      return fsa.jsonify(user), 200
  ```

See [types demo](https://github.com/zx80/flask-simple-auth/blob/main/demo/types_path.py).

### How-to use generic types in requests and responses?

Just use them! They are converted from/to JSON, but for `list[*]` with HTTP
parameters are expected to be repeated parameters.

```python
@app.get("/generic", authz="OPEN")
def get_generic(data: dict[str, list[int]]):
    # data["foo"][0]
    return {k: len(v) for k, v in data.items()}
```

The generic type support is not perfect, consider using data classes instead.
Simple standard types are expected, they cannot be mixed with data classes in
general, although some instances may work.

### How-to ... parameters?

## Miscellaneous

### How-to allow non-TLS connections?

The default configuration emphasizes security, so non TLS connections are
rejected, unless running on *localhost* for tests.
To allow non-TLS connections, set `FSA_SECURE = False` and feel deeply ashamed
to have done that.

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

### How-to get an anwer?

Submit your question [here](https://github.com/zx80/flask-simple-auth/issues)!

### How-to contribute?

Implement a feature, improve the code, fix a bug… and submit a pull request.
