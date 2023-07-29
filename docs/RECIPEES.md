# FlaskSimpleAuth Recipees

Here are a few task-oriented recipees with
[FlaskSimpleAuth](https://pypi.org/project/flasksimpleauth/).

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

## Authorization

### How-to ?

## Parameters

### How-to ?
