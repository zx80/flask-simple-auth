# Flask Simple Auth Module Documentation

This modules helps handling
[authentication](#authentication),
[authorization](#authorization),
[parameters](#parameters) and provide other
[utils](#utils) for [Flask](https://flask.palletsprojects.com/), controled from
Flask configuration and the extended `route` decorator.
It is designed to help REST application back-end development.

## Examples and Features

A simple [example](README.md#example) is available on the main page.
[Features](README.md#features) are also described there.
Look out for the [demo](demo/) application for more fully working examples.

## Install

Use `pip install FlaskSimpleAuth` to install the module, or whatever
other installation method you prefer.
Depending on options, the following modules should be installed:

- [passlib](https://pypi.org/project/passlib/) for password management.
- [cachetools](https://pypi.org/project/cachetools/) and
  [CacheToolsUtils](https://pypi.org/project/cachetoolsutils/) for caching.
- [ProxyPatternPool](https://pypi.org/project/ProxyPatternPool/) for sharing.
- [bcrypt](https://pypi.org/project/bcrypt/)  for password hashing (default algorithm).
- [PyJWT](https://pypi.org/project/PyJWT/) for JSON Web Token (JWT).
- [cryptography](https://pypi.org/project/cryptography/) for pubkey-signed JWT.
- [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth)
  for `http-*` authentication options.
- [Flask CORS](https://github.com/corydolphin/flask-cors) for CORS handling.

## Initialization

The module is simply initialize by calling its `Flask` constructor and providing
a configuration through `FSA_*` directives (from a separate file or directly
in the constructor).

```python
import FlaskSimpleAuth as fsa
app = fsa.Flask("acme", FSA_MODE="debug")
app.config.from_envvar("ACME_CONFIG")
```

Once initialized, `app` behaves as a standard Flask object with many additions.
The main change is the `route` decorator, an extended version of Flask's own
with an `authorize` parameter and transparent management of request parameters.
Per-method shortcut decorators `post`, `get`, `put`, `patch` and `delete`
which support the same extensions.
The security first principle means that if the parameter is missing the route
is closed with a *403*.

```python
@app.get("/store", authorize="ANY")
def get_store(filter: str = None):
    # return store contents, possibly filtered
    …

@app.post("/store", authorize="contributer")
def post_store(data: str):
    # append new data to store, return id
    …

@app.get("/store/<id>", authorize="ANY")
def get_store_id(id: int):
    # return data corresponding to id
    …
```

Inside a request handling function, additional methods on `app` give access to
authentication-dependent data, for instance:
- `get_user` extracts the authenticated user or raise an exception,
  and `current_user` gets the authenticated user if any, or `None`.
  It can also be requested as a parameter with the `CurrentUser` type.
- `user_scope` checks if the current token-authenticated user has some
  authorizations.
- `hash_password` and `check_password` hash or check a password.
- `create_token` computes a new authentication token for the current user.

Various decorators/functions allow to register hooks, such as:

- `user_in_group`, `get_user_pass` and `object_perms` functions/decorators to
  register authentication and authorization helper functions:
  - a function to retrieve the password hash from the user name.
  - a function which tells whether a user is in a group or role.
  - functions which define object ownership and access permissions.
- `password_quality` a function/decorator to register a function to check for
  password quality.
- `password_check` a function/decorator to register a new password checker,
  so as to handle recovery codes, for instance.
- `cast` a function/decorator to register new str-to-some-type casts for
  function parameters.
- `special_parameter` a function/decorator to register new special parameter
  types.
- `error_response` a function/decorator to register a new response generator
  when handling errors.

```python
# return password hash if any (see with FSA_GET_USER_PASS)
# None means that the user does not exists
@app.get_user_pass
def get_user_pass(user: str) -> Optional[str]:
    return …

# return whether user is in group (see with FSA_USER_IN_GROUP)
@app.user_in_group
def user_in_group(user: str, group: str) -> bool:
    return …

# return whether user can access the `foo` object for an operation
# None will generates a 404
@app.object_perms("foo")
def allow_foo_access(user: str, fooid: int, mode: str) -> Optional[bool]:
    return …
```

These hooks allow taking over control of most internal processes, if needed.

## Authentication

The main authentication configuration directive is `FSA_AUTH` which governs the
authentication methods used by the `get_user` function, as described in the
following sections. Defaut is `httpd`.

If a non-token scheme is provided, authentication will be `token`
followed by the provided scheme, i.e. `token` is tried first anyway if
enabled.

To take full control of authentication schemes, provide an ordered list.
Note that it does not always make much sense to mix some schemes, e.g.
*basic* and *digest* password storage assumptions are distinct and should
not be merged.  Also, only one HTTPAuth-based scheme can be active at a time.

Authentication is *always* performed on demand, either to check for a route
authorization declared with `authorize` or when calling `get_user`.

The authentication scheme attempted on a route can be altered with the `auth`
parameter added to the `route` decorator.
This may be used to restrict the authentication scheme to a *subset* if those
configured globally, and may or may not work otherwise depending on module
internals, so this is only for special cases.
A legitimate use for a REST API is to have `FSA_AUTH` defined to *token* and have
only one *basic* route to obtain the token used by other routes.

### Authentication Schemes

The available authentication schemes are:

- `none`

  Deactivate authentication.

- `httpd`

  Inherit web server supplied authentication through `request.remote_user`.
  This is the default.

  There are plenty authentication schemes available in a web server such as
  [Apache](https://httpd.apache.org/) or [Nginx](https://nginx.org/), including
  LDAP or other databases, all of which probably more efficiently implemented
  than python code, so it should be the preferred option.
  However, it could require significant configuration effort compared to the
  application-side approach.

- `basic`

  HTTP Basic password authentication, which rely on the `Authorization`
  HTTP header in the request.

  - `FSA_REALM` provides the authentication realm.

  See also [Password Management](#password-management) below for
  how the password is retrieved and checked.

- `http-basic`

  Same as previous based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).

  - `FSA_REALM` provides the authentication realm.
  - `FSA_HTTP_AUTH_OPTS` allow to pass additional options to the
    HTTPAuth authentication class.

- `param`

  HTTP or JSON parameter for password authentication.
  User name and password are passed as request parameters.

  - `FSA_PARAM_USER` is the parameter used for the user name.
    Default is `USER`.
  - `FSA_PARAM_PASS` is the parameter used for the password.
    Default is `PASS`.

  See also [Password Management](#password-management) below for
  the password is retrieved and checked.

- `password`

  Tries `basic` then `param` authentication.

- `http-digest` or `digest`

  HTTP Digest authentication based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).

  Note that the implementation relies on *sessions*, which may require the
  `SECRET_KEY` option to be set to something.
  The documentation states that server-side sessions are needed because
  otherwise the *nonce* and *opaque* parameters could be reused, which
  may be a security issue under some conditions. I'm unsure about that,
  but I agree that client-side cookie sessions are strange things best
  avoided if possible.

  - `FSA_REALM` provides the authentication realm.
  - `FSA_HTTP_AUTH_OPTS` allow to pass additional options to the
    HTTPAuth authentication class, such as `use_ha1_pw`, as a dictionary.

  See also [Password Management](#password-management) below for
  how the password is retrieved and checked. Note that password management
  is different for digest authentication because the simple hash of the
  password or the password itself is needed for the verification.

- `token`

  Only rely on signed tokens for authentication.
  A token certifies that a *user* is authenticated in a *realm* up to some
  time *limit*.
  The token is authenticated by a signature which is usually the hash of the
  payload (*realm*, *user* and *limit*) and a secret hold by the server.

  There are two token types chosen with the `FSA_TOKEN_TYPE` configuration
  directive: `fsa` is a simple compact readable custom format, and `jwt`
  [RFC 7519](https://tools.ietf.org/html/rfc7519) standard based
  on [PyJWT](https://pypi.org/project/PyJWT/) implementation.

  The `fsa` token syntax is: `<realm>:<user>:<limit>:<signature>`,
  for instance: `comics:calvin:20380119031407:4ee89cd4cc7afe0a86b26bdce6d11126`.
  The time limit is a simple UTC timestamp *YYYYMMDDHHmmSS* that
  can be checked easily by the application client.
  Compared to `jwt` tokens, they are short and easy to interpret and compare
  manually, no decoding is involved.
  If an issuer is set (see `FSA_TOKEN_ISSUER` below), the name is appended to
  the realm after a `/`.

  The following configuration directives are available:

  - `FSA_TOKEN_TYPE` type of token, either *fsa*, *jwt* or `None` to disable.
    Default is *fsa*.
  - `FSA_TOKEN_CARRIER` how to transport the token: *bearer* (`Authorization`
    HTTP header), *param*, *cookie* or *header*.
    Default is *bearer*.
  - `FSA_TOKEN_NAME` name of parameter or cookie holding the token, or
    bearer scheme, or header name.
    Default is `AUTH` for *param* carrier, `auth` for *cookie* carrier,
    `Bearer` for HTTP Authorization header (*bearer* carrier),
    `Auth` for *header* carrier.
  - `FSA_REALM` realm of authentication for token, basic or digest.
    Default is the simplified lower case application name.
    For *jwt*, this is translated as the audience.
  - `FSA_TOKEN_ISSUER` the issuer of the token.
    Default is *None*.
  - `FSA_TOKEN_SECRET` secret string used for validating tokens.
    Default is a system-generated random string containing 256 bits.
    This default will only work with itself, as it is not shared
    across server instances or processes.
  - `FSA_TOKEN_SIGN` secret string used for signing tokens, if
    different from previous secret. This is only relevant for public-key
    *jwt* schemes (`R…`, `E…`, `P…`).
    Default is to use the previous secret.
  - `FSA_TOKEN_DELAY` number of minutes of token validity.
    Default is *60.0* minutes.
  - `FSA_TOKEN_GRACE` number of minutes of grace time for token validity.
    Default is *0.0* minutes.
  - `FSA_TOKEN_ALGO` algorithm used to sign the token.
    Default is `blake2s` for `fsa` and `HS256` for *jwt*.
  - `FSA_TOKEN_LENGTH` number of hash bytes kept for token signature.
    Default is *16* for `fsa`. The directive is ignored for `jwt`.
  - `FSA_TOKEN_RENEWAL` for cookie tokens, the fraction of delay under
    which the cookie/token is renewed automatically.
    Default is *0.0*, meaning no renewal.

  Function `create_token(user)` creates a token for the user depending
  on the current scheme. If `user` is not given, the current user is taken.

  Token authentication is always attempted unless the secret is empty.
  Setting `FSA_AUTH` to `token` results in *only* token authentication to be used.

  Token authentication is usually much faster than password verification because
  password checks are designed to be slow so as to hinder password cracking,
  whereas token authentication relies on simple hashing for its security.
  Another benefit of token is that it avoids sending passwords over and over.
  The rational option is to use a password scheme to retrieve a token and then to
  use it till it expires. This can be enforced by setting `FSA_AUTH` to `token`
  and to only add `auth="basic"` on the login route used to retrieve a token.

  Token expiration can be understood as a kind of automatic logout, which suggests
  to choose the delay with some care depending on the use case.

  Internally token checks are cached so that even with slow JWT public-key schemes
  the performance impact should be low.

- `oauth`

  Synonymous to `token`, but to be used on a route so as to trigger JWT *scope*
  authorizations on that route.

  See also [OAuth Authorizations](#oauth-authorizations) below for how to use
  JWT token scopes.

- `http-token`

  Token scheme based on [flask-HTTPAuth](https://pypi.org/project/Flask-HTTPAuth/).
  Carrier is *bearer* or *header*.

  - `FSA_HTTP_AUTH_OPTS` passes additional options to the HTTPAuth
    authentication class, such as `header`, as a dictionary.

- `fake`

  Trust a parameter for authentication claims.
  Only for local tests, obviously.
  This is enforced.

  - `FSA_FAKE_LOGIN` is the parameter holding the user name.
    Default is `LOGIN`.

### Password Management

Password authentication is performed for the following authentication schemes:
`param`, `basic`, `http-basic`, `http-digest`, `digest`, `password`.

The provided password management comprises handling password verification
in the application, relying on standard password hashing schemes and
a user-provided function to retrieve the password hash (`get_user_pass`),
and/or delegating the whole verification process to a user-provided function
(`password_check`).

For checking passwords internally, the password (salted hash) must be retrieved
through `get_user_pass(user)`.
This function must be provided when the module is initialized.
Because this function is cached by default, the cache expiration must be reached
so that changes take effect, or the cache must be cleared manually, which may
impair application performance.

The following configuration directives are available to configure `passlib`
password checks:

- `FSA_PASSWORD_SCHEME` password scheme to use for passwords.
  Default is `bcrypt`.
  See [passlib documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html)
  for available options, including the bad *plaintext*.
  Set to `None` to disable internal password checking.
- `FSA_PASSWORD_OPTS` relevant options (for `passlib.CryptContext`).
  Default is `{'bcrypt__default_rounds': 4, 'bcrypt__default_ident': '2y'}`.

Beware that modern password checking is often pretty expensive in order to
thwart password cracking if the hashed passwords are leaked, so that you
do not want to have to use that on every request in real life (eg *hundreds*
milliseconds for passlib bcrypt *12* rounds).
The above defaults result in manageable password checks of a few milliseconds.
Consider using tokens to reduce the authentication load on each request.

For `digest` authentication, the password must be either in *plaintext* or a
simple MD5 hash ([RFC 2617](https://www.rfc-editor.org/rfc/rfc2617.txt)).
The authentication setup must be consistent (set `use_ha1_pw` as *True* for the
later).
As retrieving the stored information is enough to steal the password (plaintext)
or at least impersonate a user (hash), consider avoiding `digest` altogether.
HTTP Digest Authentication only makes sense for unencrypted connexions, which
is bad practice anyway. It is just provided here for completeness.

Function `hash_password(pass)` computes the password salted digest compatible
with the current configuration, and may be used by the application for setting
or resetting passwords.

This function checks the password quality by relying on:
- `FSA_PASSWORD_LEN` minimal password length, *0* to disable.
- `FSA_PASSWORD_RE` list of regular expressions that a password must match.
- `FSA_PASSWORD_QUALITY` hook function which returns whether the password is
  acceptable, possibly raising an exception to complain if not.
  This hook can also be filled with the `password_quality` method/decorator.
  It allows to plug a password strength estimator such as
  [zxcvbn](https://github.com/dropbox/zxcvbn).

This application-managed standard password checking can be overridden by
providing an alternate password checking function with a directive:
- `FSA_PASSWORD_CHECK` hook function which returns whether user and password
  provided is acceptable.
This allows to plug a LDAP server or a temporary password recovery scheme or
other one-time or limited-time passwords sent by SMS or mail, for instance.
This hook can also be filled with the `password_check` method/decorator.
This alternate check is used if the primary check failed or is disactivated.

An opened route for user registration with mandatory parameters
could look like that:

```python
@app.post("/register", authorize="ANY")
def post_register(user: str, password: str):
    if user_already_exists(user):
        return f"cannot create {user}", 409
    add_new_user_with_hashed_pass(user, app.hash_password(password))
    return "", 201
```

Because password checks are usually expensive, it is advisable to switch
to `token` authentication. A token can be created on a path authenticated
by a password method:

```python
# token creation route for all registered users
@app.get("/login", authorize="ALL")
def get_login():
    return jsonify(app.create_token()), 200
```

The client application will return the token as a parameter or in
headers for authenticating later requests, till it expires.

## Authorization

Authorizations are declared with the `authorize` parameter to
the `route` decorator or its per-method shortcuts.
The modules supports three permission models:

- a group-oriented model
- a scope OAuth model
- an object-oriented model

The parameter accepts a list of `str` and `int` for groups or scopes, and of
`tuple` for object permissions.  If a scalar is provided, it is assumed
to be equivalent to a list of one element.

When multiple authorizations are required through a list, they are cumulative,
that is *all* conditions must be met.

### Group Authorizations

A group or role is identified as an integer or a string.
The `user_in_group(user, group)` function is called to check whether the
authenticated user belongs to a given group.
Because this function is cached by default, the cache expiration must
be reached so that changes take effect, or the cache must be cleared
manually, which may impair application performance.

```python
@app.get("/admin-only", authorize="ADMIN")
def get_admin_only():
    # only authenticated "ADMIN" users can get here!
```

There are three special values that can be passed to the `authorize` decorator:

- `ANY` declares that no authentication is needed on that route,
  i.e. *any*one can get in.
- `ALL` declares that all authenticated user can access this route,
  without group checks.
- `NONE` returns a *403* on all access. It can be used to close a route
  temporarily. This is the default.

```python
@app.get("/closed", authorize="NONE")
def get_closed():
    # nobody can get here

@app.get("/authenticated", authorize="ALL")
def get_authenticated():
    # ALL authenticated users can get here

@app.get("/opened", authorize="ANY")
def get_opened():
    # ANYone can get here, no authentication is required
```

Note that this simplistic model does is not enough for non-trivial applications,
where permissions on objects often depend on the object owner.
For those, careful per-object and per-operation authorization are needed.

Groups *can* be registered with `add_group` or with `FSA_AUTHZ_GROUPS`.
If done so, unregistered groups are rejected and result in a configuration error:

```python
app.add_group("student", "professor")

@app.get("/students", authorize="admin")  # ERROR, unregistered group
def get_students():
    …
```

### OAuth Authorizations

OAuth authorizations are similar to group authorizations.
They are attached to the current authentification performed through a token,
on routes explicitely marked with `auth="oauth"`.
In that case, the `authorize` values are interpreted as *scopes* that must be
provided by the token.

In order to simplify security implications, *scopes* and *groups*
(`user_in_group`) authorizations cannot be mixed on a route:
create distinct routes to handle these.
Another current limitation is that only one *issuer* is allowed.

```python
# /data is only accessible through a trusted JWT token with "read" scope
@app.get("/data", authorize="read", auth="oauth"):
def get_data(user: CurrentUser):
    return access_some_data(user), 200
```

Method `user_scope` allows to check whether the current user can perform
some operation. It can be used with an object authorization rule.

Method `add_scope` and directive `FSA_AUTHZ_SCOPES` allow to register valid
scopes that can be checked later. If not set, all scopes are considered valid.

The *scope* delegated authorization model suggests that the issuer is
trusted to control accesses with any possible scope.
This may or may not make sense from a security perspective depending
on the use case.
It makes perfect sense if the issuer is providing authorizations for
accesses to itself, possibly from a third party.

### Object Authorizations

Non trivial application have access permissions which depend on the data
stored by the application. For instance, a user may alter a data because
they *own* it, or access a data because they are *friends* of the owner.

In order to implement this model, the `authorize` decorator parameter can
hold `(domain, variable, mode)` tuples which designate a permission domain
(eg a table or object or concept name in the application), the name of
a variable in the request (path or HTTP or JSON parameters) which identifies
an object of the domain, and the operation or level of access necessary for
this route:

```python
@app.get("/message/<mid>", authorize=("msg", "mid", "read"))
def get_message_mid(mid: int):
    …
```

The system will check whether the current user can access message *mid*
in *read* mode by calling a per-domain user-supplied function:

```python
@app.object_perms("msg")
def can_access_message(user: str, mid: int, mode: str) -> Optional[bool]:
    # can user access message mid for operation mode?
    return …

# also: app.object_perms("msg", can_access_message)
```

If the check function returns *None*, a *404 Not Found* response is generated.
If it returns *False*, a *403 Forbidden* response is generated.
If it returns *True*, the route function is called to generate the response.

If `mode` is not supplied, *None* is passed to the check function.
If `variable` is not supplied, the *first* parameter of the route function
is taken:

```python
# same as authorize=("msg", "mid", None)
@app.patch("/message/<mid>", authorize=("msg",))
def patch_message_mid(mid: int):
    …
```

The `FSA_OBJECT_PERMS` configuration directive can be set as a dictionary
which maps domains to their access checking functions:

```python
FSA_OBJECT_PERMS = { "msg": can_access_message, "blog": can_access_blog }
```

Because these functions are cached by default, the cache expiration must
be reached so that changes take effect, or the cache must be cleared
manually, which may impair application performance.

In the context of `oauth` authorizations, the per-domain object permission
function can rely on `user_scope` to check whether some mode is allowed
by the token.

## Parameters

Request parameters (HTTP or JSON) are translated automatically to named function
parameters by relying on function type annotations.
Parameters are considered mandatory unless a default value is provided.

```python
@app.get("/something/<id>", authorize=…)
def get_something_id(id: int, when: date, what: str = "nothing"):
    # `id` is an integer path-parameter
    # `when` is a mandatory date HTTP or JSON parameter
    # `what` is an optional string HTTP or JSON parameter
    …
```

Request parameter string values are actually *converted* to the target type,
and generate a *400* if the configuration fails.
For `int`, base syntax is accepted for HTTP/JSON parameters, i.e. `0x11`,
`0o21`, `0b10001` and `17` all mean decimal *17*.
For `bool`, *False* is an empty string, `0`, `False` or `F`, otherwise
the value is *True*.
Type `path` is a special `str` type which allows to trigger accepting
any path on a route.
Type `JsonData` is a special type to convert, if necessary, a string value
to JSON, expecting a list or a dictionary.

If one parameter is a dict of keyword arguments, all remaining request
parameters are provided into it, as shown below:

```python
@app.put("/awesome", authorize="ALL")
def put_awesome(**kwargs):
    …
```

Custom classes can be used as path and HTTP parameter types, provided that
the constructor accepts a string to convert the parameter value to the
expected type.

```python
class EmailAddr:
    def __init__(self, addr: str):
        self._addr = addr

@app.get("/mail/<addr>", authorize="ALL")
def get_mail_addr(addr: EmailAddr):
    …
```

If the constructor does not match, a custom function can be provided
with the `cast` function/decorator and will be called automatically
to convert parameters:

```python
class House:
    …

@app.cast(House)
def strToHouse(s: str) -> House:
    return …

# or: app.cast(House, strToHouse)

@app.get("/house/<h>", authorize="ANY")
def get_house_h(h: House)
    …
```

The `FSA_CAST` directive can also be defined as a dictionary mapping
types to their conversion functions:

```python
FSA_CAST = { House: strToHouse, … }
```

As a special case, the `Request`, `Session`, `Globals`, `Environ`,
`CurrentApp` and `CurrentUser` types, when used for parameters, result in the
`request`, `session`, `g` flask special objects, `environ` WSGI parameter and
the current authenticated user or the current application to be passed as this
parameter to the function, allowing to keep a functional programming style by
hidding away these special proxies.

More special parameters can be added with the `special_parameter` app
function/decorator, by providing a type and a function which returns the
expected value. For instance, the `Request` definition corresponds to:

```python
app.special_parameter(Request, lambda: request)
```

The `FSA_SPECIAL_PARAMETER` directive can also be defined as a dictionary
mapping types to their parameter value function.

Python parameter names can be prepended with a `_`, which is ignored when
translating HTTP parameters.  This allows to use python keywords as parameter
names, such as `pass` or `def`.

```python
@app.put("/user/<pass>", authorize="ALL")
def put_user_pass(_pass: str, _def: str, _import: str):
    …
```

Finally, configuration directive `FSA_REJECT_UNEXPECTED_PARAM` tells whether to
reject requests with unexpected parameters.
Default is *True*.

## Utils

Utilities include the `Reference` generic object wrapper class,
an `ErrorResponse` class to quickly generate error replies and
miscellaneous configuration directives which cover security,
caching and CORS.

### `Reference` Object Wrapper

This class provides a proxy object based on the `Proxy` class
from [ProxyPatternPool](https://pypi.org/project/proxypatternpool/).

This class implements a generic share-able global variable which can be
used by modules (eg app, blueprints…) with its initialization differed.

Under the hood, most methods calls are forwarded to a possibly sub-thread-local
object stored inside the wrapper, so that the Reference object mostly
behaves like the wrapped object itself.

See the module for a detailed documentation.

### `ErrorResponse` class

Raising this exception with a message and status from any user-defined function
generates a `Response` of this status with the text message as contents. 

### Miscellaneous Configuration Directives

Some directives govern various details for this extension internal working.

- `FSA_MODE` set module mode, expecting *prod*, *dev* or *debug*.
  This changes the module verbosity.
  Under *dev*, a `FSA-Delay` header is added to show the elapsed time from
  the application code perspective.
  Default is *prod*.

- `FSA_LOGGING_LEVEL` adjust module internal logging level.
  Default is *None*.

- `FSA_SECURE` only allows secured requests on non-local connections.
  Default is *True*.

- `FSA_SERVER_ERROR` controls the status code returned on the module internal
  errors, to help distinguish these from other internal errors which may occur.
  Default is *500*.

- `FSA_NOT_FOUND_ERROR` controls the status code returned when a permission
  checks returns *None*.
  Default is *404*.

- `FSA_LOCAL` sets the internal object isolation level.
  It must be consistent with the module WSGI usage.
  Possible values are *process*, *thread* (several threads can be used by the
  WSGI server) and *werkzeug* (should work with sub-thread level request
  handling, eg greenlets).
  Default is *thread*.

- `FSA_ERROR_RESPONSE` sets the handler for generating responses on errors.
  Text values  *plain* or *json* generate simple `text/plain` or
  `application/json` responses.
  Using *json:error* generates a JSON dictionary with key *error* holding
  the error message.
  The response generation can be fully overriden by providing a callable
  which expects the error message and status code as parameters.
  This handler can be restricted to apply only to FSA-generated errors,
  see `FSA_HANDLE_ALL_ERRORS` below.
  Default is *plain*.

- `FSA_HANDLE_ALL_ERRORS` whether to handle all *4xx* and *5xx* errors,
  i.e. take responsability for generating error responses using FSA
  internal error handler.
  Default is *True*.

- `FSA_ADD_HEADERS` allows to add headers to the generated response,
  as a dictionary.
  Keys are header names and values are either strings, which are used as is,
  or functions which are called with the response as a parameter to generate
  a value. *None* returned values are silently ignored.
  The corresponding `add_headers` method allows to add headers as keyword
  arguments.
  Default is empty.

- `FSA_BEFORE_REQUEST` and `FSA_AFTER_REQUEST` allow to add a list of before
  and after request hooks from the configuration instead of the actual
  application code.
  As a slight deviation from Flask before request hook, before request functions
  are passed the current request as an argument.
  The are executed first (just after some internal initializations and before
  application-provided before request hooks) and last, respetively.
  Defaults are empty.

Some control is available about internal caching features used for user
authentication (user password access and token validations) and
authorization (group and per-object permissions):

- `FSA_CACHE` controls the type of cache to use, set to *None* to disallow
  caches. Values for standard `cachetools` cache classes are `ttl`, `lru`,
  `lfu`, `mru`, `fifo`, `rr` plus `dict`.
  MemCached is supported by setting it to `memcached`, and Redis with `redis`.
  Default is `ttl`.

- `FSA_CACHE_OPTS` sets internal cache options with a dictionary.
  This must contain the expected connection parameters for `pymemcache.Client`
  and for `redis.Redis` redis, for instance.
  For `redis` and `ttl`, an expiration ttl of 10 minutes is used and can be
  overwritten by providing the `ttl` parameter.

- `FSA_CACHE_SIZE` controls size of internal `cachetools` caches.
  Default is *262144*, which should use a few MiB.
  *None* means unbounded, more or less.

- `FSA_CACHE_PREFIX` use this application-level prefix, useful for shared
  distributed caches.  A good candidate could be `app.name + "."`.
  Default is *None*, meaning no prefix.

- Method `clear_caches` allows to clear internal process caches.
  This is a mostly a bad idea, you should wait for the `ttl`.

Web-application oriented features:

- `FSA_401_REDIRECT` url to redirect to on *401*.
  Default is *None*.
  This can be used for a web application login page.

- `FSA_URL_NAME` name of parameter for the target URL after a successful login.
  Default is `URL` if redirect is activated, else *None*.
  Currently, the login page should use this parameter to redirect to when ok.

- `FSA_CORS` and `FSA_CORS_OPTS` control CORS (Cross Origin Resource Sharing) settings.

  [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) is a
  security feature implemented by web browsers to prevent JavaScript injection.
  It checks whether a server accepts requests from a given origin (*i.e.* from
  JavaScript code provided by some domain).

  CORS request handling is enabled by setting `FSA_CORS` to *True* which
  allows requests from any origin. Default is *False*.
  Additional options are controled with `FSA_CORS_OPTS`.
  The implementation is delegated to the
  [`flask_cors`](https://pypi.org/project/Flask-Cors/) Flask extension
  which must be available if the feature is enabled.

## License

This software is *public domain*.

All software has bug, this is software, hence…
Beware that you may lose your hairs or your friends because of it.
If you like it, feel free to send a postcard to the author.

## Versions

[Sources](https://github.com/zx80/flask-simple-auth),
[documentation](https://zx80.github.io/flask-simple-auth/) and
[issues](https://github.com/zx80/flask-simple-auth/issues)
are hosted on [GitHub](https://github.com).
Install [package](https://pypi.org/project/FlaskSimpleAuth/) from
[PyPI](https://pypi.org/).

See [all versions](VERSIONS.md).

## See Also

[Flask-Security](https://github.com/Flask-Middleware/flask-security/) is a
feature-full web-oriented authentication and authorization framework based on
an ORM.
By contrast, *Flask Simple Auth*:
- does NOT assume any ORM or impose a data model,
  you only have to provide callback functions to access the needed data
  (password, groups, object permissions…).
- does NOT do any web-related tasks (forms, views, templates, blueprint,
  translation…), it just helps providing declarative security layer (role or
  object permissions) to an HTTP API, well integrated into Flask by
  extending the existing `route` decorator.
- does provide a nice integrated parameter management to Flask,
  including conversions and type checks, detecting missing parameters…
- does care about performance by providing an automatic and relevant caching
  mechanism to expensive authentication and authorization checks, including
  relying on external stores such as *redis*.
- provides simple hooks to extend features, such as adding a
  password strength checker or a password alternate verifier.
- is much smaller (about 1/10th, ignoring dependencies), so probably it does
  less things!

[Flask-RESTful](https://github.com/flask-restful/flask-restful) is a
Flask extension designed to ease developping a REST API by associating
classes to routes, with class methods to handle each HTTP method.
By contrast, *Flask Simple Auth*:
- does NOT propose/impose a method/class for each route.
- does provide a simpler parameter management scheme.
- integrates cleanly authentification and authorizations,
  including handling *404* transparently.
Our [implementation](demo/todos-fsa.py) of the doc [example](demo/todos-frf.py)
is shorter (32 vs 40 cloc), elegant and featureful.

[Flask-AppBuilder](https://github.com/dpgaspar/Flask-AppBuilder) is
yet another Flask web-application framework on top of Flask and
SQLAlchemy.
By contrast, *Flask Simple Auth*:
- does NOT impose an ORM or database model.
- keeps close to Flask look and feel by simply extending the `route`
  decorator, instead of adding a handful of function-specific ones,
  which is error-prone as some may be forgotten.
- has a simpler and direct yet more powerful parameter management
  framework based on type declarations instead of additional decorators
  and specially formatted comments.
- offers an integrated authorization scheme linked to application objects.

## TODO

- `FSA_PARAM_STYLE` *any/http/json* to restrict/force parameters?
- test `FSA_HTTP_AUTH_OPTS`?
- add `any` token scheme?
- add app.log?
- on-demand supplied user data?
  `get\_identity(user: str) -> Any` which is to be cached
  registered with `app.identity(get_identity)`
  then `id = app.get_identity(user: str = app.get_user())`
  does it really need to be inside `FlaskSimpleAuth`?
  possibly the id can be passed to perm hooks instead of the login?
  can be managed there as well?
- demo LDAP auth? One class plus a new `check_password`?
- `authlib`?
- reduce sloc?
- password re could use a dict for providing an explanation?
- coverage should include demo run?
- refactor password manager in a separate class?
- how to have several issuers and their signatures schemes?
- add `issuer` route parameter?
- add a `pyproject.toml`?
- check for more directive types (dynamically)?
- local should depend on `traitlets`?
- check with bad char in parameter names
- add more examples in the documentation
- authz/authn instead of authorize/auth?
- should avoid generating html output on some errors (eg 405)
