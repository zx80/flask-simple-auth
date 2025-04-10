# FlaskSimpleAuth Documentation

This modules helps handling *authentication*, *authorizations*, *parameters* and
provide other *utils* for [Flask](https://flask.palletsprojects.com/), controled
from Flask configuration and the extended `route` decorator.

## Contents

- [Motivation](#motivation),
  [Installation](#install) and
  [Initialization](#initialization).
- [Authentication](#authentication)
  - [Schemes](#authentication-schemes) (*basic*, *param*, *token*…)
  - [Password Management](#password-management).
- [Authorizations](#authorization)
  - [Groups](#group-authorizations)
  - [OAuth](#oauth-authorizations)
  - [Objects](#object-authorizations)
- [Parameters](#parameters)
  *http*, *json* and *file* parameters are managed with type hints.
- [Utils](#utils) such as
  [`Reference` wrapper](#reference-object-wrapper),
  [Error Handling](#error-handling) and
  [Miscellaneous Directives](#miscellaneous-configuration-directives).
- [See Also](#see-also)
  [Flask-Security](#flask-security),
  [Flask-RESTful](#flask-restful),
  [Flask-AppBuilder](#flask-appbuilder),
  [Flask-Login](#flask-login) and
  [others](#others).
- [License](#license), [Versions](#versions).

## Motivation

[FlaskSimpleAuth](https://github.com/zx80/flask-simple-auth/)
is designed to help an application REST API back-end development.
The features provided in this module point at fixing what I deem
Flask lack of helpfulness and wrong style, such as:
- not providing a simple and effective declarative security layer,
  which must address both authentication and authorization possibly
  in connection to application data, thus requires some kind of
  integration;
- not providing a clean way to put authentication in the configuration only,
  where it belongs, and taking into account password management best
  practices.
- not providing any real help with handling parameters, which
  is demonstrated by the fact that the user must find them
  in different dictionaries depending on where they come from,
  and having to access them through *ugly* global proxies such
  as `request`.

The resulting module allows clean application development which only has to
focus on handling routes depending on cleanly typed parameters, with
declarative security on each one, reducing both line counts and code
complexity.

An emphasis is also put on performance by providing caching where it matters,
so this is not only about style:
Many hooks are provided to be able to take full control of various
features, with reasonable defaults which make this less a necessity.
Many key features rely on proven third-party packages such as `passlib`,
`PyJWT` or `flask-cors`.

This module does not care much about web and application oriented features:
it is a Flask framework extension which aims at better handling HTTP-related
features. It could be used as a cleaner layer for other Flask
application-oriented extensions such as Flask-Security.

## Install

Use `pip install FlaskSimpleAuth` to install the module, or whatever
other installation method you prefer.
Depending on options, the following modules should be installed:

- [ProxyPatternPool](https://pypi.org/project/ProxyPatternPool/) for sharing.
- [cachetools](https://pypi.org/project/cachetools/) and
  [CacheToolsUtils](https://pypi.org/project/cachetoolsutils/) for caching.
  Possibly [pymemcache](https://pypi.org/project/pymemcache/) and
  [redis](https://pypi.org/project/redis/) for external back-ends.
- [bcrypt](https://pypi.org/project/bcrypt/) for password hashing (default algorithm),
  [argon2-cffi](https://pypi.org/project/argon2-cffi/) for password hashing,
  [pyotp](https://pyauth.github.io/pyotp/) for time-base one-time passwords,
  [passlib](https://pypi.org/project/passlib/) for other password management,
  [PyJWT](https://pypi.org/project/PyJWT/) for JSON Web Token (JWT),
  [cryptography](https://pypi.org/project/cryptography/) for pubkey-signed JWT.
- [Flask HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth)
  for `http-*` authentication options.
- [Flask CORS](https://github.com/corydolphin/flask-cors) for CORS handling.

These modules are installed with the corresponding options: `password`, `jwt`,
`memcached`, `redis`, `httpauth`, `cors`: `pip install FlaskSimpleAuth[jwt]`.

Sharing and cache-related modules are currently always installed, even if they
are unused or may be desactivated.

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
with an `authz` parameter and transparent management of request
parameters.
Per-method shortcut decorators `post`, `get`, `put`, `patch` and `delete`
which support the same extensions.
The security first principle means that if the parameter is missing the route
is closed with a *403*.

```python
@app.get("/store", authz="OPEN")
def get_store(filter: str = None):
    # return store contents, possibly filtered
    ...

@app.post("/store", authz="contributor")
def post_store(data: str):
    # append new data to store, return id
    ...

@app.get("/store/<id>", authz="OPEN")
def get_store_id(id: int):
    # return data corresponding to id
    ...
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
- `check_user_password` recheck a password for a user.

Various decorators/functions allow to register hooks, such as:

- `user_in_group`, `group_check`, `get_user_pass` and `object_perms`
  functions/decorators to register authentication and authorization helper
  functions:
  - a function to retrieve the password hash from the user name.
  - a function which tells whether a user belong to some group.
  - a function which tells whether a user is in a provided group or role.
  - functions which define object ownership and access permissions.
- `password_quality` a function/decorator to register a function to check for
  password quality.
- `password_check` a function/decorator to register a new password checker,
  so as to handle recovery codes, for instance.
- `cast` a function/decorator to register new str-to-some-type casts for
  function parameters.

```python
# return password hash if any (see with FSA_GET_USER_PASS)
# None means that the user does not exists
@app.get_user_pass
def get_user_pass(user: str) -> str|None:
    return ...

# return whether user belong to some group (see with FSA_GROUP_CHECK)
@app.group_check("admin")
def user_is_admin(user: str) -> bool:
    return ...

# or alternative catch-all dynamic approach
# return whether user is in group (see with FSA_USER_IN_GROUP)
@app.user_in_group
def user_in_group(user: str, group: str) -> bool:
    return ...

# return whether user can access the `foo` object for an operation
# None will generates a 404
@app.object_perms("foo")
def allow_foo_access(user: str, fooid: int, mode: str) -> bool|None:
    return ...
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
authorization declared with `authz` or when calling `get_user`.

The authentication scheme attempted on a route can be altered with the `authn`
parameter added to the `route` decorator.
This may be used to restrict or change the authentication scheme on a route.
Some combinations may or may not work depending on module internals, so this is
only for special cases.
A legitimate use for a REST API is to have `FSA_AUTH` defined to *token* and
have only one password-authenticated route to obtain the token used by all other
routes.

### Authentication Schemes

Authentication schemes are enabled with mandatory directive `FSA_AUTH`.
The available schemes are:

- `none`

  No authentication.
  This is **necessary** for opening routes (`authz="OPEN"`).

- `httpd`

  Inherit web server supplied authentication through `request.remote_user`.

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

  Shortcut to try `basic` then `param` authentication.

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
  password or the unhashed password itself is needed for the verification.

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
    The application realm may be overriden on a route for creating MFA stages.
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

  Function `create_token(user)` creates a valid token for the user depending
  on the current scheme and detailed configuration.
  If `user` is not given, the current user is taken.
  Other parameters can be overriden, such as `realm`, `delay`, `issuer`,
  `secret`… to allow full control if necessary, eg for MFA.

  Token authentication is always attempted unless the secret is empty.
  Setting `FSA_AUTH` to `token` results in *only* token authentication to be used.

  Token authentication is usually much faster than password verification because
  password checks are designed to be slow so as to hinder password cracking,
  whereas token authentication relies on simple hashing for its security.
  Another benefit of token is that it avoids sending passwords over and over.
  The rational option is to use a password scheme to retrieve a token and then to
  use it till it expires. This can be enforced by setting `FSA_AUTH` to `token`
  and to only add `authn="basic"` on the login route used to retrieve a token.

  Token expiration can be understood as a kind of automatic logout, which suggests
  to choose the delay with some care depending on the use case.

  Internally token checks are cached so that even with slow JWT public-key schemes
  the performance impact should be low.

  Note: it is possible to switch from an expiration model (the token tells when
  it expires) to a validity model (the token tells when it was generated) by
  setting `FSA_TOKEN_DELAY` to zero and `FSA_TOKEN_GRACE` to the amount of time
  a token should be considered valid.

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

Other authentication schemes can be added by registering a new hook early
in the application initialization. This hook:

- is passed the application and request
- returns the authenticated login as a str, or None
- may raise an `ErrorResponse` if really unhappy

```python
@app.authentication("code")
def code_authentication(app: Flask, req: Request) -> str|None:
    ...

@app.get("/code-authentication", authz="AUTH", authn="code")
def get_code_authentication(user: CurrentUser):
    return f"Hello code-authenticated {user}!", 200
```

The `FSA_AUTHENTICATION` configuration directive is a dictionary which can be
used for the same purpose.

By default, authentication is performed when required on a route by trying
all enabled schemes in turn.
This can be changed by setting `FSA_AUTH_DEFAULT` to a subset of `FSA_AUTH`,
in which case other schemes will only be tried if set explicitely on a route
with `authn=…`.

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

The following configuration directives are available to configure internal
or `passlib` password checks:

- `FSA_PASSWORD_SCHEME` password provider and scheme to use for passwords.
  There are four providers: `fsa` (internal), `passlib`, `ldap` and `ldap3`.
  The two latter are **experimental**.

  Default is `bcrypt`.
  Set to _None_ to disable internal password checking.

  The internal `fsa` provider supports `bcrypt` and `scrypt` (with a dependency
  to their eponymous package), `argon2` (with `argon2-cffi`), `otp` (time OTP),
  `plaintext` (do not use) and `a85` and `b64` obfuscated plaintext (do not use
  either).

  Further documentations:

  - [bcrypt](https://github.com/pyca/bcrypt/) for `bcrypt` options.
  - [argon2](https://argon2-cffi.readthedocs.io/en/stable/) for `argon2` options.
  - [scrypt](https://github.com/holgern/py-scrypt) for `scrypt` options,
    to which `saltlength` is added by the interface.
  - [pyotp](https://pyauth.github.io/pyotp/) for TOTP options,
  - [passlib](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html)
    for available options, including the bad *plaintext*.

  Note: a list of schemes can also be provided, in which case it is passed as-is
  to passlib.

- `FSA_PASSWORD_OPTS` relevant options depending on the underlying scheme,
  (eg `passlib.CryptContext` for provider `passlib`).
  Default is ident *2y* with *4* rounds for _bcrypt_.

Beware that modern password checking is often pretty expensive in order to
thwart password cracking if the hashed passwords are leaked, so that you
do not want to have to use that on every request in real life (eg *hundreds*
milliseconds for passlib bcrypt *12* rounds).
The above defaults result in manageable password checks of a few milliseconds.
Please consider using tokens to reduce the authentication load on each request.

Beware that time-based OTP should **never** be used as a sole authentication
but only as part of a wider MFA setup, and that it requires additional
[configuration efforts](https://datatracker.ietf.org/doc/html/rfc6238#section-5).
From this perpective, the implementation provided is simply a proof of concept.
See `demo/mfa.py` for a more realistic implementation of MFA with temporary
random codes sent to the user or time-based OTP such as on RFC6238.

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
For `plaintext` and `otp`, the function returns an unhashed password.

This function checks the password quality by relying on:
- `FSA_PASSWORD_LENGTH` minimal password length, *0* to disable.
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
@app.post("/register", authz="OPEN")
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
@app.get("/login", authz="AUTH")
def get_login():
    return jsonify(app.create_token()), 200
```

The client application will return the token as a parameter or in
headers for authenticating later requests, till it expires.

Multi-factor authentication (MFA) is supported by generating intermediate tokens
on distinct *realms* at different stages, as discussed in [recipes](RECIPES.md)
and illustrated in the [demo](demo/mfa.py).

Note that route-dependent realms do **not** work with `http-*` authentications
because the realm is frozen by the external implementation in this case.
Also, The same shared secret is used to validate all realms.

### LDAP Authentication

When the provider is `ldap` or `ldap3`, password management is delegated to an
LDAP server accessed with `python-ldap` or `ldap3`.

Only the _simple_ method is currently implemented, i.e. the clear text
password is send directly to the LDAP server for consideration, which
means that if your network is compromised your are basically leaking
passwords…

LDAP does not have a simple concept of user identifier, aka login, but rather
relies on a hierarchy of identifiers to distinguish an object, called a
DN (distinguished name). Thus, the typical authentication process from
a _username_ and _password_ is:

1. Connect to the server, possibly with an initial identifier/password.
2. Perform a search to find the DN corresponding to the username.
   The search succeeds if it returns _one_ entry.
3. Authenticate (called binding) to the server with this DN and password.

You must trust the network and the server… btw, did you really authenticate it
before sending the user credentials in clear text?

The following parameters, provided with `FSA_PASSWORD_OPTS`, allow to configure
the access to the LDAP server:

- `url`: a detailed LDAP URL which can contain most parameters at once:
  `ldaps://dn:pw@host:port/base?attr?scope?filter`.
  However, given the length of LDAP query parameters, this might not be
  easy to read, so consider providing it decomposed as:
- `scheme`: `ldap` (port _389_) or `ldaps` (SSL on port _686_).
- `host`: hostname of the LDAP server, defaults to _localhost_.
- `port`: port number, defaults depends on `scheme`.
- `dn`/`pw`: distinguished name and password for searching.
  In not provided, an anonymous search will be attempted.
- `attr`: attribute for searching, defaults to `uid`.
- `scope`: `sub`, `one` or `base`, defaults to `sub`.
  Define the scope of the search.
- `filter`: additional filter for searching, defaults to `(objectClass=*)`.
- `use_tls`: whether to start a TLS connection, defaults to _True_.

For provider `ldap3`, additional parameters allow to provide more configuration
to various phases of the authentication process:

- `server_opts`: dictionary of parameters for `Server`.
- `conn_opts`: dictionary of parameters for `Connection`.
- `search_opts`: dictionary of parameters for `search`.

Performance implications of authenticating with an LDAP service are unclear.

## Authorization

Authorizations are declared with the `authz` parameter to the
`route` decorator or its per-method shortcuts.
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
There are three approaches to check for group membership:

- use predefined group special values `OPEN AUTH CLOSE`.
- associate a group membership function to each group name.
- use the `user_in_group(user, group)` function to check whether the
  authenticated user belongs to a given group.

Because these functions are cached by default, the cache expiration must
be reached so that changes take effect, or the cache must be cleared
manually, which may impair application performance.

```python
@app.get("/admin-only", authz="ADMIN")
def get_admin_only():
    # only authenticated "ADMIN" users can get here!
```

There are three special values that can be passed to the `authz` decorator
parameter:

- `"OPEN"` declares that no authentication is needed on that route,
  i.e. anyone can get in, the route is open.
  This _requires_ that authentication `none` is allowed by `FSA_AUTH`
  configuration, otherwise it is treated as `AUTH`.
  Moreover, if `FSA_AUTH_DEFAULT` is set to an authentication scheme, it is
  _necessary_ to add `authn="none"` to the route definition to open it.
- `"AUTH"` declares that all _authenticated_ users can access this route,
  without group checks.
  This _requires_ that some authentication scheme is allowed, otherwise it is
  treated as `CLOSE`.
- `"CLOSE"` returns a *403* on all access. It can be used to close a route
  temporarily. This is the default if `authz` is not set.

```python
@app.get("/closed", authz="CLOSE")
def get_closed():
    # nobody can get here

@app.get("/authenticated", authz="AUTH")
def get_authenticated():
    # AUTH-enticated users can get here

@app.get("/opened", authz="OPEN")
def get_opened():
    # anyone can get here, no authentication is required
```

Note that this simplistic model does is not enough for non-trivial applications,
where permissions on objects often depend on the object owner.
For those, careful per-object and per-operation authorization are needed.

Groups *can* be registered with `add_group` or with `FSA_AUTHZ_GROUPS`.
If done so, unregistered groups are rejected and result in a configuration error:

```python
app.add_group("student", "professor")

@app.get("/students", authz="admin")  # ERROR, unregistered group
def get_students():
    ...
```

### OAuth Authorizations

OAuth authorizations are similar to group authorizations.
They are attached to the current authentification performed through a token,
on routes explicitely marked with `authn="oauth"`.
In that case, the `authz` values are interpreted as *scopes* that must be
provided by the token.

In order to simplify security implications, *scopes* and *groups*
(`user_in_group`) authorizations cannot be mixed on a route:
create distinct routes to handle these.
Another current limitation is that only one *issuer* is allowed.

```python
# /data is only accessible through a trusted JWT token with "read" scope
@app.get("/data", authz="read", authn="oauth"):
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

In order to implement this model, the `authz` decorator parameter can
hold `(domain, variables, mode)` tuples which designate a permission domain
(eg a table or object or concept name in the application), the :-separated
names of variables in the request (path or HTTP or JSON parameters) which
identify an object of the domain, and the operation or level of access
necessary for this route:

```python
@app.get("/message/<mid>", authz=("msg", "mid", "read"))
def get_message_mid(mid: int):
    ...
```

The system will check whether the current user can access message *mid*
in *read* mode by calling a per-domain user-supplied function:

```python
@app.object_perms("msg")
def can_access_message(user: str, mid: int, mode: str) -> bool|None:
    # can user access message mid for operation mode?
    return ...

# also: app.object_perms("msg", can_access_message)
```

If the check function returns *None*, a *404 Not Found* response is generated.
If it returns *False*, a *403 Forbidden* response is generated.
If it returns *True*, the route function is called to generate the response.

If `mode` is not supplied, *None* is passed to the check function.
If `variables` is not supplied, the *first* parameter of the route function
is taken:

```python
# same as authz=("msg", "mid", None)
@app.patch("/message/<mid>", authz=("msg",))
def patch_message_mid(mid: int):
    ...
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
@app.get("/something/<id>", authz=...)
def get_something_id(id: int, when: date, what: str = "nothing"):
    # `id` is an integer path-parameter
    # `when` is a mandatory date HTTP or JSON parameter
    # `what` is an optional string HTTP or JSON parameter
    ...
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
parameters are added to it, as shown below:

```python
@app.put("/awesome", authz="AUTH")
def put_awesome(**kwargs):
    ...
```

[Pydantic](https://pydantic.dev)-generated classes and dataclasses work out of
the box both with HTTP and JSON parameters.

```python
class Search(pydantic.BaseModel):
    words: list[str]
    limit: int

# or
@dataclass
class Search:
    words: list[str]
    limit: int

@app.get("/search", authz="OPEN")
def get_search(q: Search):
    ...
```

Generic types can be used, although with restrictions: only combinations of
`list` and `str`-key `dict` of standard Python types are supported and checked.
Using custom classes may or may not work, consider using data classes instead.

```python
@app.get("/question", authz="OPEN")
def get_question(q: list[str]):
    ...
```

Note that `list[*]` when using HTTP parameters are assumed to be _repeated_
parameters, **not** one parameter with a list value.

Custom classes can be used as parameter types, provided that the constructor
accepts a string (for HTTP parameters) or whatever value provided (for JSON)
to build the expected type.

```python
class EmailAddr:
    def __init__(self, addr: str):
        self._addr = addr

@app.get("/mail/<addr>", authz="AUTH")
def get_mail_addr(addr: EmailAddr):
    ...
```

Defining new types can be used to factor out some parameter checks,
for instance requiring a positive integer:

```python
class nat(int):  # this demonstrate Python simplicity
    def __new__(cls, val):
        if val < 0:
            raise ValueError(f"nat value must be positive: {val}")
        return super().__new__(cls, val)

@app.get("/pos", authz="OPEN")
def get_pos(i: nat, j: nat):
    # i and j are positive integers
    ...
```

If the constructor does not match, a custom function can be provided with the
`cast` function/decorator and will be called automatically to convert
parameters:

```python
class House:
    ...

@app.cast(House)
def strToHouse(s: str) -> House:
    return ...

# or: app.cast(House, strToHouse)

@app.get("/house/<h>", authz="OPEN")
def get_house_h(h: House)
    ...
```

The `FSA_CAST` directive can also be defined as a dictionary mapping
types to their conversion functions:

```python
FSA_CAST = { House: strToHouse, ... }
```

As a special case, the `Request`, `Session`, `Globals`, `Environ`,
`CurrentApp`, `CurrentUser`, `Cookie`, `Header` and
[`FileStorage`](https://werkzeug.palletsprojects.com/en/2.2.x/datastructures/#werkzeug.datastructures.FileStorage)
types, when used for parameters,
result in the `request`, `session`, `g` flask special objects, `environ` WSGI
parameter, the current authenticated user, the current application, the cookie value,
the header value or a special file parameter (for upload) to be passed as this
parameter to the function, allowing to keep a functional programming style by
hidding away these special proxies.

More special parameters can be added with the `special_parameter` app
function/decorator, by providing a type and a function which is given the
parameter name (usually useless, but not always) and returns the expected value.
For instance, the `Request` and `FileStorage` definitions roughly correspond to:

```python
app.special_parameter(Request, lambda _: request)
app.special_parameter(FileStorage, lambda p: request.files[p])
```

Special parameter hooks can require other special parameters as parameters.
An example use-case is to make user-related data easily available
through such a special type:

```python
class User:
    def __init__(self, login: str):
        self.firstname, self.lastname = db.get_user_data(login=login)

@app.special_parameter(User)
def gen_user(_: str, user: CurrentUser):
    return User(user)

@app.get("/hello", authz="AUTH")
def get_hello(user: User):
    return f"Hello {user.firstname} {user.lastname}!", 200
```

The `FSA_SPECIAL_PARAMETER` directive can also be defined as a dictionary
mapping types to their parameter value function.

Python parameter names can be prepended with a `_`, which is ignored when
translating HTTP parameters.  This allows to use python keywords as parameter
names, such as `pass` or `def`.

```python
@app.put("/user/<pass>", authz="AUTH")
def put_user_pass(_pass: str, _def: str, _import: str):
    ...
```

Finally, configuration directive `FSA_REJECT_UNEXPECTED_PARAM` tells whether to
reject requests with unexpected parameters.
Default is *True*.

## Utils

Utilities include the `Reference` generic object wrapper class,
error handling utilities and
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

### Error Handling

Raising the `ErrorResponse` exception with a message, status, and possibly
headers and content type from any user-defined function generates a `Response`
of this status with the text message as contents.

The following directives provide convenient configuration about error
handling:

- `FSA_ERROR_RESPONSE` sets the handler for generating actual responses on
  errors.  Text values  *plain* or *json* generate simple `text/plain` or
  `application/json` responses.
  Using *json:error* generates a JSON dictionary with key *error* holding
  the error message.
  The response generation can be fully overriden by providing a callable which
  expects the error message, status code, headers and content type as parameters.
  This handler can be restricted to apply only to FSA-generated errors,
  see `FSA_HANDLE_ALL_ERRORS` below.
  Default is *plain*.

- `FSA_HANDLE_ALL_ERRORS` whether to handle all *4xx* and *5xx* errors,
  i.e. take full responsability for generating error responses using FSA
  internal error handler (see `FSA_ERROR_RESPONSE` above).
  Default is *True*.
  When set to *False*, some errors may generate their own response in
  any format based on Flask default error response generator.

- `FSA_KEEP_USER_ERRORS` whether to refrain from handling user errors
  and let them pass to the outer WSGI infrastructure instead.
  User errors are intercepted anyway, traced and raised again.
  They may occur from any user-provided functions such as various hooks
  and route functions.
  Default is *False*

- `FSA_SERVER_ERROR` controls the status code returned on the module internal
  errors, to help distinguish these from other internal errors which may occur.
  Default is *500*.

- `FSA_NOT_FOUND_ERROR` controls the status code returned when a permission
  checks returns *None*.
  Default is *404*.

A possible pattern is to put checks, say about parameters, in a function
which raises the `ErrorResponse` exception to control client-facing results,
and to call this function for checking these parameters:

```python
def check_foo_param(foo):
    if db_has_no_foo(foo):
        raise ErrorResponse(f"no such foo: {foo}", 404)
    if this_foo_is_confidential(foo, app.current_user()):
        raise ErrorResponse(f"no way foo: {foo}", 403)

@app.get("/foo/<fid>", authz="AUTH")
def get_foo_fid(fid: int):
    check_foo_param(fid)
    ...
```

Such checks can also be performed in an object constructor, with the
inconvenience that the objects become specific to the HTTP context.

### Miscellaneous Configuration Directives

Some directives govern various details for this extension internal working.

- `FSA_MODE` set module mode, expecting *prod*, *dev*, *debug* to *debug4*.
  This changes the module verbosity.
  Under *dev* or debug, `FSA-*` headers is added to show informations about
  the request, the authentication and the elapsed time from the application
  code perspective.
  Default is *prod*.

- `FSA_LOGGING_LEVEL` adjust module internal logging level.
  Default is *None*.

- `FSA_SECURE` only allows secured requests on non-local connections.
  Default is *True*.

- `FSA_LOCAL` sets the internal object isolation level.
  It must be consistent with the module WSGI usage.
  Possible values are *process*, *thread* (several threads can be used by the
  WSGI server), *werkzeug* (may work with sub-thread level request
  handling, eg greenlets), *gevent* and *eventlet*.
  Default is *thread*.

- `FSA_ADD_HEADERS` allows to add headers to the generated response,
  as a dictionary.
  Keys are header names and values are either strings, which are used as is,
  or functions which are called with the response as a parameter to generate
  a value. *None* returned values are silently ignored.
  The corresponding `add_headers` method allows to add headers as keyword
  arguments.
  Default is empty.

- `FSA_DEFAULT_CONTENT_TYPE` allows to replace the default `text/html` header
  added for string or byte responses.
  Default is *None*, meaning no replacement.

- `FSA_JSON_CONVERTER` allows to add new per-type JSON serialization functions,
  as a directory.
  Keys are types, value is a hook to process an object of set type and return
  a JSON serializable something, eg a string.
  The corresponding `add_json_converter` method allows to register new hooks.
  Default is empty.

- `FSA_JSON_STREAMING` allows to force `jsonify` to generate a string instead of
  a string generator when serializing a generator.
  Default _True_ is to stream the JSON output, which may interact badly with the
  database transactions in some cases depending on the driver and WSGI server.

- `FSA_JSON_ALLSTR` whether to cast all unexpected values with `str` when
  converting to JSON.
  Default _False_ is to rely on converters and the default JSON provider.

- `FSA_BEFORE_REQUEST` and `FSA_AFTER_REQUEST` allow to add a list of before
  and after request hooks from the configuration instead of the actual
  application code.
  As a slight deviation from Flask before request hook, before request functions
  are passed the current request as an argument.
  They are executed first (just after some internal initializations and before
  application-provided before request hooks) and last, respectively.
  Defaults are empty.

- `FSA_BEFORE_EXEC` allows to add a list of functions called after all
  preprocessing and just before the actual execution of the route function.
  The hooks are passed the request, the login and the authentication scheme.
  It may return a response to shortcut the route function.
  Such functions can also be registered with the `before_exec`
  function/decorator.
  Defaults are empty.

- `FSA_PATH_CHECK` allows to add a hook to check the route path and possibly
  enforce rules.
  Such functions can also be registered with the `path_check`
  function/decorator.
  Default is _None_, i.e. no checks are performed.

Some control is available about internal caching features used for user
authentication (user password access and token validations) and
authorization (group and per-object permissions):

- `FSA_CACHE` controls the type of cache to use, set to *None* to disallow
  caches. Values for standard `cachetools` cache classes are `ttl`, `lru`,
  `tlru`, `lfu`, `mru`, `fifo`, `rr` plus `dict`.
  MemCached is supported by setting it to `memcached`, and Redis with `redis`.
  Default is `ttl`.
  The directive can also be set to a `MutableMapping` instance to take direct
  control over the cache.

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

- `FSA_CACHED_OPTS` additional options for `cached` decorator.

- Method `clear_caches` allows to clear internal process caches.
  This is a mostly a bad idea, you should wait for the `ttl`.

- Methods `password_uncache`, `token_uncache`, `user_token_uncache`,
  `group_uncache`, `object_perms_uncache` and `auth_uncache` allow to remove a
  particular entry from the shared cache, without waiting for its eventual
  expiration.

  Note that uncaching features are on a best-effort basis, and may not work
  as expected especially with multi-process or multi-level cache settings.
  You should really wait for the `ttl`…

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
  The implementation is simply delegated to the
  [`flask_cors`](https://pypi.org/project/Flask-Cors/) Flask extension
  which must be available if the feature is enabled.

## See Also

The following links point to alternative to *FlaskSimpleAuth*, which may be a
better match depending on the use case.

### Flask-Security

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

### Flask-RESTful

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

### Flask-AppBuilder

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

### Flask-Login

[Flask-Login](https://github.com/maxcountryman/flask-login) is
yet another web-oriented Flask helper to manage logins and logouts using Flask
and an underlying session management. It does not help much with actual
authentication though, and does nothing about authorizations.
By contrast, *Flask Simple Auth*:
- does NOT impose a user model.
- does NOT require enabling session management.
- does NOT require any additional decorator to protect routes.
- does actually provide a consistent authentication, authorization
  and parameter management framework.

### Others

[FlaskSimpleAuth](https://github.com/zx80/flask-simple-auth) is a
[Flask](https://flask.palletsprojects.com/) extension, however:
- you do not have to use Flask for your back-end!
  Other (less popular) HTTP frameworks in the Python ecosystem include:
  [CherryPy](https://cherrypy.dev/),
  [Django](https://www.djangoproject.com/),
  [Falcon](http://falconframework.org/),
  [FastAPI](https://fastapi.tiangolo.com/),
  [Pylon](https://pylonsproject.org/),
  [Pyramid](https://trypyramid.com/)…
- you do not have to use Python for your back-end!
  Other languages with more-or-less convenient HTTP frameworks include:
  [C Ulfius](https://github.com/babelouest/ulfius),
  [C++ Oat++](https://oatpp.io/),
  [C# ASP.NET](https://dotnet.microsoft.com/apps/aspnet),
  [Go Gin](https://github.com/gin-gonic/gin),
  [Java Spring](https://spring.io/),
  [JavaScript Node.js](https://nodejs.org/),
  [Perl Dancer2](https://github.com/PerlDancer/Dancer2/),
  [PHP Lumen](https://lumen.laravel.com/),
  [Ruby Rails](https://rubyonrails.org/),
  [Rust Rocket](https://rocket.rs/),
  [Scala Play](https://www.playframework.com/),
  [SQL PostgREST](https://postgrest.org/)…

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
