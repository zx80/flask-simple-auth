# FlaskSimpleAuth Versions

Sources are available on [GitHub](https://github.com/zx80/flask-simple-auth)
and packaged on [PyPI](https://pypi.org/project/FlaskSimpleAuth/).

## 27.5 on ?

Improve configuration-time detection of uncheckable groups.
Improved documentation.

## 27.4 on 2024-01-06

Remove underserved configuration error when `user_in_group` is not set.
This is a short term fix, rPobably too lax for now.
Improved documentation.
Rename an internal class.

## 27.3 on 2024-01-06

Improved documentation, including a sample configuration.
Allow running an application without caching.

## 27.2 on 2024-01-05

Fix `check_user_password` signature.

## 27.1 on 2024-01-05

Improved documentation.
Add some resilience to passlib failures.

## 27.0 on 2023-12-09

Add `FSA_GROUP_CHECK` configuration directive and
corresponding `group_check` decorator.
Keep track of valid authenticated token.

## 26.0 on 2023-11-30

Add `FSA_DEFAULT_CONTENT_TYPE` configuration directive.
Improve documentation.

## 25.3 on 2023-11-19

Improve documentation.
Add Python _3.12_ support.

## 25.2 on 2023-10-01

Minor update for Flask 3.0 `__version__` deprecation.
Improve tutorial and API documentation.

## 25.1 on 2023-08-27

Add support for `tlru` cache (Time-aware Least Recently Used).
Add a lock consistent with `FSA_LOCAL` when caching.
Add `password_uncache`, `token_uncache`, `group_uncache` and
`object_perms_uncache` methods to remove specific cache entries.
Pass header name to header-generation functions.
Improve documentation.

## 25.0 on 2023-08-22

Add *gevent* and *eventlet* to `FSA_LOCAL`.
Improve type declarations.
Add a tested tutorial and recipes, following [Diátaxis](https://diataxis.fr/)
recommendations.
Refactor hook type declarations in a dummy class.
Rename `FSA_PASSWORD_LEN` to `FSA_PASSWORD_LENGTH` for consistency.
Turn unknown `FSA_*` directives into configuration errors.
Drop `FSA_DEBUG` compatibility.
Improve API automatically generated documentation.
Add route parameters `authz` and `authn` as synonymous to `authorize` and `auth`.

## 24.0 on 2023-07-28

Add support for custom authentication.
Extend `ErrorResponse` with headers and content type.
Add auto-generated API documentation.
Improve documentation for Sphinx with RTD theme.
Refactor documentation management in a subdirectory.
Refactor authentication, authorization, request, parameter, response, token,
password and cache management code.

## 23.2 on 2023-07-23

Improve `jsonify` to deal with pydantic-generated classes.
Allow using some auth only on some routes, not in default list.
Fix some debug message formatting.
Fix handling of `pydantic` classes as custom *special parameters*.
Better documentation.

## 23.1 on 2023-07-13

Add `Cookie` and `Header` special parameters.
Fix some markdown checks.
Fix demo tests.

## 23.0 on 2023-06-14

Rename branch `master` to `main`.
Switch to full `pyproject.toml`.
Fix and improve demo curl tests.
Add support for MFA with per-route `realm`, see demo.

## 22.0 on 2023-03-12

Add a minimal `pyproject.toml`: yet another useless file, which would be a
good thing if it *replaced* other files, alas the two `setup.*` files are still
required.
Add support for data classes and [pydantic](https://pydantic.dev/) classes
as parameter types.
Add an after auth/before exec hook, executed just before actually calling
the route function.
Report all possible *400* instead of stopping on the first issue.
Improve documentation.

## 21.5 on 2023-02-05

Remove badly thought upward compatibility attempt.

## 21.4 on 2023-02-05

Make `jsonify` work with generators, maps, filters and ranges.
Ensure upward compatibility with next `ProxyPatternPool` release.
Fix `debug4` request formatting.

## 21.3 on 2023-02-04

Add list of params and files to `debug4` request traces.

## 21.2 on 2023-02-02

Add `debug4` verbosity to show request and response headers.
To intercept the body, consider using `tcpdump`.

## 21.1 on 2023-01-31

Improve `demo` with an upload example.
Fix display of authentication source in `dev` mode.
Better check parameter types.

## 21.0 on 2023-01-29

Add `FSA_KEEP_USER_ERRORS` configuration directive to skip handling
user errors and let them pass to the WSGI infrastructure instead.
Add convenient messages when missing an optional module.
Log internal error traces as errors.
Simplify optional dependencies.
Extend special parameter functions with a parameter holding
the name of the expected parameter.
Add `FileStorage` special parameter to get file uploads.
Add *manual* table of contents to `README.md` and `DOCUMENTATION.md`.

## 20.11 on 2023-01-26

Add dependency options to `setup.cfg`.
Show traces on internal errors.

## 20.10 on 2023-01-15

Reduce verbosity again by adding a "debug3" mode.

## 20.9 on 2023-01-14

Reduce verbosity when calling `current_user`.
Improved documentation.

## 20.8 on 2023-01-14

Prioritize parameter sources and detect shadowing.
Improved documentation.

## 20.7 on 2023-01-14

Add convenient `FSA-Request` and `FSA-User` headers in `dev` mode.
Return several challenges with `WWW-Authenticate` if appropriate.

## 20.6 on 2023-01-13

Fix password manager lazy initialization.
Improved documentation.

## 20.5 on 2023-01-11

Improve debug messages on parameters.

## 20.4 on 2023-01-07

Accept `? | None` type declarations on route functions.

## 20.3 on 2023-01-02

Add `FSA_HANDLE_ALL_ERRORS` configuration directive.
Improved documentation.

## 20.2 on 2022-12-27

Generate `application/json` instead of `text/json`.
Cleanup a flake8 warning.
Improved documentation.

## 20.1 on 2022-12-24

Replace `FSA_DEBUG` by `FSA_MODE`.
Show request execution time in µs precision under debug.
Improved documentation.

## 20.0 on 2022-12-22

Split `README.md` with `DOCUMENTATION.md`.
Improve documentation, published on [github.io](https://zx80.github.io/flask-simple-auth/).
Add `error_response` decorator and `FSA_ERROR_RESPONSE` directive
to control generated error responses.
Add `add_headers` function and `FSA_ADD_HEADERS` directive to append
new headers to the response.
Add `FSA_BEFORE_REQUEST` and `FSA_AFTER_REQUEST` directives to add hooks
directly from the configuration.

## 19.3 on 2022-12-06

Fix an uncaught typo.

## 19.2 on 2022-12-06

Improve work around to handle early return.
Add `CurrentApp` special parameter type.
Improved documentation.

## 19.1 on 2022-12-05

Avoid internal error if a user before request generates an early
return, in some cases.
Improve documentation and tests.

## 19.0 on 2022-11-16

Add `add_group` method to register groups allowed for `authorize`,
and `add_scope` to register scopes allowed for `oauth`.
Add corresponding `FSA_AUTHZ_GROUPS` and `FSA_AUTHZ_SCOPES`
directives.
Rename `user_oauth` as `user_scope` for consistency.
Allow to provide configuration directives as constructor arguments.
Improve documentation.

## 18.1 on 2022-11-11

Handle `Optional` parameters to please `mypy`.
Add Python 3.12-dev check to CI.
Improve documentation.

## 18.0 on 2022-11-07

Add `special_parameter` decorator and `FSA_SPECIAL_PARAMETER` directive
to add special parameters.
Add `CurrentUser` special parameter.
Add `password_check` hook (also with `FSA_PASSWORD_CHECK` directive) for
alternate password checking such as temporary access codes or external
passwords, eg LDAP.
Add `password_quality` hook (also with `FSA_PASSWORD_QUALITY` directive) to
check for a password strength.
Add `FSA_TOKEN_ISSUER` to specify a token issuer.
Add `oauth` authentication for OAuth 2.0 authorization support (RFC 8693).
Add `FSA_LOCAL` to adjust local data management.
Set `FSA_TOKEN_RENEWAL` default to *0.0*.
Prioritize authentication scheme per configuration or route order (`auth`).
Improve documentation.

## 17.0 on 2022-10-29

Move `Reference` implementation to module `ProxyPatternPool`.
Add `Environ` special parameter type.

## 16.0 on 2022-10-27

Require Flask 2.2.
Add `FSA_REJECT_UNEXPECTED_PARAM` to be strict about unexpected parameters.
Add `Request`, `Session` and `Globals` special parameter types.
Ensure `Reference` count consistency.
Improve one error message.

## 15.0 on 2022-09-11

Add early sanity checks about path parameters: they *must* appear as function
parameters and should not have a default value.
Also, path parameters converter, if declared, should be consistent with
the corresponding parameter type.
Improve `mypy` checks by removing some *ignore* hints.
Improve `Makefile`.
Rename FSA generated exceptions: `ErrorResponse` and `ConfigError`.
Add `pymarkdown` check.
Add a GitHub CI configuration (with 99% coverage for now).

## 14.2 on 2022-08-02

Only use `re2` if available, do not require it as a dependency.

## 14.1 on 2022-08-02

Fix pypi badge version link.

## 14.0 on 2022-08-02

Fix compatibility with *Flask 2.2*.
Add `max_use` to internal pool.
Use `re2` instead of `re`.
Improve documentation.

## 13.0 on 2022-06-12

Add `max_size` parameter to `Reference` pool.
Remove `pool` constructor parameter.
Add `mode` option to `Reference` with a `VERSATILE` scope.

## 12.0 on 2022-05-30

Add `pool` option to `Reference` to better deal with `werkzeug` thread management.
Improve documentation and code comments.

## 11.0 on 2022-05-27

Add `FSA_CACHE_PREFIX` directive to help with sharing a distributed cache
such as redis or memcached.

Fixes for Flask 2.1:
Now `get_json` raises a exception when unhappy instead of returning `None`.
Remove `safe_join` export as flask removed it.

## 10.0 on 2022-03-06

Improve documentation. Minor code cleanup.
Take advantage of `CacheToolUtils` 3.0 to reduce the loc count.

## 9.0 on 2022-03-04

Extend `set` in `Reference` to handle both objects and generation functions.
Fix `cast` decorator.

## 8.0 on 2022-03-04

Use `AUTH` as the default parameter name for tokens.
Under debug, warn about unused parameters.
Improve demonstration code and environment.
Use `threading.local()` so that `Flask` and `Reference` work with threads.

## 7.0 on 2022-02-24

Improve and simplify code where possible.
Remove `FSA_MODE`, `FSA_SKIP_PATH` and `FSA_CHECK` directives to make
authentication *always* on demand. This is safe because missing
authorizations are treated as errors and route are closed by default.
Drop Flask 1.x support.
Remove `register_cast` function, in favor of the `cast` method.
Simplify `Reference` implementation.

## 6.0 on 2022-02-13

Rename `register_object_perms` and `register_cast` functions to simpler
`object_perms` and `cast`.
Add `FSA_OBJECT_PERMS` and `FSA_CAST` configuration directives.
Make module work without `cachetools` if `FSA_CACHE` is set to *None*.
Use `ttl` as a default cache strategy.
Simplify version numbering from 3 to 2 figures.
Improve demo example with login and email authentication.
Make all configuration errors issue a critical message.

## 5.4.0 on 2022-02-08

Add `JsonData` special type to convert strings to JSON.
Improve json parameter type tests.

## 5.3.0 on 2022-02-04

Improve debug mode setting.
Attempt at fixing typing errors with json.

## 5.2.0 on 2022-01-31

Add convenient `cast` decorator to register a cast directly.
Add `FSA_DEBUG` and `FSA_NOT_FOUND_ERROR` configuration directives.

## 5.1.0 on 2022-01-30

Add default variable name to object permission checks.
Add convenient `object_perms` decorator.
Return *404* when checking perm on an unknown object.
Warn on overriden hooks.
Improve tests.

## 5.0.0 on 2022-01-29

Add a per-object permission scheme to the `authorize` decorator parameter.
Add support for [Redis](https://redis.io/) and [MemCached](https://memcached.org/)
distributed caches.
Move cache support to [CacheToolsUtils](https://pypi.org/project/CacheToolsUtils/).

## 4.7.1 on 2022-01-16

Bump version in doc.

## 4.7.0 on 2022-01-16

Add `FSA_SERVER_ERROR` configuration directive to control the server internal
error status code.
Add `FSA_SECURE` to check for secure requests, on by default (sorry!).
Drop `allparams` and `required` route parameters: they are implicit with a dict
of keyword arguments and default values.
Improve documentation.

## 4.6.3 on 2022-01-12

Improve error messages on internal errors in user functions such as
`get_user_pass`, `user_in_group` or path functions.

## 4.6.2 on 2021-12-26

Put back version auto extraction after `aiosql` update to *3.4.0*.

## 4.6.1 on 2021-12-24

Minor cleanup.

## 4.6.0 on 2021-12-19

Fix timezone issues by putting everything explicitely in UTC.
Rework caching: remove `CacheOK` class, add `FSA_CACHE` and `FSA_CACHE_OPTS` to
give more ability to control the type of cache and its behavior.
Use a TTL cache set to 10 minutes by default.
Rename `*_OPTIONS` to `_OPTS` for consistency and concision.

## 4.5.1 on 2021-12-12

Ensure that FSA internal exceptions are always translated into HTTP responses.

## 4.5.0 on 2021-12-12

Add `FSA_PASSWORD_LEN` and `FSA_PASSWORD_RE` directives to check
for password quality when hashing.
Remove `VERSION` and `VERSION\_NUM`, replaced with `__version__`,
although not from the package resources because of some obscure issue…

## 4.4.0 on 2021-12-11

Add support for CORS with directives `FSA_CORS` and `FSA_CORS_OPTIONS`.

## 4.3.1 on 2021-12-05

Add `FSA_TOKEN_RENEWAL` directive to manage automatic renewal of cookie-based
authentication tokens.
Fix version in module.

## 4.3.0 on 2021-10-14

Rename `FSA_TOKEN_REALM` as `FSA_REALM`, because it is not token specific.
Make demo work with psycopg 3.

## 4.2.0 on 2021-09-14

Add `register_cast` to provide a cast function for custom types, if the type
itself would not work.
Add `VERSION` as a string and `VERSION_NUM` as an integer tuple.
Improve documentation.
Allow to use Python keywords as HTTP parameters by prepending the
parameter with a `_`.

## 4.1.0 on 2021-06-12

Add support for per-method decorator shortcuts to `Flask` wrapper class.
Add `FSA_LOGGING_LEVEL` directive.
Make `current_user` attempt an authentication, but not fail on errors.
Check configuration directive names to warn about possible typos or errors.
Warn about some unused directives.
Check `get_user_pass` and `user_in_group` returned types.
Update documentation.
Add a demo application.

## 4.0.0 on 2021-06-01

Port to Flask 2.0, working around a regression on `request.values` handling.
Add support for Flask 2.0 per-method decorator shortcuts `get`, `post`, `put`,
`delete` and `patch`.
Rework documentation.
Minor style improvements.
Fix `all` authentication mode.

## 3.1.1 on 2021-05-31

Tell setup that Flask 2.0 is not yet supported.

## 3.1.0 on 2021-04-17

Defer password manager setup till it is actually needed, so as to avoid
importing `passlib` for nothing.
Do not attempt to re-create a token if it is not possible, i.e. when
relying on a third party token provider.
Allow to fully control the list of authentication schemes.
Allow to control the authentication scheme on a route.
Improve test code coverage.

## 3.0.0 on 2021-04-07

Add `FSA_CACHE_SIZE` to control caches.
Merge `FSA_ALWAYS` and `FSA_LAZY` in a single `FSA_MODE` directive
with 3 values: `always`, `lazy` and `all`.
Make `ANY`, `ALL` and `NONE` special groups simple strings as well.
Package as a one file module (again), and add more files to packaging.

## 2.5.0 on 2021-04-04

Add *header* carrier for authentication tokens.
Make it work both with internal and HTTPAuth implementations.
Force HTTPAuth implementation on `http-token`.

## 2.4.1 on 2021-03-29

Fix packaging issue… the python file was missing.
Add `digest` as a synonymous for `http-digest`.
Improve documentation.

## 2.4.0 on 2021-03-29

Add `http-basic`, `http-digest` and `http-token` authentication schemes based
on flask-HTTPAuth.
Add coverage report on tests.
Distribute as a one file python module.
Only simplify realm for *fsa* tokens.
Renew cookies when they are closing expiration.

## 2.3.0 on 2021-03-27

Use a fully dynamic method for `set` in `Reference`.
Add a `string` type.
Add caching of `get_user_pass` and `user_in_group` helpers.
Add `clear_caches` method.
Warn on missing `authorize` on a route declaration.
Add `FSA_TOKEN_CARRIER` to specify how token auth is transfered,
including a new *cookie* option.
Rename `FSA_TYPE` to `FSA_AUTH`.
Make `create_token` argument optional.
Add `WWW-Authenticate` headers when appropriate.
Set `Content-Type` to `text/plain` on generated responses.

## 2.2.1 on 2021-03-22

Partial fix for method renaming in `Reference`.

## 2.2.0 on 2021-03-22

Rename `_setobj` to `set` in `Reference`, with an option to rename the method
if needed.
Shorten `Reference` class implementation.
Add `current_user` to `FlaskSimpleAuth` as well.
Add python documentation on class and methods.
Fix `Reference` issue when using several references.

## 2.1.0 on 2021-03-21

Add `Reference` any object wrapper class.
Add `CacheOK` positive caching decorator.
Add `current_user` function.
Add `none` authentication type.
Add `path` parameter type.
Add more tests.

## 2.0.0 on 2021-03-16

Make the module as an extension *and* a full `Flask` wrapper.
Advertise only the extended `route` decorator in the documentation
(though others are still used internally).
Change passlib bcrypt version to be compatible with Apache httpd.
Allow disabling password checking.
Rename `FSA_TOKEN_HASH` as `FSA_TOKEN_ALGO`.
Disable tokens by setting their type to `None`.
Import Flask `session`, `redirect`, `url_for`, `make_response`,
`abort`, `render_template`, `current_app` objects.
Add parameter support for `date`, `time` and `datetime` in iso format.
Allow to use any type as path parameters, not just Flask predefined ones.
Make blueprints work.
Add special `path` type for parameters taken from the path.

## 1.9.0 on 2021-03-10

Add *bearer* authorization for tokens and make it the default.
Add *JWT* tokens, both hmac and pubkey variants.
Add *500* generation if a route is missing an authorization declaration.
Add convenient `route` decorator.
Add type inference for HTTP/JSON parameters based on default value, when provided.
Add type inference for root path parameters based on function declaration.

## 1.8.1 on 2021-03-02

Fix typo in distribution configuration file.

## 1.8.0 on 2021-03-02

Merge `autoparams` and `parameters` decorators into a single `parameters`
decorator.
Make it guess optional parameters based on default values.
Fix conversion issues with boolean type parameters.
Enhance integer type to accept other base syntaxes.
Improve documentation to advertise the simple and elegant approach.
Implement decorator with functions instead of a class.

## 1.7.0 on 2021-03-01

Simplify code.
Add `FSA_ALWAYS` configuration directive and move the authentication before request
hook logic inside the module.
Add `FSA_SKIP_PATH` to skip authentication for some paths.
Update documentation to reflect this simplified model.
Switch all decorators to functions.

## 1.6.0 on 2021-02-28

Add `autoparams` decorator with required or optional parameters.
Add typed parameters to `parameters` decorator.
Make `parameters` pass request parameters as named function parameters.
Simplify `authorize` decorator syntax and implementation.
Advise `authorize` *then* `parameters` or `autoparams` decorator order.
Improved documentation.

## 1.5.0 on 2021-02-27

Flask *internal* tests with a good coverage.
Switch to `setup.cfg` configuration.
Add convenient `parameters` decorator.

## 1.4.0 on 2021-02-23

Add `FSA_LAZY` configuration directive.
Simplify code.
Improve warning on short secrets.
Repackage…

## 1.3.0 on 2021-02-23

Improved documentation.
Reduce default token signature length and default token secret.
Warn on random or short token secrets.

## 1.2.0 on 2021-02-22

Add grace time for auth token validity.
Some code refactoring.

## 1.1.0 on 2021-02-22

Add after request module cleanup.

## 1.0.0 on 2021-02-21

Add `authorize` decorator.
Add `password` authentication scheme.
Improved documentation.

## 0.9.0 on 2021-02-21

Initial release in beta.
