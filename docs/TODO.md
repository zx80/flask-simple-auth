# Backlog

Backlog of features that may or may not come.

## Authentication

- several _simultaneous_ password management schemes should really be supported.
  this is already the case with `passlib`.
- use default authentication in demo and other live projects (kiva, pizza, ref).
- ldap
  - [see also](https://github.com/rroemhild/flask-ldapconn)
  - ldap3 pool?
  - how to actually tests LDAP?
    [rroemhild](https://github.com/rroemhild/docker-test-openldap) 2021?
- fake provider for testing: limiting fake authn to a parameter is inconvenient in practice.
  or record "test" as a new authentication and provide an adhoc function,
  eg to rely on ad-hoc unsigned tokens, for instance.
- [passlib totp](https://passlib.readthedocs.io/en/stable/lib/passlib.totp.html)
- add `any` token scheme?
- oauth: issuer/scope? issuer/secret?
- how to have several issuers and their signatures schemes?
- add `issuer` route parameter? see `realm`.
- integrate `authlib`?
- password re could use a dict for providing an explanation?
- test `FSA_HTTP_AUTH_OPTS`?
- declare scopes *per domain*?

## Authorization

- ldap authz?
- authz/authn consistency? should "none" be required for "OPEN" routes?

## Parameters

- `FSA_PARAM_STYLE` *any/http/json* to restrict/force parameters?
  being lazy is not too bad?
- allow handling files in kwargs?
- add a filter on returned value? `make_response`? after request?

## Caching

- how to export and use the cache for user-related data?
- client caching should/could depend on the route/method…
  use declarations? hints? hooks?
- what about secured caching, eg an expensive password check?

## Other Features

- how to add a timeout? or manage an outside one?
- `logging` default behavior is a *pain* and the maintainer is self satisfied.
  how to ensure that logging is initialized?
- the doc and implementation should clarify exception handling,
  and possible overrides.
- add ability to catch and process any user error.
  what about Flask?
- declare some exceptions to be turned into 400 instead of 500?
  currently this can be done below, eg anodb, maybe this is enough?
- json mode: generate json in more cases? automatically?

## Software Engineering

- reduce sloc?
- check for more directive types (dynamically)?
- add app.log?
- take advantage of `TypedDict`?

## Documentation

- more recipes?
- include demo? point to demo?
- comparisons with other frameworks
- use `FlaskTester` in tutorial?

## Misc

- bad/malformed requests should generate _400_ instead of _500_ in some cases?
- remove deprecated authorize/auth decorator parameter names.
- remove deprecated ALL/ANY/NONE special groups.
- fix `SpecialParameterFun` type declaration.
- fix `ObjectPermsFun` type declaration.
