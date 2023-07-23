"""
Flask Extension and Wrapper

This extension helps manage:
- authentication
- authorization
- parameters
- and more…

This code is public domain.
"""

import sys
from typing import Callable, MutableMapping, Any
import typing
import types

import functools
import inspect
import datetime as dt
import dataclasses
from enum import IntEnum
import json

try:
    import re2 as re  # type: ignore
except ModuleNotFoundError:
    import re  # type: ignore

import flask
import werkzeug.exceptions as exceptions
import ProxyPatternPool as ppp  # type: ignore

# for local use & forwarding
# NOTE the only missing should be "Flask"
from flask import (
    Response, Request, request, session, Blueprint, make_response,
    abort, redirect, url_for, after_this_request, send_file, current_app, g,
    send_from_directory, render_template, get_flashed_messages,
    has_app_context, has_request_context, render_template_string,
    stream_template, stream_template_string, stream_with_context,
)

if flask.__version__.startswith("2.2."):  # pragma: no cover
    from flask import escape, Markup
# 2.3: they are in markupsafe

from werkzeug.datastructures import FileStorage

import logging
log = logging.getLogger("fsa")

# get module version
from importlib.metadata import version as pkg_version
__version__ = pkg_version("FlaskSimpleAuth")

# hook function types
# generate an error response for message and status
ErrorResponseFun = Callable[[str, int], Response]
# get password from user login, None if unknown
GetUserPassFun = Callable[[str], str|None]
# is user login in group (str or int): yes, no, unknown
UserInGroupFun = Callable[[str, str|int], bool|None]
# check object access in domain, for parameter, in mode
ObjectPermsFun = Callable[[str, Any, str|None], bool]
# low level check login/password validity
PasswordCheckFun = Callable[[str, str], bool|None]
# is this password quality suitable?
PasswordQualityFun = Callable[[str], bool]
# cast parameter value to some object
CastFun = Callable[[str|Any], object]
# generate a "special" parameter, with the parameter name
SpecialParameterFun = Callable[[str], Any]
# add a header to the current response
HeaderFun = Callable[[Response], str|None]
# before request hook, with request provided
BeforeRequestFun = Callable[[Request], Response|None]
# after authentication and right before exec
BeforeExecFun = Callable[[Request, str, str], Response|None]
# after request hook
AfterRequestFun = Callable[[Response], Response]


@dataclasses.dataclass
class ErrorResponse(BaseException):
    """Internal exception class to carry fields for an error Response."""
    # NOTE this should maybe inherit from exceptions.HTTPException?
    message: str
    status: int


class ConfigError(BaseException):
    """FSA Configuration User Error."""
    pass


class Mode(IntEnum):
    """FSA running modes."""
    UNDEF = 0
    PROD = 1
    DEV = 2
    DEBUG1 = 3
    DEBUG2 = 4
    DEBUG3 = 5
    DEBUG4 = 6
    DEBUG = 3


_MODES = {
    "debug1": Mode.DEBUG1,
    "debug2": Mode.DEBUG2,
    "debug3": Mode.DEBUG3,
    "debug4": Mode.DEBUG4,
    "debug": Mode.DEBUG,
    "dev": Mode.DEV,
    "prod": Mode.PROD,
}


#
# TYPE CASTS
#
class path(str):
    """Type to distinguish str path parameters."""
    pass


class string(str):
    """Type to distinguish str string parameters."""
    pass


# "JsonData = json.loads" would do:-)
class JsonData:
    """Magic JSON type."""
    pass


class Session:
    """Session parameter type."""
    pass


class Globals:
    """Globals parameter type."""
    pass


class Environ:
    """Environ parameter type."""
    pass


class CurrentUser:
    """CurrentUser parameter type."""
    pass


class CurrentApp:
    """CurrentApp parameter type."""
    pass


class Cookie:
    """Application Cookie type."""
    pass


class Header:
    """Request Header type."""
    pass


#
# SPECIAL PREDEFINED GROUP NAMES
#
#  ANY: anyone can come in, no authentication required
#  ALL: all authenticated users are allowed
# NONE: no one can come in, the path is forbidden
#
ANY, ALL, NONE = "ANY", "ALL", "NONE"
_PREDEFS = (ANY, ALL, NONE)


def _typeof(p: inspect.Parameter):
    """Guess parameter type, possibly with some type inference."""
    if p.kind is inspect.Parameter.VAR_KEYWORD:  # **kwargs
        return dict
    elif p.kind is inspect.Parameter.VAR_POSITIONAL:  # *args
        return list
    elif p.annotation is not inspect._empty:
        a = p.annotation
        # FIXME how to recognize reliably an Optional[?] across versions
        if sys.version_info >= (3, 10):  # pragma: no cover
            if isinstance(a, types.UnionType) and len(a.__args__) == 2 and a.__args__[1] == type(None):
                return a.__args__[0]
            elif hasattr(a, "__name__") and a.__name__ == "Optional":
                return a.__args__[0]
            elif hasattr(a, "__origin__") and a.__origin__ is typing.Union and len(a.__args__) == 2:
                return a.__args__[0]
            else:
                return a
        elif hasattr(a, "__origin__") and a.__origin__ is typing.Union and len(a.__args__) == 2:  # pragma: no cover
            return a.__args__[0]
        else:  # pragma: no cover
            return a
    elif p.default and p.default is not inspect._empty:
        return type(p.default)
    else:
        return str


def _get_file_storage(p: str) -> FileStorage:
    """Extract file parameter from request, or generate 400."""
    if p not in request.files:
        raise ErrorResponse(f"missing file parameter \"{p}\"", 400)
    return request.files[p]


def jsonify(a: Any):
    """Jsonify something, including generators and pydantic stuff."""
    if hasattr(a, "model_dump"):  # Pydantic BaseModel
        return a.model_dump()
    elif hasattr(a, "__pydantic_fields__"):  # Pydantic dataclass
        return dataclasses.asdict(a)
    elif hasattr(a, "__dataclass_fields__"):  # standard dataclass
        return dataclasses.asdict(a)
    elif inspect.isgenerator(a) or type(a) in (map, filter, range):
        return flask.jsonify(list(a))
    else:
        return flask.jsonify(a)


class Reference(ppp.Proxy):
    """Convenient object wrapper class."""

    def __init__(self, *args, close: str|None = "close", **kwargs):
        # NOTE max_delay is just here for backward compatibility
        # TODO remove at some point
        # if max_delay is not None and ppp.__version__ >= (4, 0):  # pragma: no cover
        #    kwargs["max_avail_delay"] = max_delay
        super().__init__(*args, close=close, **kwargs)


class Flask(flask.Flask):
    """Flask class wrapper.

    The class behaves mostly as a Flask class, but supports extensions:

    - the `route` decorator manages authentication, authorization and
      parameters transparently.
    - per-methods shortcut decorators allow to handle root for a given
      method: `get`, `post`, `put`, `patch`, `delete`.
    - several additional methods are provided: `get_user_pass`,
      `user_in_group`, `check_password`, `hash_password`, `create_token`,
      `get_user`, `current_user`, `clear_caches`, `cast`, `object_perms`,
      `user_scope`, `password_quality`, `password_check`, `add_group`,
      `add_scope`, `add_headers`, `error_response`.
    """

    def __init__(self, *args, debug: bool = False, **kwargs):
        # extract FSA-specific directives
        fsaconf: dict[str, Any] = {}
        for key, val in kwargs.items():
            if key.startswith("FSA_"):
                fsaconf[key] = val
        for key in fsaconf:
            del kwargs[key]
        # Flask initialization
        super().__init__(*args, **kwargs)
        # FSA initialization
        self._fsa = FlaskSimpleAuth(self, debug=debug, **fsaconf)
        # overwritten late because called by upper Flask initialization for "static"
        setattr(self, "add_url_rule", self._fsa.add_url_rule)
        # forward hooks
        self.error_response = self._fsa.error_response
        self.get_user_pass = self._fsa.get_user_pass
        self.user_in_group = self._fsa.user_in_group
        self.object_perms = self._fsa.object_perms
        self.user_scope = self._fsa.user_scope
        self.cast = self._fsa.cast
        self.special_parameter = self._fsa.special_parameter
        self.password_quality = self._fsa.password_quality
        self.password_check = self._fsa.password_check
        self.add_group = self._fsa.add_group
        self.add_scope = self._fsa.add_scope
        self.add_headers = self._fsa.add_headers
        self.before_exec = self._fsa.before_exec
        # forward methods
        self.check_password = self._fsa.check_password
        self.hash_password = self._fsa.hash_password
        self.create_token = self._fsa.create_token
        self.get_user = self._fsa.get_user
        self.current_user = self._fsa.current_user
        self.clear_caches = self._fsa.clear_caches
        # overwrite decorators ("route" done through add_url_rule above)
        setattr(self, "get", self._fsa.get)  # FIXME avoid mypy warnings
        setattr(self, "put", self._fsa.put)
        setattr(self, "post", self._fsa.post)
        setattr(self, "patch", self._fsa.patch)
        setattr(self, "delete", self._fsa.delete)


# all possible flask-simple-auth directives
_DIRECTIVES = {
    # debug mode
    "FSA_MODE", "FSA_LOGGING_LEVEL",
    # general settings
    "FSA_SECURE", "FSA_SERVER_ERROR", "FSA_NOT_FOUND_ERROR", "FSA_LOCAL",
    "FSA_HANDLE_ALL_ERRORS", "FSA_KEEP_USER_ERRORS",
    # register hooks
    "FSA_GET_USER_PASS", "FSA_USER_IN_GROUP", "FSA_CAST", "FSA_OBJECT_PERMS",
    "FSA_SPECIAL_PARAMETER", "FSA_ERROR_RESPONSE", "FSA_ADD_HEADERS",
    "FSA_BEFORE_REQUEST", "FSA_BEFORE_EXEC", "FSA_AFTER_REQUEST",
    # authentication
    "FSA_AUTH", "FSA_REALM", "FSA_FAKE_LOGIN", "FSA_PARAM_USER",
    "FSA_PARAM_PASS", "FSA_TOKEN_TYPE", "FSA_TOKEN_ALGO", "FSA_TOKEN_CARRIER",
    "FSA_TOKEN_DELAY", "FSA_TOKEN_GRACE", "FSA_TOKEN_NAME", "FSA_TOKEN_LENGTH",
    "FSA_TOKEN_SECRET", "FSA_TOKEN_SIGN", "FSA_TOKEN_RENEWAL",
    "FSA_TOKEN_ISSUER", "FSA_PASSWORD_SCHEME", "FSA_PASSWORD_OPTS",
    "FSA_PASSWORD_CHECK", "FSA_PASSWORD_LEN", "FSA_PASSWORD_RE",
    "FSA_PASSWORD_QUALITY", "FSA_HTTP_AUTH_OPTS",
    # authorization
    "FSA_AUTHZ_GROUPS", "FSA_AUTHZ_SCOPES",
    # parameter handing
    "FSA_REJECT_UNEXPECTED_PARAM",
    # internal caching
    "FSA_CACHE", "FSA_CACHE_SIZE", "FSA_CACHE_OPTS", "FSA_CACHE_PREFIX",
    # web-oriented settings
    "FSA_401_REDIRECT", "FSA_URL_NAME", "FSA_CORS", "FSA_CORS_OPTS",
}

# default settings are centralized here
_DEFAULT_MODE = "prod"
_DEFAULT_CACHE = "ttl"
_DEFAULT_CACHE_SIZE = 262144  # a few MB
_DEFAULT_CACHE_TTL = 600  # seconds, 10 minutes
_DEFAULT_REJECT_UNEXPECTED_PARAM = True
_DEFAULT_SERVER_ERROR = 500
_DEFAULT_NOT_FOUND_ERROR = 404
_DEFAULT_KEEP_USER_ERRORS = False
_DEFAULT_ERROR_RESPONSE = "plain"
_DEFAULT_PASSWORD_SCHEME = "bcrypt"
_DEFAULT_PASSWORD_OPTS = {"bcrypt__default_rounds": 4, "bcrypt__default_ident": "2y"}


# actual extension
class FlaskSimpleAuth:
    """Flask extension for authentication, authorization and parameters."""

    def __init__(self, app: flask.Flask, debug: bool = False, **config):
        """Constructor parameter: flask application to extend."""
        self._mode = Mode.DEBUG2 if debug else Mode.UNDEF
        self._app = app
        self._app.config.update(**config)
        # hooks
        self._error_response: ErrorResponseFun|None = None
        self._get_user_pass: GetUserPassFun|None = None
        self._user_in_group: UserInGroupFun|None = None
        self._object_perms: dict[Any, ObjectPermsFun] = dict()
        self._password_check: PasswordCheckFun|None = None
        self._password_quality: PasswordQualityFun|None = None
        self._casts: dict[type, CastFun] = {
            bool: lambda s: None if s is None else s.lower() not in ("", "0", "false", "f"),
            int: lambda s: int(s, base=0) if s else None,
            inspect._empty: str,
            path: str,
            string: str,
            dt.date: dt.date.fromisoformat,
            dt.time: dt.time.fromisoformat,
            dt.datetime: dt.datetime.fromisoformat,
            JsonData: json.loads,
        }
        self._special_parameters: dict[type, SpecialParameterFun] = {
            Request: lambda _: request,
            Environ: lambda _: request.environ,
            Session: lambda _: session,
            Globals: lambda _: g,
            CurrentUser: lambda _: self.current_user(),
            CurrentApp: lambda _: current_app,
            FileStorage: _get_file_storage,
            Cookie: lambda p: request.cookies[p],
            Header: lambda p: request.headers[p],
        }
        self._auth: list[str] = []           # order default authentications
        self._all_auth: set[str] = set()     # all authentication methods
        self._http_auth = None               # possibly flask_httpauth instance, if needed
        self._pm = None                      # password manager instance, if needed
        # cache management
        self._cache: MutableMapping[str, str]|None = None
        self._gen_cache: Callable|None = None
        # fsa-generated errors
        self._server_error: int = _DEFAULT_SERVER_ERROR
        self._not_found_error: int = _DEFAULT_NOT_FOUND_ERROR
        self._keep_user_errors: bool = _DEFAULT_KEEP_USER_ERRORS
        self._secure: bool = True
        self._secure_warning = True
        # misc
        self._auth_params: set[str] = set()  # authentication parameters to ignore
        self._groups: set[str|int] = set()   # predeclared groups, error if not there
        self._scopes: set[str] = set()       # idem for scopes
        self._headers: dict[str, HeaderFun|str] = {}  # response headers
        self._before_requests: list[BeforeRequestFun] = []
        self._before_exec_hooks: list[BeforeExecFun] = []
        self._after_requests: list[AfterRequestFun] = []
        self._local: Any = None              # per-request data
        # registered here to avoid being bypassed by user hooks
        # FIXME not always?
        self._app.before_request(self._show_request)
        self._app.before_request(self._auth_reset_user)
        self._app.before_request(self._check_secure)
        self._app.before_request(self._run_before_requests)
        # COLDLY override Flask route decorator…
        self._app.route = self.route  # type: ignore
        # pydantic generated class support
        try:
            import pydantic
            self._pydantic_base_model = pydantic.BaseModel  # type: ignore
        except ModuleNotFoundError:  # pragma: no cover
            self._pydantic_base_model = None  # type: ignore
        # actual main initialization is deferred to `_init_app`
        self._initialized = False

    def _Res(self, msg: str, code: int):
        """Generate a actual error Response with a message."""
        # FIXME what about headers and content_type?
        if self._mode >= Mode.DEBUG:
            log.debug(f"error response: {code} {msg}")
        assert self._error_response is not None
        return self._error_response(msg, code)

    def _Exc(self, exc):
        """Handle an internal error."""
        # trace once with subtle tracking
        if exc and not hasattr(exc, "_fsa_traced"):
            log.error(exc, exc_info=True)
            setattr(exc, "_fsa_traced", True)
        return exc if self._keep_user_errors else None

    def _Err(self, msg: str, code: int, exc: Exception = None):
        """Build and trace an ErrorResponse exception with a message."""
        if self._mode >= Mode.DEBUG3:
            log.debug(f"error: {code} {msg}")
        return self._Exc(exc) or ErrorResponse(msg, code)

    def _Bad(self, msg: str, misc: str = None):
        """Build and trace an exception on a bad configuration."""
        if misc:
            msg += "\n" + misc
        log.critical(msg)
        return ConfigError(msg)

    def _auth_has(self, *auth):
        """Tell whether current authentication includes any of these schemes."""
        for a in auth:
            if a in self._local.auth:
                return True
        return False

    #
    # HOOKS
    #
    def _check_secure(self):
        """Before request hook to reject insecure (non-TLS) requests."""
        if not request.is_secure and not (
            request.remote_addr.startswith("127.") or request.remote_addr == "::1"
        ):  # pragma: no cover
            if self._secure:
                log.error("insecure HTTP request, allow with FSA_SECURE=False")
                return self._Res("insecure HTTP request denied", self._server_error)
            else:  # one warning is issued
                if self._secure_warning:
                    log.warning("insecure HTTP request seen")
                    self._secure_warning = False

    def _show_request(self):
        """Show request in debug mode."""
        if self._mode >= Mode.DEBUG4:
            # FIXME is there a decent request prettyprinter?
            r = request
            rpp = f"{r}\n"
            params = self._params()
            if params:
                rpp += " - params: " + ", ".join(sorted(params.keys())) + "\n"
            if request.files:
                rpp += " - files: " + ", ".join(sorted(request.files.keys())) + "\n"
            if not params and not request.files:
                rpp += " - no params, no files\n"
            rpp += f"\t{r.method} {r.path} HTTP/?\n\t" + \
                "\n\t".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n"
            log.debug(rpp)

    def _auth_reset_user(self):
        """Before request hook to cleanup authentication and authorization."""
        self._local.start = dt.datetime.timestamp(dt.datetime.now())
        # whether some routing has occurred, vs a before_request generated response
        self._local.routed = False
        # authentication and authorizations
        self._local.source = None              # what authn has been used
        self._local.user = None                # for this user
        self._local.need_authorization = True  # whether some authz occurred
        self._local.auth = self._auth          # allowed authn schemes
        self._local.realm = self._realm        # authn realm
        self._local.scopes = None              # current oauth scopes
        # parameters
        self._local.params = None              # json|http

    def _run_before_requests(self):
        """Run internal before request hooks."""
        for fun in self._before_requests:
            rep = fun(request)
            if rep is not None:
                return rep

    def _run_after_requests(self, res: Response):
        """Run internal after request hooks."""
        for fun in self._after_requests:
            res = fun(res)
        return res

    def _auth_post_check(self, res: Response):
        """After request hook to detect missing authorizations."""
        if not hasattr(self._local, "routed"):  # pragma: no cover
            # may be triggered by an early return from a before_request hook?
            log.warn(f"external response on {request.method} {request.path}")
            return res
        if self._local.routed and res.status_code < 400 and self._local.need_authorization:  # pragma: no cover
            # this case is really detected when building the app
            method, path = request.method, request.path
            if not (self._cors and method == "OPTIONS"):
                log.error(f"missing authorization on {method} {path}")
                return self._Res("missing authorization check", self._server_error)
        return res

    def _possible_redirect(self, res: Response):
        """After request hook to turn a 401 into a redirect."""
        if res.status_code == 401 and self._401_redirect:
            location = self._401_redirect
            # allow to come back later in some cases
            if self._url_name and request.method == "GET":
                import urllib

                sep = "&" if "?" in self._url_name else "?"
                location += sep + urllib.parse.urlencode({self._url_name: request.url})
            return redirect(location, 307)
        return res

    def _set_auth_cookie(self, res: Response):
        """After request hook to set a cookie if needed and none was sent."""
        # NOTE thanks to max_age the client should not send stale cookies
        if self._carrier == "cookie":
            assert self._token and self._name
            if self._local.user and self._can_create_token():
                if self._name in request.cookies and self._renewal:
                    # renew token when closing expiration
                    user, exp, _ = self._get_any_token_auth_exp(request.cookies[self._name], self._local.realm)
                    limit = dt.datetime.now(dt.timezone.utc) + \
                        self._renewal * dt.timedelta(minutes=self._delay)
                    set_cookie = exp < limit
                else:  # no cookie, set it
                    set_cookie = True
                if set_cookie:
                    # path? other parameters?
                    res.set_cookie(self._name, self.create_token(self._local.user),
                                   max_age=int(60 * self._delay))
        return res

    def _set_www_authenticate(self, res: Response):
        """Set WWW-Authenticate response header depending on current scheme."""
        if res.status_code == 401:
            schemes = set()
            for a in self._local.auth:
                if a in ("token", "oauth") and self._carrier == "bearer":
                    schemes.add(f'{self._name} realm="{self._local.realm}"')
                elif a in ("basic", "password"):
                    schemes.add(f'Basic realm="{self._local.realm}"')
                elif a in ("http-token", "http-basic", "digest", "http-digest"):
                    assert self._http_auth
                    schemes.add(self._http_auth.authenticate_header())
                # else: scheme does not rely on WWW-Authenticate…
            if schemes:
                res.headers["WWW-Authenticate"] = ", ".join(sorted(schemes))
        # else: no need for WWW-Authenticate
        return res

    def _add_headers(self, res: Response):
        """Add arbitrary headers to response."""
        for name, value in self._headers.items():
            val = value(res) if callable(value) else value
            if val:
                res.headers[name] = val
        return res

    def _add_fsa_headers(self, res: Response):
        """Add convenient FSA-related headers."""
        res.headers["FSA-Request"] = f"{request.method} {request.path}"
        res.headers["FSA-User"] = f"{self.current_user()} ({self._local.source})"
        delay = dt.datetime.timestamp(dt.datetime.now()) - self._local.start
        res.headers["FSA-Delay"] = f"{delay:.6f}"
        return res

    def _show_response(self, res: Response):
        """Show response."""
        if self._mode >= Mode.DEBUG4:
            # FIXME there is no decent response prettyprinter
            r = res
            rpp = (f"{r}\n\tHTTP/? {r.status}\n\t" +
                   "\n\t".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n")
            log.debug(rpp)
        return res

    def _params(self):
        """Get request parameters wherever they are."""
        if request.is_json:
            self._local.params = "json"
            return request.json
        else:
            self._local.params = "http"

            # reimplement "request.values" after Flask 2.0 regression
            # the logic of web-targetted HTTP does not make sense for a REST API
            # https://github.com/pallets/werkzeug/pull/2037
            # https://github.com/pallets/flask/issues/4120
            from werkzeug.datastructures import CombinedMultiDict, MultiDict

            return CombinedMultiDict([MultiDict(d) if not isinstance(d, MultiDict) else d
                                      for d in (request.args, request.form)])

    #
    # REGISTER HOOKS
    #
    def get_user_pass(self, gup: GetUserPassFun):
        """Set `get_user_pass` helper, can be used as a decorator."""
        if self._get_user_pass:
            log.warning("overriding already defined get_user_pass hook")
        self._get_user_pass = gup
        self._init_password_manager()
        return gup

    def user_in_group(self, uig: UserInGroupFun):
        """Set `user_in_group` helper, can be used as a decorator."""
        if self._user_in_group:
            log.warning("overriding already defined user_in_group hook")
        self._user_in_group = uig
        return uig

    def password_quality(self, pqc: PasswordQualityFun):
        """Set `password_quality` hook."""
        if self._password_quality:
            log.warning("overriding already defined password_quality hook")
        self._password_quality = pqc
        return pqc

    def password_check(self, pwc: PasswordCheckFun):
        """Set `password_check` hook."""
        if self._password_check:
            log.warning("overriding already defined password_check hook")
        self._password_check = pwc
        return pwc

    def error_response(self, erh: ErrorResponseFun):
        """Set `error_response` hook."""
        if self._error_response:
            log.warning("overriding already defined error_response hook")
        self._error_response = erh
        return erh

    def _store(self, store: dict[Any, Any], what: str, key: Any, val: Callable|None = None):
        """Add a function associated to something in a dict."""
        if self._mode >= Mode.DEBUG2:
            log.debug(f"registering {what} for {key} ({val})")
        if key in store:
            log.warning(f"overriding {what} function for {key}")
        if val:  # direct
            store[key] = val
        else:

            def decorate(fun: Callable):
                store[key] = fun
                return fun

            return decorate

    def cast(self, t, cast: CastFun = None):
        """Add a cast function associated to a type."""
        return self._store(self._casts, "type casting", t, cast)

    def special_parameter(self, t, sp: SpecialParameterFun = None):
        """Add a special parameter type."""
        return self._store(self._special_parameters, "special parameter", t, sp)

    def object_perms(self, domain: str, checker: ObjectPermsFun = None):
        """Add an object permission helper for a given domain."""
        return self._store(self._object_perms, "object permission checker", domain, checker)

    def _check_object_perms(self, user, domain, oid, mode):
        """Can user access object oid in domain for mode, cached."""
        assert domain in self._object_perms
        return self._object_perms[domain](user, oid, mode)

    def user_scope(self, scope):
        """Is scope in the current user scope."""
        return self._local.scopes and scope in self._local.scopes

    def add_group(self, *groups):
        """Add some groups."""
        for grp in groups:
            self._groups.add(grp)

    def add_scope(self, *scopes):
        """Add some scopes."""
        for scope in scopes:
            self._scopes.add(scope)

    def add_headers(self, **kwargs):
        """Add some headers."""
        for k, v in kwargs.items():
            self._store(self._headers, "header", k, v)

    def before_exec(self, hook: BeforeExecFun):
        """Add an after auth hook."""
        self._before_exec_hooks.append(hook)

    #
    # DEFERRED INITIALIZATIONS
    #
    def initialize(self):
        """Run late initialization on current app."""
        if not self._initialized:
            self._init_app()

    def _init_app(self) -> None:
        """Initialize extension with a Flask application.

        The initialization is performed through `FSA_*` configuration
        directives.
        """
        log.info("FSA initialization…")
        assert self._app
        conf = self._app.config
        # running mode
        if "FSA_DEBUG" in conf and conf["FSA_DEBUG"]:  # upward compatibility
            self._mode = Mode.DEBUG
            del conf["FSA_DEBUG"]
        if self._mode and self._mode >= Mode.DEBUG and "FSA_MODE" in conf:
            log.warning("ignoring FSA_MODE because already in debug mode")
        else:
            mode = conf.get("FSA_MODE", _DEFAULT_MODE)
            if mode in _MODES:
                self._mode = _MODES[mode]
            else:
                raise self._Bad(f"unexpected FSA_MODE value: {mode}")
        if self._mode >= Mode.DEBUG:
            log.warning("FlaskSimpleAuth running in debug mode")
            log.setLevel(logging.DEBUG)
            if "FSA_LOGGING_LEVEL" in conf:
                log.warning("ignoring FSA_LOGGING_LEVEL because already in debug mode")
        elif "FSA_LOGGING_LEVEL" in conf:
            log.setLevel(conf["FSA_LOGGING_LEVEL"])
        # check directives for typos
        for name in conf:
            if name.startswith("FSA_") and name not in _DIRECTIVES:
                log.warning(f"unexpected directive, ignored: {name}")
        # set self._local internal holder
        local = conf.get("FSA_LOCAL", "thread")
        if local == "process":
            class Local(object):  # type: ignore
                pass
        elif local == "thread":
            from threading import local as Local  # type: ignore
        elif local == "werkzeug":
            # FIXME should handle various *let stuff
            from werkzeug.local import Local  # type: ignore
        else:
            raise self._Bad(f"unexpected FSA_LOCAL value: {local}")
        self._local = Local()
        # whether to only allow secure requests
        self._secure = conf.get("FSA_SECURE", True)
        if not self._secure:
            log.warning("not secure: non local http queries are accepted")
        # status code for some errors errors
        self._server_error = conf.get("FSA_SERVER_ERROR", _DEFAULT_SERVER_ERROR)
        self._not_found_error = conf.get("FSA_NOT_FOUND_ERROR", _DEFAULT_NOT_FOUND_ERROR)
        # error response generation
        if conf.get("FSA_HANDLE_ALL_ERRORS", True):
            # take responsability for handling errors
            self._app.register_error_handler(exceptions.HTTPException, lambda e: self._Res(e.description, e.code))
        # override FSA internal error handling user errors
        self._keep_user_errors = conf.get("FSA_KEEP_USER_ERRORS", False)
        # how to generate an error response
        if self._error_response is None:
            error = conf.get("FSA_ERROR_RESPONSE", _DEFAULT_ERROR_RESPONSE)
            if error is None:
                pass
            elif callable(error):
                self._error_response = error
            elif not isinstance(error, str):
                pass
            elif error == "plain":
                self._error_response = lambda m, c: Response(m, c, content_type="text/plain")
            elif error == "json":
                self._error_response = lambda m, c: Response(json.dumps(m), c, content_type="application/json")
            elif error.startswith("json:"):
                key = error.split(":", 1)[1]
                self._error_response = lambda m, c: Response(json.dumps({key: m}), c, content_type="application/json")
            if self._error_response is None:
                raise self._Bad(f"unexpected FSA_ERROR_RESPONSE value: {error}")
        elif "FSA_ERROR_RESPONSE" in conf:
            log.warning("ignoring FSA_ERROR_RESPONSE directive, handler already set")
        # whether to error on unexpected parameters
        self._reject_param = \
            conf.get("FSA_REJECT_UNEXPECTED_PARAM", _DEFAULT_REJECT_UNEXPECTED_PARAM)
        #
        # overall authn setup
        #
        auth = conf.get("FSA_AUTH", None)
        if not auth:
            self._auth = ["httpd"]
        elif isinstance(auth, str):
            if auth not in ("oauth", "token", "http-token"):
                self._auth = ["token", auth]
            else:
                self._auth = [auth]
        elif isinstance(auth, list):  # keep the provided list, whatever
            self._auth = auth
        else:
            raise self._Bad(f"unexpected FSA_AUTH type: {type(auth)}")
        # needed for _auth_has used below once for flask_httpauth initialization
        self._local.auth = self._auth  # type: ignore
        #
        # authorize
        #
        self._groups.update(conf.get("FSA_AUTHZ_GROUPS", []))
        self._scopes.update(conf.get("FSA_AUTHZ_SCOPES", []))
        #
        # web apps…
        #
        self._cors: bool = conf.get("FSA_CORS", False)
        self._cors_opts: dict[str, Any] = conf.get("FSA_CORS_OPTS", {})
        if self._cors:
            try:
                from flask_cors import CORS  # type: ignore
            except ModuleNotFoundError:  # pragma: no cover
                log.error("missing module: install FlaskSimpleAuth[cors]")
                raise
            CORS(self._app, **self._cors_opts)
        self._401_redirect: str|None = conf.get("FSA_401_REDIRECT", None)
        self._url_name: str|None = conf.get("FSA_URL_NAME", "URL" if self._401_redirect else None)
        #
        # cache management for passwords, permissions, tokens…
        #
        self._cache_opts: dict[str, Any] = conf.get("FSA_CACHE_OPTS", {})
        cache = conf.get("FSA_CACHE", _DEFAULT_CACHE)
        if cache:
            # NOTE no try/except because the dependency is mandatory
            import cachetools as ct
            import CacheToolsUtils as ctu  # type: ignore

            prefix = conf.get("FSA_CACHE_PREFIX", None)
            if cache in ("ttl", "lru", "lfu", "mru", "fifo", "rr", "dict"):
                maxsize = conf.get("FSA_CACHE_SIZE", _DEFAULT_CACHE_SIZE)
                # build actual storage tier
                if cache == "ttl":
                    ttl = self._cache_opts.pop("ttl", _DEFAULT_CACHE_TTL)
                    rcache: MutableMapping = ct.TTLCache(maxsize, **self._cache_opts, ttl=ttl)
                elif cache == "lru":
                    rcache = ct.LRUCache(maxsize, **self._cache_opts)
                elif cache == "lfu":
                    rcache = ct.LFUCache(maxsize, **self._cache_opts)
                elif cache == "mru":
                    rcache = ct.MRUCache(maxsize, **self._cache_opts)
                elif cache == "fifo":
                    rcache = ct.FIFOCache(maxsize, **self._cache_opts)
                elif cache == "rr":
                    rcache = ct.RRCache(maxsize, **self._cache_opts)
                elif cache == "dict":
                    rcache = dict()
                else:  # pragma: no cover
                    raise self._Bad(f"unexpected simple cache type: {cache}")
                if prefix:
                    rcache = ctu.PrefixedCache(rcache, prefix)
                self._cache = ctu.StatsCache(rcache)
                self._gen_cache = ctu.PrefixedCache
            elif cache in ("memcached", "pymemcache"):
                try:
                    import pymemcache as pmc  # type: ignore
                except ModuleNotFoundError:  # pragma: no cover
                    log.error("missing module: install FlaskSimpleAuth[memcached]")
                    raise

                if "serde" not in self._cache_opts:
                    self._cache_opts.update(serde=ctu.JsonSerde())
                if prefix and "key_prefix" not in self._cache_opts:
                    self._cache_opts.update(key_prefix=prefix.encode("utf-8"))
                self._cache = ctu.StatsMemCached(pmc.Client(**self._cache_opts))
                self._gen_cache = ctu.PrefixedMemCached
            elif cache == "redis":
                try:
                    import redis
                except ModuleNotFoundError:  # pragma: no cover
                    log.error("missing module: install FlaskSimpleAuth[redis]")
                    raise

                ttl = self._cache_opts.pop("ttl", _DEFAULT_CACHE_TTL)
                rc = redis.Redis(**self._cache_opts)
                if prefix:
                    self._cache = ctu.PrefixedRedisCache(rc, prefix=prefix, ttl=ttl)
                else:
                    self._cache = ctu.RedisCache(rc, ttl=ttl)
                self._gen_cache = ctu.PrefixedRedisCache
            else:
                raise self._Bad(f"unexpected FSA_CACHE: {cache}")
        #
        # token setup
        #
        self._token: str = conf.get("FSA_TOKEN_TYPE", "fsa")
        if self._token not in (None, "fsa", "jwt"):
            raise self._Bad(f"unexpected FSA_TOKEN_TYPE: {self._token}")
        # token carrier
        need_carrier = self._token is not None
        self._carrier: str|None = conf.get("FSA_TOKEN_CARRIER", "bearer" if need_carrier else None)
        if self._carrier not in (None, "bearer", "param", "cookie", "header"):
            raise self._Bad(f"unexpected FSA_TOKEN_CARRIER: {self._carrier}")
        # sanity checks
        if need_carrier and not self._carrier:
            raise self._Bad(f"Token type {self._token} requires a carrier")
        # name of token for cookie or param, Authentication scheme, or other header
        default_name: str|None = (
            "AUTH" if self._carrier == "param" else
            "auth" if self._carrier == "cookie" else
            "Bearer" if self._carrier == "bearer" else
            "Auth" if self._carrier == "header" else
            None)
        self._name: str|None = conf.get("FSA_TOKEN_NAME", default_name)
        if need_carrier and not self._name:
            raise self._Bad(f"Token carrier {self._carrier} requires a name")
        if self._carrier == "param":
            assert isinstance(self._name, str)
        # token realm and possible issuer…
        realm = conf.get("FSA_REALM", self._app.name)
        if self._token == "fsa":  # simplify realm for fsa
            keep_char = re.compile(r"[-A-Za-z0-9]").match
            realm = "".join(c if keep_char(c) else "-" for c in realm)
            realm = "-".join(filter(lambda s: s != "", realm.split("-")))
        self._realm: str = realm
        self._issuer: str|None = conf.get("FSA_TOKEN_ISSUER", None)
        # token expiration in minutes
        self._delay: float = conf.get("FSA_TOKEN_DELAY", 60.0)
        self._grace: float = conf.get("FSA_TOKEN_GRACE", 0.0)
        self._renewal: float = conf.get("FSA_TOKEN_RENEWAL", 0.0)  # ratio of delay, only for cookies
        # token signature
        if "FSA_TOKEN_SECRET" in conf:
            self._secret: str = conf["FSA_TOKEN_SECRET"]
            if self._secret and len(self._secret) < 16:
                log.warning("token secret is short")
        else:
            import random
            import string

            log.warning("random token secret, only ok for one process app")
            # list of 94 chars, about 6.5 bits per char, 40 chars => 260 bits
            chars = string.ascii_letters + string.digits + string.punctuation
            self._secret = "".join(random.SystemRandom().choices(chars, k=40))
        if not self._token:  # pragma: no cover
            pass
        elif self._token == "fsa":
            self._sign: str|None = self._secret
            self._algo: str = conf.get("FSA_TOKEN_ALGO", "blake2s")
            self._siglen: int = conf.get("FSA_TOKEN_LENGTH", 16)
            if "FSA_TOKEN_SIGN" in conf:
                log.warning("ignoring FSA_TOKEN_SIGN directive for fsa tokens")
        elif self._token == "jwt":
            if "FSA_TOKEN_LENGTH" in conf:
                log.warning("ignoring FSA_TOKEN_LENGTH directive for jwt tokens")
            algo = conf.get("FSA_TOKEN_ALGO", "HS256")
            self._algo = algo
            if algo[0] in ("R", "E", "P"):
                self._sign = conf.get("FSA_TOKEN_SIGN", None)
                if not self._sign:
                    log.warning("cannot sign JWT token, assuming a third party provider")
            elif algo[0] == "H":
                self._sign = self._secret
            elif algo == "none":
                self._sign = None
            else:
                raise self._Bad(f"unexpected jwt FSA_TOKEN_ALGO ({algo})")
            self._siglen = 0
        else:  # pragma: no cover
            raise self._Bad(f"invalid FSA_TOKEN_TYPE ({self._token})")
        if "oauth" in self._auth:  # JWT authorizations (RFC 8693)
            if self._token != "jwt":
                raise self._Bad("oauth token authorizations require JWT")
            if not self._issuer:
                raise self._Bad("oauth token authorizations require FSA_TOKEN_ISSUER")
        #
        # HTTP parameter names
        #
        if "fake" not in self._auth and "FSA_FAKE_LOGIN" in conf:
            log.warning("ignoring directive FSA_FAKE_LOGIN")
        if "param" not in self._auth and "password" not in self._auth:
            if "FSA_PARAM_USER" in conf:
                log.warning("ignoring directive FSA_PARAM_USER")
            if "FSA_PARAM_PASS" in conf:
                log.warning("ignoring directive FSA_PARAM_PASS")
        self._login = conf.get("FSA_FAKE_LOGIN", "LOGIN")
        self._userp = conf.get("FSA_PARAM_USER", "USER")
        self._passp = conf.get("FSA_PARAM_PASS", "PASS")
        #
        # authentication checks are delayed here because we may need params
        #
        for a in self._auth:
            if a not in self._FSA_AUTH:
                raise self._Bad(f"unexpected auth: {a}")
            self._add_auth(a)
        #
        # authentication and authorization hooks
        #
        if "FSA_GET_USER_PASS" in conf:
            self.get_user_pass(conf["FSA_GET_USER_PASS"])
        if "FSA_USER_IN_GROUP" in conf:
            self.user_in_group(conf["FSA_USER_IN_GROUP"])

        def _set_hooks(directive: str, set_hook: Callable[[Any, Callable], Any]):
            if directive in conf:
                hooks = conf[directive]
                if not isinstance(hooks, dict):
                    raise self._Bad(f"{directive} must be a dict")
                for key, val in hooks.items():
                    set_hook(key, val)

        _set_hooks("FSA_CAST", self.cast)
        _set_hooks("FSA_OBJECT_PERMS", self.object_perms)
        _set_hooks("FSA_SPECIAL_PARAMETER", self.special_parameter)
        #
        # http auth setup
        #
        if self._auth_has("http-basic", "http-digest", "http-token", "digest"):
            opts = conf.get("FSA_HTTP_AUTH_OPTS", {})
            try:
                import flask_httpauth as fha  # type: ignore
            except ModuleNotFoundError:  # pragma: no cover
                log.error("missing module: install FlaskSimpleAuth[httpauth]")
                raise

            if "http-basic" in self._auth:
                self._http_auth = fha.HTTPBasicAuth(realm=self._realm, **opts)
                assert self._http_auth is not None  # for pleasing mypy
                self._http_auth.verify_password(self._check_password)
            elif self._auth_has("http-digest", "digest"):
                self._http_auth = fha.HTTPDigestAuth(realm=self._realm, **opts)
                assert self._http_auth is not None  # for pleasing mypy
                # FIXME? nonce & opaque callbacks? session??
            elif "http-token" in self._auth:
                # NOTE incompatible with local realm
                if self._carrier == "header" and "header" not in opts and self._name:
                    opts["header"] = self._name
                self._http_auth = fha.HTTPTokenAuth(scheme=self._name, realm=self._realm, **opts)
                assert self._http_auth is not None  # for pleasing mypy
                self._http_auth.verify_token(lambda t: self._get_any_token_auth(t, self._realm))
            assert self._http_auth is not None  # for pleasing mypy
            self._http_auth.get_password(self._get_user_pass)
            # FIXME? error_handler?
        else:
            self._http_auth = None
        # headers
        self._headers.update(conf.get("FSA_ADD_HEADERS", {}))
        #
        # request hooks: before request executed in order, after in reverse
        # (some before hooks are registered in __init__)
        #
        self._before_requests = conf.get("FSA_BEFORE_REQUEST", [])
        self._before_exec_hooks += conf.get("FSA_BEFORE_EXEC", [])
        # internal hooks
        if self._mode >= Mode.DEBUG4:
            self._app.after_request(self._show_response)
        if self._mode >= Mode.DEV:
            self._app.after_request(self._add_fsa_headers)
        self._after_requests = conf.get("FSA_AFTER_REQUEST", [])
        if self._after_requests:
            self._app.after_request(self._run_after_requests)
        if self._headers:
            self._app.after_request(self._add_headers)
        self._app.after_request(self._set_www_authenticate)  # always for auth=…
        if self._carrier == "cookie":
            self._app.after_request(self._set_auth_cookie)
        if self._401_redirect:
            self._app.after_request(self._possible_redirect)
        self._app.after_request(self._auth_post_check)
        #
        # blueprint hacks
        #
        self.blueprints = self._app.blueprints
        self.debug = False
        if hasattr(self._app, "_check_setup_finished"):
            # Flask 2.2
            self._check_setup_finished = self._app._check_setup_finished
            self.before_request_funcs = self._app.before_request_funcs
            self.after_request_funcs = self._app.after_request_funcs
            self.teardown_request_funcs = self._app.teardown_request_funcs
            self.url_default_functions = self._app.url_default_functions
            self.url_value_preprocessors = self._app.url_value_preprocessors
            self.template_context_processors = self._app.template_context_processors
        else:  # pragma: no cover
            raise self._Bad("unexpected Flask version while dealing with blueprints?")
        #
        # caches
        #
        self._set_caches()
        # done!
        self._initialized = True

    def _add_auth(self, auth: str):
        """Register that an authentication method is used."""
        if not isinstance(auth, str):  # pragma: no cover
            self._Bad(f"unexpected authentication identifier type: {type(auth)}")
        if auth in self._all_auth:
            return
        self._all_auth.add(auth)
        # possibly add parameters to ignore silently
        if auth in ("param", "password"):
            self._auth_params.add(self._userp)
            self._auth_params.add(self._passp)
        if auth == "fake":
            self._auth_params.add(self._login)
        if auth == "token" and self._carrier == "param":
            assert isinstance(self._name, str)
            self._auth_params.add(self._name)

    def _init_password_manager(self) -> None:
        """Deferred password manager initialization."""
        assert self._app
        conf = self._app.config
        self._password_check = conf.get("FSA_PASSWORD_CHECK", self._password_check)
        # FIXME add _password_hash?
        self._password_len: int = conf.get("FSA_PASSWORD_LEN", 0)
        self._password_re: list[PasswordQualityFun] = [
            re.compile(r).search for r in conf.get("FSA_PASSWORD_RE", [])
        ]
        self._password_quality = \
            conf.get("FSA_PASSWORD_QUALITY", self._password_quality)
        # only actually initialize with passlib if needed
        scheme = conf.get("FSA_PASSWORD_SCHEME", _DEFAULT_PASSWORD_SCHEME)
        log.info(f"initializing password manager with {scheme}")
        if scheme:
            if scheme == "plaintext":
                log.warning("plaintext password manager is a bad idea")
            # passlib context is a pain, you have to know the scheme name to set its
            # round. Ident "2y" is same as "2b" but apache compatible.
            options = conf.get("FSA_PASSWORD_OPTS", _DEFAULT_PASSWORD_OPTS)
            try:
                from passlib.context import CryptContext  # type: ignore
            except ModuleNotFoundError:  # pragma: no cover
                log.error("missing module: install FlaskSimpleAuth[passwords]")
                raise

            self._pm = CryptContext(schemes=[scheme], **options)

    #
    # INHERITED HTTP AUTH
    #
    def _get_httpd_auth(self) -> str|None:
        """Inherit HTTP server authentication."""
        return request.remote_user

    #
    # HTTP FAKE AUTH
    #
    # Just trust a parameter, *only* for local testing.
    #
    # FSA_FAKE_LOGIN: name of parameter holding the login ("LOGIN")
    #
    def _get_fake_auth(self):
        """Return fake user. Only for local tests."""
        assert request.remote_addr.startswith("127.") or request.remote_addr == "::1", \
            "fake auth only on localhost"
        params = self._params()
        user = params.get(self._login, None)
        if not user:
            raise self._Err(f"missing fake login parameter: {self._login}", 401)
        return user

    #
    # PASSWORD MANAGEMENT
    #
    # FSA_PASSWORD_SCHEME: name of password scheme for passlib context
    # FSA_PASSWORD_OPTS: further options for passlib context
    # FSA_PASSWORD_LEN: minimal length of provided passwords
    # FSA_PASSWORD_RE: list of re a password must match
    # FSA_PASSWORD_QUALITY: hook for password strength check
    # FSA_PASSWORD_CHECK: hook for alternate password check
    #
    # NOTE passlib bcrypt is Apache compatible
    # NOTE about caching: if password checks are cached, this would
    #      mean that the clear text password is stored in cache, which
    #      is a VERY BAD IDEA because consulting the cache would give
    #      access to said passwords. Thus `check_password`, `hash_password`
    #      `_check_password`, `_password_check` and `_check_with_password_hook`
    #      should not be cached, ever, even if expensive.
    #      Make good use of tokens to reduce password check costs.

    def check_password(self, pwd, ref):
        """Verify whether a password is correct compared to a reference (eg salted hash)."""
        if not self._pm:
            self._init_password_manager()
        return self._pm.verify(pwd, ref)

    def _check_password_quality(self, pwd):
        """Check password quality, raising issues or proceeding."""
        if len(pwd) < self._password_len:
            raise self._Err(f"password is too short, must be at least {self._password_len}", 400)
        for search in self._password_re:
            if not search(pwd):
                raise self._Err(f"password must match {search.__self__.pattern}", 400)
        if self._password_quality:
            try:
                if not self._password_quality(pwd):
                    raise self._Err("password quality too low", 400)
            except Exception as e:
                raise self._Err(f"password quality too low: {e}", 400, e)

    def hash_password(self, pwd, check=True):
        """Hash password according to the current password scheme."""
        if not self._pm:
            self._init_password_manager()
        if check:
            self._check_password_quality(pwd)
        return self._pm.hash(pwd)

    def _check_with_password_hook(self, user, pwd):
        """Check user/password with external hook."""
        if self._password_check:
            try:
                return self._password_check(user, pwd)
            except ErrorResponse as e:
                raise e
            except Exception as e:
                log.info(f"AUTH (hook) failed: {e}")
                if self._Exc(e):  # pragma: no cover
                    raise
                return False
        return False

    def _check_password(self, user, pwd):
        """Check user/password against internal or external credentials.

        Raise an exception if not ok, otherwise simply return the user."""
        # first, get user password hash if available
        if self._get_user_pass:
            try:
                ref = self._get_user_pass(user)
            except ErrorResponse as e:
                raise e
            except Exception as e:
                log.error(f"get_user_pass failed: {e}")
                raise self._Err("internal error in get_user_pass", self._server_error, e)
        else:
            ref = None
        if not ref:  # not available, try alternate check
            if not self._check_with_password_hook(user, pwd):
                if self._get_user_pass:
                    log.debug(f"AUTH (password): no such user ({user})")
                    raise self._Err(f"no such user: {user}", 401)
                else:
                    log.debug(f"AUTH (password): invalid user/password ({user})")
                    raise self._Err(f"invalid user/password for {user}", 401)
            # else OK because of alternate hook
        elif not isinstance(ref, (str, bytes)):  # do a type check in passing
            log.error(f"type error in get_user_pass: {type(ref)} on {user}, expecting None, str or bytes")
            raise self._Err("internal error with get_user_pass", self._server_error)
        elif not self.check_password(pwd, ref):  # does not match, try alternate check
            if not self._check_with_password_hook(user, pwd):
                log.debug(f"AUTH (password): invalid password ({user})")
                raise self._Err(f"invalid password for {user}", 401)
            # else ok because of alternate hook
        return user

    #
    # FLASK HTTP AUTH (BASIC, DIGEST, TOKEN)
    #
    def _get_httpauth(self):
        """Delegate user authentication to HTTPAuth."""
        assert self._http_auth
        auth = self._http_auth.get_auth()
        password = self._http_auth.get_auth_password(auth) if "http-token" not in self._local.auth else None
        try:
            # NOTE "authenticate" signature is not very clean…
            user = self._http_auth.authenticate(auth, password)
            if user is not None and user is not False:
                return auth.username if user is True else user
        except ErrorResponse as e:
            log.debug(f"AUTH (http-*): bad authentication {e}")
            raise e
        log.debug("AUTH (http-*): bad authentication")
        raise self._Err("failed HTTP authentication", 401)

    #
    # HTTP BASIC AUTH
    #
    def _get_basic_auth(self):
        """Get user with basic authentication."""
        auth = request.headers.get("Authorization", None)
        if not auth:
            log.debug("AUTH (basic): missing Authorization header")
            raise self._Err("missing authorization header", 401)
        if not auth.startswith("Basic "):
            log.debug(f'AUTH (basic): unexpected auth "{auth}"')
            raise self._Err("unexpected Authorization header", 401)
        try:
            import base64 as b64
            user, pwd = b64.b64decode(auth[6:]).decode().split(":", 1)
        except Exception as e:
            log.debug(f'AUTH (basic): error while decoding auth "{auth}" ({e})')
            raise self._Err("decoding error on authorization header", 401, e)
        return self._check_password(user, pwd)

    #
    # HTTP PARAM AUTH
    #
    # User credentials provided from http or json parameters.
    #
    # FSA_PARAM_USER: parameter name for login ("USER")
    # FSA_PARAM_PASS: parameter name for password ("PASS")
    #
    def _get_param_auth(self):
        """Get user with parameter authentication."""
        params = self._params()
        user = params.get(self._userp, None)
        if not user:
            raise self._Err(f"missing param login parameter: {self._userp}", 401)
        pwd = params.get(self._passp, None)
        if not pwd:
            raise self._Err(f"missing param password parameter: {self._passp}", 401)
        return self._check_password(user, pwd)

    #
    # HTTP BASIC OR PARAM AUTH
    #
    def _get_password_auth(self):
        """Get user from basic or param authentication."""
        try:
            return self._get_basic_auth()
        except ErrorResponse:  # failed, let's try param
            return self._get_param_auth()

    #
    # TOKEN AUTH
    #
    # The token can be checked locally with a simple hash, without querying the
    # database and validating a possibly expensive salted password (+400 ms!).
    #
    #
    # FSA_TOKEN_TYPE: 'jwt', 'fsa' or None to disactivate
    # - for 'fsa': format is <realm>:<user>:<validity-limit>:<signature>
    # FSA_TOKEN_CARRIER: 'param', 'header' or 'bearer'
    # FSA_TOKEN_NAME: name of parameter/cookie/scheme holding the token
    # FSA_TOKEN_ALGO:
    # - for 'fsa': hashlib algorithm for token authentication ("blake2s")
    # - for 'jwt': signature algorithm ("HS256")
    # FSA_TOKEN_LENGTH:
    # - for 'fsa': number of signature bytes (16)
    # - for 'jwt': unused
    # FSA_TOKEN_SECRET: signature secret for verifying tokens (mandatory!)
    # FSA_TOKEN_SIGN: secret for signing new tokens for jwt pubkey algorithms
    # FSA_TOKEN_DELAY: token validity in minutes (60)
    # FSA_TOKEN_GRACE: grace delay for token validity in minutes (0)
    # FSA_TOKEN_RENEWAL: fraction of delay for automatic renewal (0.0)
    # FSA_TOKEN_ISSUER: token issuer (None)
    # FSA_REALM: realm (lc simplified app name)
    #
    def _cmp_sig(self, data, secret):
        """Compute signature for data."""
        import hashlib

        h = hashlib.new(self._algo)
        h.update(f"{data}:{secret}".encode())
        return h.digest()[: self._siglen].hex()

    def _to_timestamp(self, ts):
        """Build a simplistic timestamp string."""
        # this is shorter than an iso format timestamp
        return "%04d%02d%02d%02d%02d%02d" % ts.timetuple()[:6]

    def _from_timestamp(self, ts):
        """Parses a simplistic timestamp string."""
        p = re.match(r"^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$", ts)
        if not p:
            raise self._Err(f"unexpected timestamp format: {ts}", 400)
        return dt.datetime(*[int(p[i]) for i in range(1, 7)], tzinfo=dt.timezone.utc)

    def _get_fsa_token(self, realm, issuer, user, delay, secret):
        """Compute a signed token for "user" valid for "delay" minutes."""
        limit = self._to_timestamp(dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=delay))
        data = f"{realm}/{issuer}:{user}:{limit}" if issuer else f"{realm}:{user}:{limit}"
        sig = self._cmp_sig(data, secret)
        return f"{data}:{sig}"

    def _get_jwt_token(self, realm: str, issuer: str|None, user, delay: float,
                       secret, scope: list[str]|None = None):
        """Json Web Token (JWT) generation.

        - exp: expiration
        - sub: subject (the user)
        - iss: issuer (the source)
        - aud : audience (the realm)
        - not used: iat (issued at), nbf (not before), jti (jtw id)
        - scope: optional authorizations
        """
        try:
            import jwt
        except ModuleNotFoundError:  # pragma: no cover
            log.error("missing module: install FlaskSimpleAuth[jwt]")
            raise

        exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=delay)
        token = {"exp": exp, "sub": user, "aud": realm}
        if issuer:
            token.update(iss=issuer)
        if scope:
            # NOTE Why doesn't JWT use a list there?
            token.update(scope=" ".join(scope))
        return jwt.encode(token, secret, algorithm=self._algo)

    def _can_create_token(self):
        """Whether it is possible to create a token."""
        return self._token and not (
            self._token == "jwt" and self._algo[0] in ("R", "E", "P") and not self._sign
        )

    def create_token(self, user: str = None, realm: str = None, issuer: str = None,
                     delay: float = None, secret: str = None, **kwargs):
        """Create a new token for user depending on the configuration."""
        assert self._token
        user = user or self.get_user()
        realm = realm or self._local.realm
        issuer = issuer or self._issuer
        delay = delay or self._delay
        secret = secret or (self._secret if self._token == "fsa" else self._sign)
        return (
            self._get_fsa_token(realm, issuer, user, delay, secret, **kwargs) if self._token == "fsa" else
            self._get_jwt_token(realm, issuer, user, delay, secret, **kwargs)
        )

    # internal function to check a fsa token
    def _check_fsa_token(self, token: str, realm: str, issuer: str|None, secret: str, grace: float) \
            -> tuple[str, str, list[str]|None]:
        """Check FSA token validity against a configuration."""
        # token format: "realm[/issuer]:calvin:20380119031407:<signature>"
        if token.count(":") != 3:
            if self._mode >= Mode.DEBUG:
                log.debug(f"AUTH (fsa token): unexpected token ({token})")
            raise self._Err(f"invalid fsa token: {token}", 401)
        trealm, user, slimit, sig = token.split(":", 3)
        try:
            limit = self._from_timestamp(slimit)
        except Exception as e:
            if self._mode >= Mode.DEBUG:
                log.debug(f"AUTH (fsa token): malformed timestamp {slimit} ({token}): {e}")
            raise self._Err(f"unexpected fsa token limit: {slimit} ({token})", 401, e)
        # check realm
        if issuer and trealm != f"{realm}/{issuer}" or \
           not issuer and trealm != realm:
            if self._mode >= Mode.DEBUG:
                log.debug(f"AUTH (fsa token): unexpected realm {trealm} ({token})")
            raise self._Err(f"unexpected fsa token realm: {trealm} ({token})", 401)
        # check signature
        ref = self._cmp_sig(f"{trealm}:{user}:{slimit}", secret)
        if ref != sig:
            if self._mode >= Mode.DEBUG:
                log.debug("AUTH (fsa token): invalid signature ({token})")
            raise self._Err("invalid fsa auth token signature ({token})", 401)
        # check limit with a grace time
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=self._grace)
        if now > limit:
            if self._mode >= Mode.DEBUG:
                log.debug("AUTH (fsa token): token {token} has expired ({token})")
            raise self._Err("expired fsa auth token ({token})", 401)
        return user, limit, None

    # function suitable for the internal authentication API
    def _get_fsa_token_auth(self, token: str, realm: str):
        """Tell whether FSA token is ok: return validated user or None."""
        return self._check_fsa_token(token, realm, self._issuer, self._secret, self._grace)

    def _get_jwt_token_auth(self, token: str, realm: str):
        """Tell whether JWT token is ok: return validated user or None."""
        try:
            import jwt
        except ModuleNotFoundError:  # pragma: no cover
            log.error("missing module: install FlaskSimpleAuth[jwt]")
            raise

        try:
            data = jwt.decode(token, self._secret, leeway=self._grace * 60.0,
                              audience=realm, issuer=self._issuer, algorithms=[self._algo])
            exp = dt.datetime.fromtimestamp(data["exp"], tz=dt.timezone.utc)
            scopes = data["scope"].split(" ") if "scope" in data else None
            return data["sub"], exp, scopes
        except jwt.ExpiredSignatureError:
            if self._mode >= Mode.DEBUG:
                log.debug(f"AUTH (jwt token): token has expired ({token})")
            raise self._Err(f"expired jwt auth token: {token}", 401)
        except Exception as e:
            if self._mode >= Mode.DEBUG:
                log.debug(f"AUTH (jwt token): invalid token {token}: {e}")
            raise self._Err(f"invalid jwt token: {token}", 401, e)

    # NOTE as the realm can be route-dependent, cached validations include the realm.
    def _get_any_token_auth_exp(self, token: str, realm: str):
        """Return validated user and expiration, cached."""
        return (self._get_fsa_token_auth(token, realm) if self._token == "fsa" else
                self._get_jwt_token_auth(token, realm))

    # NOTE the realm parameter is really only for testing purposes
    def _get_any_token_auth(self, token: str|None, realm: str|None = None) -> str|None:
        """Tell whether token is ok: return validated user or None, may raise 401."""
        if not token:
            raise self._Err("missing token", 401)
        user, exp, scopes = self._get_any_token_auth_exp(token, realm or self._local.realm)
        # must recheck token expiration
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=self._grace)
        if now > exp:
            if self._mode >= Mode.DEBUG:
                log.debug(f"AUTH (token): token has expired ({token})")
            raise self._Err(f"expired auth token: {token}", 401)
        self._local.scopes = scopes
        return user

    def _get_token(self) -> str|None:
        """Get authentication from token."""
        token: str|None = None
        if self._carrier == "bearer":
            auth = request.headers.get("Authorization", None)
            if auth:
                assert self._name
                slen = len(self._name) + 1
                if auth[:slen] == f"{self._name} ":  # FIXME lower case?
                    token = auth[slen:]
            # else we ignore… maybe it will be resolved later
        elif self._carrier == "cookie":
            assert self._name
            token = (request.cookies[self._name] if self._name in request.cookies else
                     None)
        elif self._carrier == "param":
            token = self._params().get(self._name, None)
        else:
            assert self._carrier == "header" and self._name
            token = request.headers.get(self._name, None)
        return token

    def _get_token_auth(self) -> str|None:
        """Authenticate with current token."""
        user = None
        if self._token:
            # this raises a missing token 401 if no token
            user = self._get_any_token_auth(self._get_token())
        return user

    # map auth types to their functions
    _FSA_AUTH: dict[str, Callable[[Any], str|None]] = {
        "none": lambda s: None,
        "httpd": _get_httpd_auth,
        "token": _get_token_auth,
        "oauth": _get_token_auth,
        "fake": _get_fake_auth,
        "basic": _get_basic_auth,
        "digest": _get_httpauth,
        "param": _get_param_auth,
        "password": _get_password_auth,
        "http-basic": _get_httpauth,
        "http-digest": _get_httpauth,
        "http-token": _get_httpauth,
    }

    def get_user(self, required=True) -> str|None:
        """Authenticate user or throw exception."""

        # safe because _user is reset before requests
        if self._local.source:
            return self._local.user

        assert self._initialized, "FlaskSimpleAuth must be initialized"

        # try authentication schemes
        lae = None
        for a in self._local.auth:
            try:
                self._local.user = self._FSA_AUTH[a](self)
                if self._local.user:
                    self._local.source = a
                    break
            except ErrorResponse as e:
                lae = e
            except Exception as e:  # pragma: no cover
                log.error(f"internal error in {a} authentication: {e}")
                self._Exc(e)

        # even if not set, we say that the answer is the right one.
        if not self._local.source:
            self._local.source = "none"

        # rethrow last auth exception on failure
        if required and not self._local.user:
            # we do not leak allowed authentication schemes
            raise lae or self._Err("missing authentication", 401)

        return self._local.user

    def current_user(self):
        """Return current authenticated user, if any."""
        return self._local.user

    # authentication and authorization methods that can/should be cached
    _CACHABLE = {
        "_get_any_token_auth_exp": "t.",
        "_get_user_pass": "u.",
        "_user_in_group": "g.",
        "_check_object_perms": "p.",
    }

    def _set_caches(self):
        """Create caches around some functions."""
        if self._gen_cache is not None and self._cache is not None:
            log.debug(f"caching: {self._CACHABLE}")
            import CacheToolsUtils as ctu

            ctu.cacheMethods(cache=self._cache, obj=self, gen=self._gen_cache, **self._CACHABLE)

    def clear_caches(self):
        """Clear internal shared cache.

        Probably a bad idea because:
        - of the performance impact
        - for a local cache in a multi-process setup, other processes are out

        The best option is to wait for cache entries to expire with a TTL.
        """
        self._cache.clear()

    #
    # INTERNAL DECORATORS
    #
    # _authenticate: set self._user
    #  _oauth_authz: check OAuth scope authorization
    #  _group_authz: check group authorization
    #     _no_authz: validate that no authorization was needed
    #   _parameters: handle HTTP/JSON/FILE to python parameter translation
    #     _noparams: just check that no parameters are passed
    #   _perm_authz: check per-object permissions
    #  _before_exec: as told
    #
    def _safe_call(self, path, level, fun, *args, **kwargs):
        """Call a route function ensuring a response whatever."""
        try:  # the actual call
            return fun(*args, **kwargs)
        except ErrorResponse as e:  # something went wrong
            return self._Res(e.message, e.status)
        except Exception as e:  # something went *really* wrong
            log.error(f"internal error on {request.method} {request.path}: {e}")
            if self._Exc(e):
                raise
            return self._Res(f"internal error caught at {level} on {path}", self._server_error)

    def _authenticate(self, path, auth=None, realm=None):
        """Decorator to authenticate current user."""
        # check auth parameter
        if auth:
            if isinstance(auth, str):
                auth = [auth]
            for a in auth:
                if a not in self._FSA_AUTH:
                    raise self._Bad(f"unexpected authentication scheme {auth} on {path}")

        def decorate(fun: Callable):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                # get user if needed
                if not self._local.source:
                    # possibly overwrite the authentication scheme
                    # NOTE this may or may not work because other settings may
                    #   not be compatible with the provided scheme…
                    if realm:
                        self._local.realm = realm
                    if auth:
                        self._local.auth = auth
                    try:
                        self.get_user()
                    except ErrorResponse as e:
                        return self._Res(e.message, e.status)

                if not self._local.user:  # pragma no cover
                    return self._Res("no auth", 401)

                return self._safe_call(path, "authenticate", fun, *args, **kwargs)

            return wrapper

        return decorate

    def _oauth_authz(self, path, *scopes):
        """Decorator to authorize OAuth scopes (token-provided authz)."""

        if self._scopes:
            for scope in scopes:
                if scope not in self._scopes:
                    raise self._Bad(f"unexpected scope {scope}")

        def decorate(fun: Callable):
            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                self._local.need_authorization = False

                for scope in scopes:
                    if not self.user_scope(scope):
                        return self._Res(f'missing permission "{scope}"', 403)

                return self._safe_call(path, "oauth authorization", fun, *args, **kwargs)

            return wrapper

        return decorate

    def _group_authz(self, path, *groups):
        """Decorator to authorize user groups."""

        for grp in _PREDEFS:
            if grp in groups:
                raise self._Bad(f"unexpected predefined {grp}")

        if self._groups:
            for grp in groups:
                if grp not in self._groups:
                    raise self._Bad(f"unexpected group {grp}")

        if not self._user_in_group:  # pragma: no cover
            raise self._Bad(f"user_in_group callback needed for group authorization on {path}")

        def decorate(fun: Callable):
            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                # track that some autorization check was performed
                self._local.need_authorization = False

                # check against all authorized groups/roles
                for grp in groups:
                    try:
                        ok = self._user_in_group(self._local.user, grp)
                    except ErrorResponse as e:
                        return self._Res(e.message, e.status)
                    except Exception as e:
                        log.error(f"user_in_group failed: {e}")
                        if self._Exc(e):  # pragma: no cover
                            raise
                        return self._Res("internal error in user_in_group", self._server_error)
                    if not isinstance(ok, bool):
                        log.error(f"type error in user_in_group: {ok}: {type(ok)}, must return a boolean")
                        return self._Res("internal error with user_in_group", self._server_error)
                    if not ok:
                        return self._Res(f'not in group "{grp}"', 403)

                # all groups are ok, proceed to call underlying function
                return self._safe_call(path, "group authorization", fun, *args, **kwargs)

            return wrapper

        return decorate

    # just to record that no authorization check was needed
    def _no_authz(self, path, *groups):
        def decorate(fun: Callable):
            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                self._local.need_authorization = False
                return self._safe_call(path, "no authorization", fun, *args, **kwargs)

            return wrapper

        return decorate

    # just check that there are no unused parameters
    def _noparams(self, path):
        def decorate(fun: Callable):
            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                if self._reject_param:
                    params = self._params()
                    if params:
                        sparams = set(params.keys())
                        if not sparams.issubset(self._auth_params):
                            bads = ' '.join(sorted(list(sparams - self._auth_params)))
                            return f"unexpected {self._local.params} parameters: {bads}", 400
                    fparams = request.files
                    if fparams:
                        return f"unexpected file parameters: {' '.join(sorted(fparams.keys()))}", 400

                return self._safe_call(path, "no params", fun, *args, **kwargs)

            return wrapper

        return decorate

    def _parameters(self, path):
        """Decorator to handle request parameters."""

        def decorate(fun: Callable):

            # for each parameter name: type, cast, default value, http param name
            types: dict[str, type] = {}
            typings: dict[str, Callable[[str], Any]] = {}
            defaults: dict[str, Any] = {}
            names: dict[str, str] = {}

            # parameters types/casts and defaults taken from signature
            sig, keywords = inspect.signature(fun), False

            where = f"{fun.__name__}() at {fun.__code__.co_filename}:{fun.__code__.co_firstlineno}"

            # build helpers
            for n, p in sig.parameters.items():
                sn = n[1:] if n[0] == "_" and len(n) > 1 else n
                names[n], names[sn] = sn, n
                if n not in types and p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL):
                    # guess and store parameter type
                    t = _typeof(p)
                    types[n] = t
                    # typings: how to actually build the parameter
                    if t in self._special_parameters:
                        # this is really managed elsewhere
                        typings[n] = t
                    elif (self._pydantic_base_model is not None and
                          isinstance(t, type) and
                          issubclass(t, self._pydantic_base_model) or
                          hasattr(t, "__dataclass_fields__")):
                        # create a convenient cast for pydantic classes or dataclasses
                        # we assume that named-parameters are passed
                        def datacast(val):
                            if isinstance(val, str):  # HTTP parameters
                                val = json.loads(val)
                            if not isinstance(val, dict):  # JSON parameters
                                raise self._Err(f"unexpected value {val} for dict", 400)
                            return t(**val)
                        typings[n] = datacast
                    else:
                        typings[n] = self._casts.get(t, t)
                    # check that type can be isinstance and is castable
                    try:
                        isinstance("", t)
                    except TypeError as e:
                        raise self._Bad(f"parameter {n} type {t} is not (yet) supported: {e}", where)
                    except Exception as e:  # pragma: no cover
                        raise self._Bad(f"parameter {n} type {t} is not (yet) supported: {e}", where)
                    if not callable(typings[n]) or typings[n].__module__ == "typing":
                        raise self._Bad(f"parameter {n} type cast {typings[n]} is not callable", where)
                if p.default != inspect._empty:
                    defaults[n] = p.default
                if p.kind == p.VAR_KEYWORD:
                    keywords = True

            # debug helpers
            def getNames(pl):
                return sorted(map(lambda n: names[n], pl))

            mandatory = getNames(filter(lambda n: n not in defaults, types.keys()))
            optional = getNames(filter(lambda n: n in defaults, types.keys()))
            signature = f"{fun.__name__}({', '.join(mandatory)}, [{', '.join(optional)}])"

            def debugParam():
                params = sorted(self._params().keys())
                files = sorted(request.files.keys())
                mtype = request.headers.get("Content-Type", "?")
                return f"{signature}: {' '.join(params)}/{' '.join(files)} [{mtype}]"

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                # NOTE *args and **kwargs are empty before being filled in from HTTP

                # translate request parameters to named function parameters
                params = self._params()  # HTTP or JSON params
                fparams = request.files  # FILE params

                # detect all possible 400 errors before returning
                error_400 = []
                e400 = error_400.append

                # process all expected "standard" parameters
                for p, tf in typings.items():
                    pn = names[p]
                    if tf in self._special_parameters:  # force specials
                        if p in params:
                            e400(f'unexpected {self._local.params} parameter "{pn}"')
                            continue
                        try:
                            kwargs[p] = self._special_parameters[tf](pn)
                        except ErrorResponse as e:
                            if e.status == 400:
                                e400(f"error when retrieving special parameter \"{pn}\": {e.message}")
                                continue
                            else:  # pragma: no cover
                                raise  # rethrow?
                        except Exception as e:
                            if self._Exc(e):  # pragma: no cover
                                raise
                            # this is some unexpected internal error
                            return self._Res(f"unexpected error when retrieving special parameter \"{pn}\" ({e})",
                                             self._server_error)
                        # other exception would pass through
                    elif p in kwargs:  # path parameter, or already seen?
                        if p in params:
                            e400(f'unexpected {self._local.params} parameter "{pn}"')
                            continue
                        val = kwargs[p]
                        if not isinstance(val, types[p]):
                            try:
                                kwargs[p] = tf(val)
                            except Exception as e:
                                if self._Exc(e):  # pragma: no cover
                                    raise
                                e400(f'type error on path parameter "{p}": "{val}" ({e})')
                                continue
                    else:  # parameter not yet encountered
                        if pn in params:
                            val = params[pn]
                            is_json = types[p] == JsonData
                            if is_json and isinstance(val, str) or \
                               not is_json and not isinstance(val, types[p]):
                                try:
                                    kwargs[p] = tf(val)
                                except Exception as e:
                                    if self._Exc(e):  # pragma: no cover
                                        raise
                                    e400(f'type error on {self._local.params} parameter "{pn}": "{val}" ({e})')
                                    continue
                            else:
                                kwargs[p] = val
                        else:  # not found anywhere, set default value if any
                            if p in defaults:
                                kwargs[p] = defaults[p]
                            else:  # missing mandatory (no default) parameter
                                if self._mode >= Mode.DEBUG2:
                                    log.info(debugParam())
                                e400(f'missing parameter "{pn}"')
                                continue

                # possibly add others, without shadowing already provided ones
                if keywords:  # handle **kwargs
                    for p in params:
                        if p not in kwargs and p not in self._auth_params:
                            kwargs[p] = params[p]  # FIXME names[p]?
                    for p in fparams:
                        if p not in kwargs and p not in self._auth_params:
                            kwargs[p] = fparams[p]  # FIXME?
                elif self._mode >= Mode.DEBUG or self._reject_param:
                    # detect unused parameters and warn or reject them
                    for p in params:
                        # NOTE we silently ignore special authentication params
                        if p not in names and p not in self._auth_params:
                            if self._mode >= Mode.DEBUG:
                                log.debug(f"unexpected {self._local.params} parameter \"{p}\"")
                                if self._mode >= Mode.DEBUG2:
                                    log.debug(debugParam())
                            if self._reject_param:
                                e400(f"unexpected {self._local.params} parameter \"{p}\"")
                                continue
                    for p in fparams:
                        if p not in names:
                            if self._mode >= Mode.DEBUG:
                                log.debug(f"unexpected file parameter \"{p}\"")
                                if self._mode >= Mode.DEBUG2:
                                    log.debug(debugParam())
                            if self._reject_param:
                                e400(f"unexpected file parameter \"{p}\"")
                                continue

                if error_400:
                    return self._Res("\n".join(error_400), 400)

                return self._safe_call(path, "parameters", fun, *args, **kwargs)

            return wrapper

        return decorate

    def _perm_authz(self, path, first, *perms):
        """Decorator for per-object permissions."""
        # check perms wrt to recorded per-object checks

        # normalize tuples length to 3
        perms = list(map(lambda a: (a + (first, None)) if len(a) == 1 else
                                   (a + (None,)) if len(a) == 2 else
                                   a, perms))

        # perm checks
        for perm in perms:
            if not len(perm) == 3:
                raise self._Bad(f"per-object permission tuples must have 3 data {perm} on {path}")
            domain, name, mode = perm
            if domain not in self._object_perms:
                raise self._Bad(f"missing object permission checker for {perm} on {path}")
            if not isinstance(name, str):
                raise self._Bad(f"unexpected identifier name type ({type(name)}) for {perm} on {path}")
            if mode is not None and type(mode) not in (int, str):
                raise self._Bad(f"unexpected mode type ({type(mode)}) for {perm} on {path}")

        def decorate(fun: Callable):

            # check perms wrt fun signature
            for domain, name, mode in perms:
                if name not in fun.__code__.co_varnames:
                    raise self._Bad(f"missing function parameter {name} for {perm} on {path}")
                # FIXME should parameter type be restricted to int or str?

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                # track that some autorization check was performed
                self._local.need_authorization = False

                for domain, name, mode in perms:
                    val = kwargs[name]

                    try:
                        ok = self._check_object_perms(self._local.user, domain, val, mode)
                    except ErrorResponse as e:
                        return self._Res(e.message, e.status)
                    except Exception as e:
                        log.error(f"internal error on {request.method} {request.path} permission {perm} check: {e}")
                        if self._Exc(e):  # pragma: no cover
                            raise
                        return self._Res("internal error in permission check", self._server_error)

                    if ok is None:
                        log.warning(f"none object permission on {domain} {val} {mode}")
                        return self._Res("object not found", self._not_found_error)
                    elif not isinstance(ok, bool):  # paranoid?
                        log.error(f"type error on on {request.method} {request.path} permission {perm} check: {type(ok)}")
                        return self._Res("internal error with permission check", self._server_error)
                    elif not ok:
                        return self._Res(f"permission denied on {domain}/{val} {mode}", 403)
                    # else: all is well, check next!

                # then call the initial function
                return self._safe_call(path, "perm authorization", fun, *args, **kwargs)

            return wrapper

        return decorate

    # run any hook after auth and before exec
    def _before_exec(self, path):

        def decorate(fun: Callable):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                login = self.current_user()  # may be None
                auth = self._local.auth

                # apply all hooks
                for hook in self._before_exec_hooks:
                    try:
                        res = hook(request, login, auth)
                        if res:
                            if self._mode >= Mode.DEBUG2:
                                log.debug(f"returning on {request.method} {request.path} before exec hook")
                            return res
                    except Exception as e:
                        if self._Exc(e):  # pragma: no cover
                            raise
                        return self._Res("internal error with before exec hook", self._server_error)

                # then call the initial function
                return self._safe_call(path, "before exec hook", fun, *args, **kwargs)

            return wrapper

        return decorate

    # FIXME endpoint?
    def add_url_rule(self, rule, endpoint=None, view_func=None, authorize=NONE, auth=None, realm=None, **options):
        """Route decorator helper method."""

        # lazy initialization
        if not self._initialized:
            self.initialize()

        # ensure that authorize is a list
        if type(authorize) in (int, str, tuple):
            authorize = [authorize]

        # ensure that auth is registered as used
        if auth is None:
            pass
        elif isinstance(auth, str):
            self._add_auth(auth)
        elif isinstance(auth, (list, tuple)):
            # this also checks that list items are str
            for a in auth:
                self._add_auth(a)
        else:
            raise self._Bad(f"unexpected auth type, should be str, list or tuple: {type(auth)}")

        # normalize None to NONE
        authorize = list(map(lambda a: NONE if a is None else a, authorize))

        # ensure non emptyness
        if len(authorize) == 0:
            authorize = [NONE]

        # special handling of "oauth" rule-specific authentication
        if auth and type(auth) in (tuple, list) and "oauth" in auth:
            if len(auth) != 1:
                raise self._Bad(f"oauth authentication cannot be mixed with other schemes on {rule}")
            auth = "oauth"

        if auth == "oauth":  # sanity checks
            if self._token != "jwt":
                raise self._Bad(f"oauth authorizations require JWT tokens on {rule}")
            if not self._issuer:
                raise self._Bad(f"oauth token authorizations require FSA_TOKEN_ISSUER on {rule}")

        # separate predefs, groups and perms
        predefs = list(filter(lambda a: a in _PREDEFS, authorize))
        groups = list(filter(lambda a: type(a) in (int, str) and a not in _PREDEFS, authorize))
        perms = list(filter(lambda a: isinstance(a, tuple), authorize))

        # authorize are either in groups or in perms
        if len(authorize) != len(groups) + len(perms) + len(predefs):
            bads = list(filter(lambda a: a not in groups and a not in perms and a not in predefs, authorize))
            raise self._Bad(f"unexpected authorizations on {rule}: {bads}")

        if NONE in predefs:
            # overwrite all perms, a route is closed just by appending "NONE"
            # NOTE the handling is performed later to allow for some checks
            predefs, groups, perms = [NONE], [], []
        elif ANY in predefs:
            if len(predefs) > 1:
                raise self._Bad(f"cannot mix ANY/ALL predefined groups on {path}")
            if groups:
                raise self._Bad(f"cannot mix ANY and other groups on {path}")
            if perms:
                raise self._Bad(f"cannot mix ANY with per-object permissions on {path}")

        from uuid import UUID

        # add the expected type to path sections, if available
        # flask converters: string (default), int, float, path, uuid
        # NOTE it can be extended (`url_map`), but we are managing through annotations
        sig = inspect.signature(view_func)

        splits = rule.split("<")
        for i, s in enumerate(splits):
            if i > 0:
                spec, remainder = s.split(">", 1)
                # some sanity checks on path parameters
                conv, name = spec.split(":") if ":" in spec else (None, spec)
                # check for predefined converters, but "any"
                if conv not in (None, "string", "int", "float", "path", "uuid"):
                    raise self._Bad(f"unexpected converter: {conv}")
                if name in sig.parameters:
                    namesig = sig.parameters[name]
                    if namesig.default != inspect._empty:
                        raise self._Bad(f"path parameter cannot have a default: {name}")
                    if conv and namesig.annotation != inspect.Parameter.empty:
                        atype = namesig.annotation
                        if conv == "string" and atype not in (string, str) or \
                           conv == "uuid" and atype != UUID or \
                           conv == "path" and atype not in (path, str) or \
                           conv == "int" and atype != int or \
                           conv == "float" and atype != float:
                            raise self._Bad(f"inconsistent type for {conv} converter on {name}: {atype}")
                    # else no annotation consistency to check
                else:
                    raise self._Bad(f"path parameter missing from function signature: {name}")
                # add explicit "Flask" path parameter type
                if ":" not in spec and spec in sig.parameters:
                    t = _typeof(sig.parameters[spec])
                    # Flask supports 5 types, with string the default?
                    if t in (int, float, UUID, path):
                        splits[i] = f"{t.__name__.lower()}:{spec}>{remainder}"
                    else:
                        splits[i] = f"string:{spec}>{remainder}"
                # else spec includes a type that we keep…
        newpath = "<".join(splits)

        # special shortcut for NONE, override the user function
        if NONE in predefs:

            @functools.wraps(view_func)
            def r403():
                self._local.routed = True
                return "currently closed route", 403

            return flask.Flask.add_url_rule(self._app, newpath, endpoint=endpoint, view_func=r403, **options)

        fun = view_func

        # else only add needed filters on top of "fun", in reverse order
        need_authenticate = ALL in predefs or groups or perms
        need_parameters = len(fun.__code__.co_varnames) > 0
        assert len(predefs) <= 1

        # build handling layers in reverse order:
        # routed / authenticate / (oauth|group|no|) / params / perms / hooks / fun
        if self._before_exec_hooks:
            fun = self._before_exec(newpath)(fun)
        if perms:
            if not need_parameters:
                raise self._Bad("permissions require some parameters")
            assert need_authenticate and need_parameters
            first = fun.__code__.co_varnames[0]
            fun = self._perm_authz(newpath, first, *perms)(fun)
        if need_parameters:
            fun = self._parameters(newpath)(fun)
        else:
            fun = self._noparams(newpath)(fun)
        if groups:
            assert need_authenticate
            if auth == "oauth":
                fun = self._oauth_authz(newpath, *groups)(fun)
            else:
                fun = self._group_authz(newpath, *groups)(fun)
        elif ANY in predefs:
            assert not groups and not perms
            fun = self._no_authz(newpath, *groups)(fun)
        elif ALL in predefs:
            assert need_authenticate
            fun = self._no_authz(newpath, *groups)(fun)
        else:  # no authorization at this level
            assert perms
        if need_authenticate:
            assert perms or groups or ALL in predefs
            fun = self._authenticate(newpath, auth=auth, realm=realm)(fun)
        else:  # "ANY" case deserves a warning
            log.warning(f"no authenticate on {newpath}")

        assert fun != view_func, "some wrapping added"

        # last wrapper to signal a "routed" function
        @functools.wraps(fun)
        def entry(*args, **kwargs):
            self._local.routed = True
            return fun(*args, **kwargs)

        return flask.Flask.add_url_rule(self._app, newpath, endpoint=endpoint, view_func=entry, **options)

    def route(self, rule, **options):
        """Extended `route` decorator provided by the extension."""
        if "authorize" not in options:
            log.warning(f'missing authorize on route "{rule}" makes it 403 Forbidden')

        def decorate(fun: Callable):
            return self.add_url_rule(rule, view_func=fun, **options)

        return decorate

    # support Flask 2.0 per-method decorator shortcuts
    # note that app.get("/", methods=["POST"], …) would do a POST.
    def get(self, rule, **options):
        """Shortcut for `route` with `GET` method."""
        return self.route(rule, methods=["GET"], **options)

    def post(self, rule, **options):
        """Shortcut for `route` with `POST` method."""
        return self.route(rule, methods=["POST"], **options)

    def put(self, rule, **options):
        """Shortcut for `route` with `PUT` method."""
        return self.route(rule, methods=["PUT"], **options)

    def delete(self, rule, **options):
        """Shortcut for `route` with `DELETE` method."""
        return self.route(rule, methods=["DELETE"], **options)

    def patch(self, rule, **options):
        """Shortcut for `route` with `PATCH` method."""
        return self.route(rule, methods=["PATCH"], **options)

    # duck-typing blueprint code stealing: needs blueprints and some other attributes.
    def register_blueprint(self, blueprint, **options):
        """Register a blueprint."""

        # lazy initialization
        if not self._initialized:  # pragma: no cover
            self.initialize()

        flask.Flask.register_blueprint(self, blueprint, **options)
