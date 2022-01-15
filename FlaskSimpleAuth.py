"""
Flask Extension and Wrapper

This extension helps manage:
- authentication
- authorization
- parameters
- and more…

This code is public domain.
"""

from typing import Optional, Callable, Dict, List, Set, Any, Union

import functools
import inspect
import datetime as dt
import re

import flask

# for local use & forwarding
from flask import Response, request

# just for forwarding
# NOTE the only missing should be "Flask"
from flask import session, jsonify, Blueprint, make_response, abort, \
    redirect, url_for, after_this_request, send_file, send_from_directory, \
    safe_join, escape, Markup, render_template, current_app, g

import logging
log = logging.getLogger("fsa")

# get module version
import pkg_resources as pkg  # type: ignore
__version__ = pkg.require("FlaskSimpleAuth")[0].version


class FSAException(BaseException):
    """Exception class to carry fields for an error Response."""

    def __init__(self, message: str, status: int):
        """Constructor parameters:

        - message: Response's message
        - status: intended HTTP status
        """
        self.message = message
        self.status = status


#
# TYPE CASTS
#
def bool_cast(s: str) -> Optional[bool]:
    """Parses a bool."""
    return None if s is None else \
        False if s.lower() in ("", "0", "false", "f") else \
        True


def int_cast(s: str) -> Optional[int]:
    """Parses an integer, allowing several bases."""
    return int(s, base=0) if s else None


class path(str):
    """Type to distinguish str path parameters."""
    pass


class string(str):
    """Type to distinguish str string parameters."""
    pass


_CASTS: Dict[type, Callable[[str], object]] = {
    bool: bool_cast,
    int: int_cast,
    # NOTE mypy complains wrongly about non-existing _empty.
    inspect._empty: str,  # type: ignore
    path: str,
    string: str,
    dt.date: dt.date.fromisoformat,
    dt.time: dt.time.fromisoformat,
    dt.datetime: dt.datetime.fromisoformat
}


def register_cast(t: type, c: Callable[[str], object]):
    """Add a cast for a custom type, if the type itself does not work."""
    if t in _CASTS:
        log.warning(f"overriding type casting function for {t}")
    _CASTS[t] = c


#
# SPECIAL PREDEFINED GROUP NAMES
#
ANY = "ANY"    # anyone can come in, no authentication required
ALL = "ALL"    # all authenticated users are allowed
NONE = "NONE"  # none can come in, the path is forbidden


def typeof(p: inspect.Parameter):
    """Guess parameter type, possibly with some type inference."""
    if p.kind is inspect.Parameter.VAR_KEYWORD:
        return dict
    elif p.kind is inspect.Parameter.VAR_POSITIONAL:
        return list
    elif p.annotation is not inspect._empty:  # type: ignore
        return p.annotation
    elif p.default and p.default is not inspect._empty:  # type: ignore
        return type(p.default)  # type inference!
    else:
        return str


class Reference:
    """Convenient object wrapper class.

    The wrapper forwards most method calls to the wrapped object, so that
    the reference can be imported even if the object is not created yet.

    ```python
    r = Reference()
    o = …
    r.set(o)
    r.whatever(…) # behaves as o.whatever(…)
    ```

    """

    def __init__(self, obj: Any = None, set_name: str = "set"):
        """Constructor parameters:

        - obj: object to be wrapped, can also be provided later.
        - set_name: provide another name for the "set" function.
        """
        self._obj = None
        # create "set" method, which may use another name…
        set_name = set_name or "set"
        setattr(self, set_name, getattr(self, "_set_obj"))
        # keep track of initial methods for later cleanup
        self._init: Set[str] = set()
        self._init.update(self.__dir__())
        if obj:
            self._set_obj(obj)

    def _set_obj(self, obj):
        """Set current wrapped object, possibly replacing the previous one."""
        log.debug(f"setting reference to {obj} ({type(obj)})")
        self._obj = obj
        # method cleanup
        for f in self.__dir__():
            if f not in self._init:
                delattr(self, f)
        # forward
        for f in obj.__dir__():
            if f not in self._init:
                setattr(self, f, getattr(obj, f))

    # forward standard methods
    # automating that with setattr/getattr does not work…
    # contrary to the documentation say, it seems that str(obj)
    # really calls obj.__class__.__str__() and *not* obj.__str__().
    def __str__(self):
        return self._obj.__str__()

    def __repr__(self):
        return self._obj.__repr__()

    def __hash__(self):
        return self._obj.__hash__()

    def __eq__(self, o):
        return self._obj.__eq__(o)

    def __ne__(self, o):
        return self._obj.__ne__(o)

    def __le__(self, o):
        return self._obj.__le__(o)

    def __lt__(self, o):
        return self._obj.__lt__(o)

    def __ge__(self, o):
        return self._obj.__ge__(o)

    def __gt__(self, o):
        return self._obj.__gt__(o)


class Flask(flask.Flask):
    """Flask class wrapper.

    The class behaves mostly as a Flask class, but supports extensions:

    - the `route` decorator manages authentication, authorization and
      parameters transparently.
    - per-methods shortcut decorators allow to handle root for a given
      method: `get`, `post`, `put`, `patch`, `delete`.
    - several additional methods are provided: `get_user_pass`,
      `user_in_group`, `check_password`, `hash_password`, `create_token`,
      `get_user`, `current_user`, `clear_caches`, `register_cast`.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._fsa = FlaskSimpleAuth(self)
        # needed for blueprint registration
        # overwritten late because called by upper Flask initialization for "static"
        self.add_url_rule = self._fsa.add_url_rule

    def clear_caches(self):
        """Clear all internal caches."""
        self._fsa.clear_caches()

    # hooks
    def get_user_pass(self, gup):
        """Set `get_user_pass` helper function."""
        return self._fsa.get_user_pass(gup)

    def user_in_group(self, uig):
        """Set `user_in_group` helper function."""
        return self._fsa.user_in_group(uig)

    def register_cast(self, t, c):
        """Register a cast function for a type."""
        self._fsa.register_cast(t, c)

    # password management
    def check_password(self, pwd, ref):
        """Check whether password is ok wrt to current password manager."""
        return self._fsa.check_password(pwd, ref)

    def hash_password(self, pwd):
        """Hash password using current password manager scheme."""
        return self._fsa.hash_password(pwd)

    # token
    def create_token(self, user: str = None):
        """Create a token with the current token scheme."""
        return self._fsa.create_token(user)

    # user
    def get_user(self, required=True):
        """Authenticate remote user or raise exception."""
        return self._fsa.get_user(required)

    def current_user(self):
        """Get current authenticated user, if any, or None."""
        return self._fsa.current_user()

    # per-method decorator forwarding
    def get(self, rule, **options):
        return self._fsa.get(rule, **options)

    def post(self, rule, **options):
        return self._fsa.post(rule, **options)

    def put(self, rule, **options):
        return self._fsa.put(rule, **options)

    def delete(self, rule, **options):
        return self._fsa.delete(rule, **options)

    def patch(self, rule, **options):
        return self._fsa.patch(rule, **options)


# all possible directives
_DIRECTIVES = {
    "FSA_401_REDIRECT", "FSA_AUTH", "FSA_CHECK",
    "FSA_CACHE", "FSA_CACHE_SIZE", "FSA_CACHE_OPTS",
    "FSA_FAKE_LOGIN", "FSA_GET_USER_PASS", "FSA_HTTP_AUTH_OPTS",
    "FSA_MODE", "FSA_PARAM_PASS", "FSA_PARAM_USER", "FSA_PASSWORD_OPTS",
    "FSA_PASSWORD_SCHEME", "FSA_SKIP_PATH", "FSA_TOKEN_ALGO",
    "FSA_TOKEN_CARRIER", "FSA_TOKEN_DELAY", "FSA_TOKEN_GRACE",
    "FSA_TOKEN_LENGTH", "FSA_TOKEN_NAME", "FSA_REALM",
    "FSA_TOKEN_SECRET", "FSA_TOKEN_SIGN", "FSA_TOKEN_TYPE",
    "FSA_TOKEN_RENEWAL", "FSA_URL_NAME", "FSA_USER_IN_GROUP",
    "FSA_LOGGING_LEVEL", "FSA_CORS", "FSA_CORS_OPTS",
    "FSA_PASSWORD_LEN", "FSA_PASSWORD_RE", "FSA_SERVER_ERROR", "FSA_SECURE"
}

_DEFAULT_CACHE_SIZE = 16384
_DEFAULT_SERVER_ERROR = 500


# actual extension
class FlaskSimpleAuth:
    """Flask extension for authentication, authorization and parameters."""

    def __init__(self, app: flask.Flask = None):
        """Constructor parameter: flask application to extend."""
        self._app = app
        self._get_user_pass = None
        self._user_in_group = None
        self._auth: List[str] = []
        self._saved_auth: Optional[List[str]] = None
        self._http_auth = None
        self._pm = None
        self._cache: Optional[Callable[[Any], Callable]] = None
        self._server_error: int = _DEFAULT_SERVER_ERROR
        self._secure: bool = True
        # actual main initialization is deferred to `init_app`
        self._initialized = False

    def _Resp(self, msg: str, code: int):
        """Genenerate a text/plain Response."""
        return Response(msg, code, content_type="text/plain")

    #
    # HOOKS
    #
    def _check_secure(self):
        if not request.is_secure and \
           not (request.remote_addr.startswith("127.") or request.remote_addr == "::1"):
            msg = f"insecure HTTP request on {request.remote_addr}, allow with FSA_SECURE=False"
            if self._secure:
                log.error(msg)
                return self._Resp("insecure HTTP request denied", self._server_error)
            else:
                log.warning(msg)

    def _auth_set_user(self):
        """Before request hook to perform early authentication."""
        self._user_set = False
        self._user = None
        self._need_authorization = True
        if self._mode == "lazy":
            return
        # keep on under always & all
        for skip in self._skip_path:
            if skip(request.path):
                return
        try:
            self.get_user()
        except FSAException as e:
            return self._Resp(e.message, e.status)

    def _auth_after_cleanup(self, res: Response):
        """After request hook to cleanup authentication and detect missing
        authorization."""
        self._user_set = False
        self._user = None
        # NOTE this may be too late to prevent a commit?
        if res.status_code < 400 and self._need_authorization:
            method, path = request.method, request.path
            if self._check and not (self._cors and method == "OPTIONS"):
                log.error(f"missing authorization on {method} {path}")
                return self._Resp("missing authorization check", self._server_error)
        return res

    def _possible_redirect(self, res: Response):
        """After request hook to turn a 401 into a redirect."""
        if res.status_code == 401 and self._401_redirect:
            location = self._401_redirect
            # allow to come back later in some cases
            if self._url_name and request.method == "GET":
                sep = "&" if "?" in self._url_name else "?"
                import urllib
                location += sep + urllib.parse.urlencode({self._url_name: request.url})
            return redirect(location, 307)
        return res

    def _set_auth_cookie(self, res: Response):
        """Set a cookie if needed and none was sent."""
        # NOTE thanks to max_age the client should not send stale cookies
        if self._carrier == "cookie":
            assert self._token and self._name
            if self._user and self._can_create_token():
                if self._name in request.cookies:
                    user, exp = self._get_any_token_auth_exp(request.cookies[self._name])
                    # renew token when closing expiration
                    limit = dt.datetime.now(dt.timezone.utc) + self._renewal * dt.timedelta(minutes=self._delay)
                    set_cookie = exp < limit
                else:
                    set_cookie = True
                if set_cookie:
                    res.set_cookie(self._name, self.create_token(self._user),
                                   max_age=int(60 * self._delay))
        return res

    def _auth_has(self, *auth):
        """Tell whether current authentication includes any of these schemes."""
        for a in auth:
            if a in self._auth:
                return True
        return False

    def _set_www_authenticate(self, res: Response):
        """Set WWW-Authenticate response header depending on current scheme."""
        if res.status_code == 401:
            # FIXME should it prioritize based on self._auth order?
            if self._auth_has("basic", "password"):
                res.headers["WWW-Authenticate"] = f"Basic realm=\"{self._realm}\""
            elif self._auth_has("http-basic", "http-digest", "http-token", "digest"):
                assert self._http_auth
                res.headers["WWW-Authenticate"] = self._http_auth.authenticate_header()
            elif "token" in self._auth and self._carrier == "bearer":
                res.headers["WWW-Authenticate"] = f"{self._name} realm=\"{self._realm}\""
            # else: scheme does not rely on WWW-Authenticate…
        # else: no need for WWW-Authenticate
        # restore temporary auth if needed
        if self._saved_auth:
            self._auth, self._saved_auth = self._saved_auth, None
        return res

    # NOTE for multiprocess setups:
    # clearing a cache in a process does not tell others to do it as well…
    def _cache_function(self, fun):
        """Generate or regenerate cache for function."""
        # get the actual function when regenerating caches
        while hasattr(fun, "__wrapped__"):
            fun = fun.__wrapped__
        return fun if not fun or self._cache is None else \
            self._cache(**self._cache_opts)(fun)

    def _params(self):
        """Get request parameters wherever they are."""
        if request.json:
            return request.json
        else:
            # reimplement "request.values" after Flask 2.0 regression
            # https://github.com/pallets/werkzeug/pull/2037
            # https://github.com/pallets/flask/issues/4120
            from werkzeug.datastructures import CombinedMultiDict, MultiDict
            return CombinedMultiDict([MultiDict(d) if not isinstance(d, MultiDict) else d
                                      for d in (request.args, request.form)])

    def get_user_pass(self, gup):
        """Set `get_user_pass` helper, can be used as a decorator."""
        self._get_user_pass = self._cache_function(gup)
        self._init_password_manager()
        return gup

    def user_in_group(self, uig):
        """Set `user_in_group` helper, can be used as a decorator."""
        self._user_in_group = self._cache_function(uig)
        return uig

    def register_cast(self, t, c):
        """Register a cast function for a type."""
        register_cast(t, c)

    #
    # DEFERRED INITIALIZATIONS
    #
    def initialize(self):
        """Run late initialization on current app."""
        assert self._app
        self.init_app(self._app)

    def init_app(self, app: flask.Flask):
        """Initialize extension with a Flask application.

        The initialization is performed through `FSA_*` configuration
        directives.
        """
        log.info("FSA initialization…")
        assert app
        self._app = app
        conf = app.config
        if "FSA_LOGGING_LEVEL" in conf:
            log.setLevel(conf["FSA_LOGGING_LEVEL"])
        # check directives for typos
        for name in conf:
            if name[:4] == "FSA_" and name not in _DIRECTIVES:
                log.warning(f"unexpected directive: {name}")
        # whether to only allow secure requests
        self._secure = conf.get("FSA_SECURE", True)
        # status code for this module internal errors
        self._server_error = conf.get("FSA_SERVER_ERROR", _DEFAULT_SERVER_ERROR)
        #
        # overall auth setup
        #
        auth = conf.get("FSA_AUTH", None)
        if not auth:
            self._auth = ["httpd"]
        elif isinstance(auth, str):
            if auth not in ("token", "http-token"):
                self._auth = ["token", auth]
            else:
                self._auth = [auth]
        else:
            self._auth = auth
        for a in self._auth:
            assert a in self._FSA_AUTH
        self._mode = conf.get("FSA_MODE", "lazy")
        assert self._mode in ("always", "lazy", "all")
        self._check: bool = conf.get("FSA_CHECK", True)
        self._skip_path = [re.compile(r).match for r in conf.get("FSA_SKIP_PATH", [])]
        #
        # web apps…
        #
        self._cors: bool = conf.get("FSA_CORS", False)
        self._cors_opts: Dict[str, Any] = conf.get("FSA_CORS_OPTS", {})
        if self._cors:
            from flask_cors import CORS  # type: ignore
            CORS(self._app, **self._cors_opts)
        self._401_redirect = conf.get("FSA_401_REDIRECT", None)
        self._url_name = conf.get("FSA_URL_NAME", "URL" if self._401_redirect else None)
        #
        # internal cache management for passwords, permissions, tokens…
        #
        self._cache_opts: Dict[str, Any] = conf.get("FSA_CACHE_OPTS", {})
        if "FSA_CACHE_SIZE" in conf or "maxsize" not in self._cache_opts:
            self._cache_opts.update(maxsize=conf.get("FSA_CACHE_SIZE", _DEFAULT_CACHE_SIZE))
        cache: Union[str, Callable[[Any], Callable]] = conf.get("FSA_CACHE", "fc-lru")
        if isinstance(cache, str):
            if cache == "ttl":
                import cachetools.func
                self._cache = cachetools.func.ttl_cache
                if "ttl" not in self._cache_opts:
                    self._cache_opts.update(ttl=60 * 10)  # 10 minutes default
            elif cache == "lru":
                import cachetools.func
                self._cache = cachetools.func.lru_cache
            elif cache == "lfu":
                import cachetools.func
                self._cache = cachetools.func.lfu_cache
            elif cache == "fifo":
                import cachetools.func
                self._cache = cachetools.func.fifo_cache
            elif cache == "rr":
                import cachetools.func
                self._cache = cachetools.func.rr_cache
            elif cache == "fc-lru":
                self._cache = functools.lru_cache
            else:
                raise Exception(f"Unexpected FSA_CACHE: {cache}")
        else:  # hopefully a callable
            self._cache = cache
        #
        # token setup
        #
        self._token = conf.get("FSA_TOKEN_TYPE", "fsa")
        if self._token not in (None, "fsa", "jwt"):
            raise Exception(f"Unexpected FSA_TOKEN_TYPE: {self._token}")
        # token carrier
        need_carrier = self._token is not None
        self._carrier = conf.get("FSA_TOKEN_CARRIER", "bearer" if need_carrier else None)
        if self._carrier not in (None, "bearer", "param", "cookie", "header"):
            raise Exception(f"Unexpected FSA_TOKEN_CARRIER: {self._carrier}")
        # sanity checks
        if need_carrier and not self._carrier:
            raise Exception(f"Token type {self._token} requires a carrier")
        # name of token for cookie or param, Authentication scheme, or other header
        default_name: Optional[str] = None
        if self._carrier in ("param", "cookie"):
            default_name = "auth"
        elif self._carrier == "bearer":
            default_name = "Bearer"
        elif self._carrier == "header":
            default_name = "Auth"
        self._name = conf.get("FSA_TOKEN_NAME", default_name)
        if need_carrier and not self._name:
            raise Exception(f"Token carrier {self._carrier} requires a name")
        # token realm…
        realm = conf.get("FSA_REALM", self._app.name)
        if self._token == "fsa":
            # simplify realm for fsa
            keep_char = re.compile(r"[-A-Za-z0-9]").match
            realm = "".join(c if keep_char(c) else "-" for c in realm)
            realm = "-".join(filter(lambda s: s != "", realm.split("-")))
        self._realm = realm
        # token expiration
        self._delay = conf.get("FSA_TOKEN_DELAY", 60.0)
        self._grace = conf.get("FSA_TOKEN_GRACE", 0.0)
        self._renewal = conf.get("FSA_TOKEN_RENEWAL", 0.25)  # only for cookies
        # token signature
        if "FSA_TOKEN_SECRET" in conf:
            self._secret = conf["FSA_TOKEN_SECRET"]
            if self._secret and len(self._secret) < 16:
                log.warning("token secret is short")
        else:
            import random
            import string
            log.warning("random token secret, only ok for one process app")
            # list of 94 chars, about 6.5 bits per char
            chars = string.ascii_letters + string.digits + string.punctuation
            self._secret = "".join(random.SystemRandom().choices(chars, k=40))
        if not self._token:
            pass
        elif self._token == "fsa":
            self._sign = self._secret
            self._algo = conf.get("FSA_TOKEN_ALGO", "blake2s")
            self._siglen = conf.get("FSA_TOKEN_LENGTH", 16)
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
                raise Exception(f"unexpected jwt FSA_TOKEN_ALGO ({algo})")
            self._siglen = 0
        else:  # pragma: no cover
            raise Exception(f"invalid FSA_TOKEN_TYPE ({self._token})")
        #
        # HTTP parameter names
        #
        if "fake" not in self._auth and "FSA_FAKE_LOGIN" in conf:
            log.warning("ignoring directive FSA_FAKE_LOGIN")
        self._login = conf.get("FSA_FAKE_LOGIN", "LOGIN")
        if "param" not in self._auth and "password" not in self._auth:
            if "FSA_PARAM_USER" in conf:
                log.warning("ignoring directive FSA_PARAM_USER")
            if "FSA_PARAM_PASS" in conf:
                log.warning("ignoring directive FSA_PARAM_PASS")
        self._userp = conf.get("FSA_PARAM_USER", "USER")
        self._passp = conf.get("FSA_PARAM_PASS", "PASS")
        #
        # password authentication and authorization hooks
        #
        if "FSA_GET_USER_PASS" in conf:
            self.get_user_pass(conf["FSA_GET_USER_PASS"])
        if "FSA_USER_IN_GROUP" in conf:
            self.user_in_group(conf["FSA_USER_IN_GROUP"])
        #
        # http auth setup
        #
        if self._auth_has("http-basic", "http-digest", "http-token", "digest"):
            opts = conf.get("FSA_HTTP_AUTH_OPTS", {})
            import flask_httpauth as fha  # type: ignore
            if "http-basic" in self._auth:
                self._http_auth = fha.HTTPBasicAuth(realm=self._realm, **opts)
                assert self._http_auth is not None  # for pleasing mypy
                self._http_auth.verify_password(self._check_password)
            elif self._auth_has("http-digest", "digest"):
                self._http_auth = fha.HTTPDigestAuth(realm=self._realm, **opts)
                assert self._http_auth is not None  # for pleasing mypy
                # FIXME? nonce & opaque callbacks? session??
            elif "http-token" in self._auth:
                if self._carrier == "header" and "header" not in opts and self._name:
                    opts["header"] = self._name
                self._http_auth = fha.HTTPTokenAuth(scheme=self._name, realm=self._realm, **opts)
                assert self._http_auth is not None  # for pleasing mypy
                self._http_auth.verify_token(self._get_any_token_auth)
            assert self._http_auth is not None  # for pleasing mypy
            self._http_auth.get_password(self._get_user_pass)
            # FIXME? error_handler?
        else:
            self._http_auth = None
        #
        # register auth request hooks
        #
        app.before_request(self._check_secure)
        app.before_request(self._auth_set_user)
        app.after_request(self._auth_after_cleanup)
        app.after_request(self._possible_redirect)
        app.after_request(self._set_auth_cookie)
        app.after_request(self._set_www_authenticate)
        #
        # blueprint hacks
        #
        self.blueprints = self._app.blueprints
        self.debug = False
        # portability tricks which generates mypy errors…
        if hasattr(self._app, '_blueprint_order'):
            # Flask 1.x
            self._blueprint_order = self._app._blueprint_order
        elif hasattr(self._app, '_is_setup_finished'):
            # Flask 2.0
            self._is_setup_finished = self._app._is_setup_finished
            self.before_request_funcs = self._app.before_request_funcs
            self.after_request_funcs = self._app.after_request_funcs
            self.teardown_request_funcs = self._app.teardown_request_funcs
            self.url_default_functions = self._app.url_default_functions
            self.url_value_preprocessors = self._app.url_value_preprocessors
            self.template_context_processors = self._app.template_context_processors
        else:
            log.warning("unexpected Flask version while dealing with blueprints?")
        #
        # caches
        #
        self._set_caches()
        # done!
        self._initialized = True
        return

    def _init_password_manager(self):
        """Deferred password manager initialization."""
        # only initialize if some password may need to be checked
        # so that passlib is not imported for nothing
        if not self._get_user_pass or self._pm:
            return
        assert self._app
        conf = self._app.config
        scheme = conf.get("FSA_PASSWORD_SCHEME", "bcrypt")
        log.info(f"initializing password manager with {scheme}")
        if scheme:
            if scheme == "plaintext":
                log.warning("plaintext password manager is a bad idea")
            # passlib context is a pain, you have to know the scheme name to set its
            # round. Ident "2y" is same as "2b" but apache compatible.
            options = conf.get("FSA_PASSWORD_OPTS",
                               {"bcrypt__default_rounds": 4,
                                "bcrypt__default_ident": "2y"})
            from passlib.context import CryptContext  # type: ignore
            self._pm = CryptContext(schemes=[scheme], **options)
        self._password_len: int = conf.get("FSA_PASSWORD_LEN", 0)
        self._password_re: List[str] = conf.get("FSA_PASSWORD_RE", [])

    #
    # INHERITED HTTP AUTH
    #
    def _get_httpd_auth(self) -> Optional[str]:
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
        assert request.remote_user is None, "do not shadow web server auth"
        assert request.remote_addr.startswith("127.") or \
               request.remote_addr == "::1", "fake auth only on localhost"
        params = self._params()
        user = params.get(self._login, None)
        # it could check that the user exists in db
        if not user:
            raise FSAException("missing login parameter", 401)
        return user

    #
    # PASSWORD MANAGEMENT
    #
    # FSA_PASSWORD_SCHEME: name of password scheme for passlib context
    # FSA_PASSWORD_OPTS: further options for passlib context
    # FSA_PASSWORD_LEN: minimal length of provided passwords
    # FSA_PASSWORD_RE: list of re a password must match
    #
    # NOTE passlib bcrypt is Apache compatible
    #

    def check_password(self, pwd, ref):
        """Verify whether a password is correct."""
        return self._pm.verify(pwd, ref)

    def hash_password(self, pwd, check=True):
        """Hash password according to the current password scheme."""
        # check password quality
        if check:
            if len(pwd) < self._password_len:
                raise FSAException(f"password is too short, must be at least {self._password_len}", 400)
            for r in self._password_re:
                if not re.search(r, pwd):
                    raise FSAException(f"password must match {r}", 400)
        return self._pm.hash(pwd)

    def _check_password(self, user, pwd):
        """Check user password against internal credentials.

        Raise an exception if not ok, otherwise simply proceeds."""
        try:
            ref = self._get_user_pass(user)
        except FSAException as fe:
            raise fe
        except Exception as e:
            log.error(f"get_user_pass failed: {e}")
            raise FSAException("internal error in get_user_pass", self._server_error)
        if not ref:
            log.debug(f"AUTH (password): no such user ({user})")
            raise FSAException(f"no such user: {user}", 401)
        if not isinstance(ref, (str, bytes)):
            log.error(f"type error in get_user_pass: {type(ref)}, expecting None, str or bytes")
            raise FSAException("internal error with get_user_pass", self._server_error)
        if not self.check_password(pwd, ref):
            log.debug(f"AUTH (password): invalid password for {user}")
            raise FSAException(f"invalid password for {user}", 401)
        return user

    #
    # FLASK HTTP AUTH (BASIC, DIGEST, TOKEN)
    #
    def _get_httpauth(self):
        """Delegate user authentication to HTTPAuth."""
        assert self._http_auth
        auth = self._http_auth.get_auth()
        # log.debug(f"auth = {auth}")
        password = self._http_auth.get_auth_password(auth) \
            if "http-token" not in self._auth else None
        # log.debug(f"password = {password}")
        try:
            # NOTE "authenticate" signature is not very clean…
            user = self._http_auth.authenticate(auth, password)
            if user is not None and user is not False:
                return auth.username if user is True else user
        except FSAException as error:
            log.debug(f"AUTH (http-*): bad authentication {error}")
            raise error
        log.debug("AUTH (http-*): bad authentication")
        raise FSAException("failed HTTP authentication", 401)

    #
    # HTTP BASIC AUTH
    #
    def _get_basic_auth(self):
        """Get user with basic authentication."""
        import base64 as b64
        assert request.remote_user is None
        auth = request.headers.get("Authorization", None)
        log.debug(f"auth: {auth}")
        if not auth:
            log.debug("AUTH (basic): missing authorization header")
            raise FSAException("missing authorization header", 401)
        if auth[:6] != "Basic ":
            log.debug(f"AUTH (basic): unexpected auth \"{auth}\"")
            raise FSAException("unexpected authorization header", 401)
        try:
            user, pwd = b64.b64decode(auth[6:]).decode().split(":", 1)
        except Exception as e:
            log.debug(f"AUTH (basic): error while decoding auth \"{auth}\" ({e})")
            raise FSAException("decoding error on authorization header", 401)
        self._check_password(user, pwd)
        return user

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
        assert request.remote_user is None
        params = self._params()
        user = params.get(self._userp, None)
        if not user:
            raise FSAException(f"missing login parameter: {self._userp}", 401)
        pwd = params.get(self._passp, None)
        if not pwd:
            raise FSAException(f"missing password parameter: {self._passp}", 401)
        self._check_password(user, pwd)
        return user

    #
    # HTTP BASIC OR PARAM AUTH
    #
    def _get_password_auth(self):
        """Get user from basic or param authentication."""
        try:
            return self._get_basic_auth()
        except FSAException:  # failed, let's try param
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
    # FSA_TOKEN_NAME: name of parameter holding the token, or None for bearer auth
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
    # FSA_REALM: realm (lc simplified app name)
    #
    def _cmp_sig(self, data, secret):
        """Compute signature for data."""
        import hashlib
        h = hashlib.new(self._algo)
        h.update(f"{data}:{secret}".encode())
        return h.digest()[:self._siglen].hex()

    def _to_timestamp(self, ts):
        """Build a simplistic timestamp string."""
        # this is shorter than an iso format timestamp
        return "%04d%02d%02d%02d%02d%02d" % ts.timetuple()[:6]

    def _from_timestamp(self, ts):
        """Parses a simplistic timestamp string."""
        p = re.match(r"^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$", ts)
        if not p:
            raise Exception(f"unexpected timestamp format: {ts}")
        return dt.datetime(*[int(p[i]) for i in range(1, 7)], tzinfo=dt.timezone.utc)

    def _get_fsa_token(self, realm, user, delay, secret):
        """Compute a signed token for "user" valid for "delay" minutes."""
        limit = self._to_timestamp(dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=delay))
        data = f"{realm}:{user}:{limit}"
        sig = self._cmp_sig(data, secret)
        return f"{data}:{sig}"

    def _get_jwt_token(self, realm, user, delay, secret):
        """Json Web Token (JWT) generation.

        - exp: expiration
        - sub: subject (the user)
        - iss: issuer (not used)
        - aud = audience (the realm)
        """
        exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=delay)
        import jwt
        return jwt.encode({"exp": exp, "sub": user, "aud": realm},
                          secret, algorithm=self._algo)

    def _can_create_token(self):
        """Whether it is possible to create a token."""
        return self._token and not \
            (self._token == "jwt" and self._algo[0] in ("R", "E", "P") and not self._sign)

    def create_token(self, user: str = None):
        """Create a new token for user depending on the configuration."""
        assert self._token
        user = user or self.get_user()
        realm, delay = self._realm, self._delay
        if self._token == "fsa":
            return self._get_fsa_token(realm, user, delay, self._secret)
        else:
            return self._get_jwt_token(realm, user, delay, self._sign)

    def _get_fsa_token_auth(self, token):
        """Tell whether FSA token is ok: return validated user or None.

        This function is expected to be cached, so it returns the token
        expiration so that it can be rechecked later.
        """
        # token format: "realm:calvin:20380119031407:<signature>"
        realm, user, slimit, sig = token.split(":", 3)
        limit = self._from_timestamp(slimit)
        # check realm
        if realm != self._realm:
            log.debug(f"AUTH (fsa token): unexpected realm {realm}")
            raise FSAException(f"unexpected realm: {realm}", 401)
        # check signature
        ref = self._cmp_sig(f"{realm}:{user}:{slimit}", self._secret)
        if ref != sig:
            log.debug("AUTH (fsa token): invalid signature")
            raise FSAException("invalid fsa auth token signature", 401)
        # check limit with a grace time
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=self._grace)
        if now > limit:
            log.debug("AUTH (fsa token): token {token} has expired")
            raise FSAException("expired fsa auth token", 401)
        # all is well
        return user, limit

    def _get_jwt_token_auth(self, token):
        """Tell whether JWT token is ok: return validated user or None.

        This function is expected to be cached, so it returns the token
        expiration so that it can be rechecked later.
        """
        import jwt
        try:
            data = jwt.decode(token, self._secret, leeway=self._grace * 60.0,
                              audience=self._realm, algorithms=[self._algo])
            exp = dt.datetime.fromtimestamp(data["exp"], tz=dt.timezone.utc)
            return data["sub"], exp
        except jwt.ExpiredSignatureError:
            log.debug(f"AUTH (jwt token): token {token} has expired")
            raise FSAException("expired jwt auth token", 401)
        except Exception as e:
            log.debug(f"AUTH (jwt token): invalid token ({e})")
            raise FSAException("invalid jwt token", 401)

    def _get_any_token_auth_exp(self, token):
        """return validated user and expiration."""
        if not token:
            raise FSAException("missing token", 401)
        return \
            self._get_fsa_token_auth(token) if self._token == "fsa" else \
            self._get_jwt_token_auth(token)

    def _get_any_token_auth(self, token):
        """Tell whether token is ok: return validated user or None."""
        user, exp = self._get_any_token_auth_exp(token)
        # recheck token expiration
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=self._grace)
        if now > exp:
            log.debug(f"AUTH (token): token {token} has expired")
            raise FSAException("expired auth token", 401)
        return user

    def _get_token_auth(self) -> Optional[str]:
        """Get authentication from token."""
        user = None
        if self._token:
            token: Optional[str] = None
            if self._carrier == "bearer":
                auth = request.headers.get("Authorization", None)
                if auth:
                    slen = len(self._name) + 1
                    if auth[:slen] == f"{self._name} ":  # FIXME lower case?
                        token = auth[slen:]
                # else we ignore… maybe it will be resolved later
            elif self._carrier == "cookie":
                token = request.cookies[self._name] \
                    if self._name in request.cookies else None
            elif self._carrier == "param":
                params = self._params()
                token = params.get(self._name, None)
            else:
                assert self._carrier == "header" and self._name
                token = request.headers.get(self._name, None)
            user = self._get_any_token_auth(token)
        return user

    # map auth types to their functions
    _FSA_AUTH: Dict[str, Callable[[Any], Optional[str]]] = {
        "none": lambda s: None,
        "httpd": _get_httpd_auth,
        "token": _get_token_auth,
        "fake": _get_fake_auth,
        "basic": _get_basic_auth,
        "digest": _get_httpauth,
        "param": _get_param_auth,
        "password": _get_password_auth,
        "http-basic": _get_httpauth,
        "http-digest": _get_httpauth,
        "http-token": _get_httpauth,
    }

    def get_user(self, required=True) -> Optional[str]:
        """Authenticate user or throw exception."""
        log.debug(f"get_user for {self._auth}")

        # _user is reset before/after requests
        # so relying on in-request persistance is safe
        if self._user_set:
            return self._user

        assert self._initialized, "FlaskSimpleAuth must be initialized"

        # try authentication schemes
        lae = None
        for a in self._auth:
            try:
                self._user = self._FSA_AUTH[a](self)
                if self._user:
                    break
            except FSAException as e:
                lae = e
            # FIXME other exceptions?

        # even if not set, we say that the answer is the right one.
        self._user_set = True

        # rethrow last auth exception on failure
        if required and not self._user:
            raise lae or FSAException("missing authentication", 401)

        log.debug(f"get_user({self._auth}): {self._user}")
        return self._user

    def current_user(self):
        """Return current authenticated user, if any."""
        return self.get_user(required=False)

    # methods that may be cached
    _CACHABLE = ("_get_jwt_token_auth", "_get_fsa_token_auth", "_get_user_pass", "_user_in_group")

    def _set_caches(self):
        """Create caches around some functions."""
        for name in self._CACHABLE:
            fun = getattr(self, name)
            setattr(self, name, self._cache_function(fun))

    def clear_caches(self):
        """Clear internal caches."""
        for name in self._CACHABLE:
            fun = getattr(self, name)
            if fun and hasattr(fun, "cache_clear"):
                fun.cache_clear()

    #
    # authorize internal decorator
    #
    def _authorize(self, *groups, auth=None):
        """Decorator to authorize groups."""

        if len(groups) > 1 and \
           (ANY in groups or ALL in groups or NONE in groups or None in groups):
            raise Exception("must not mix ANY/ALL/NONE and other groups")

        if ANY not in groups and ALL not in groups and \
           NONE not in groups and None not in groups:
            assert self._user_in_group, \
                "user_in_group callback needed for authorize"

        if auth:
            if isinstance(auth, str):
                auth = [auth]
            for a in auth:
                if a not in self._FSA_AUTH:
                    raise Exception(f"unexpected authentication scheme {auth}")

        def decorate(fun: Callable):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                # track that some autorization check was performed
                self._need_authorization = False
                # shortcuts
                if NONE in groups or None in groups:
                    return self._Resp("", 403)
                if ANY in groups:
                    try:
                        return fun(*args, **kwargs)
                    except FSAException as e:
                        return self._Resp(e.message, e.status)
                # get user if needed
                if not self._user:
                    # no current user, try to get one?
                    if self._mode != "always":
                        # possibly overwrite the authentication scheme
                        # it will be restored in an after request hook
                        # NOTE this may or may not work because other settings may
                        #   not be compatible with the provided scheme…
                        if auth:
                            self._saved_auth, self._auth = self._auth, auth
                        try:
                            self._user = self.get_user()
                        except FSAException as e:
                            return self._Resp(e.message, e.status)
                    else:
                        return self._Resp("", 401)
                if not self._user:  # pragma: no cover
                    return self._Resp("", 401)  # should be unreachable
                # shortcut for authenticated users
                if ALL in groups:
                    try:
                        return fun(*args, **kwargs)
                    except FSAException as e:
                        return self._Resp(e.message, e.status)
                # check against all authorized groups/roles
                for r in groups:
                    try:
                        uig = self._user_in_group(self._user, r)
                    except FSAException as fe:
                        return self._Resp(fe.message, fe.status)
                    except Exception as e:
                        log.error(f"user_in_group failed: {e}")
                        return self._Resp("internal error in user_in_group", self._server_error)
                    if not isinstance(uig, bool):
                        log.error(f"type error in user_in_group: {type(uig)}, must return a boolean")
                        return self._Resp("internal error with user_in_group", self._server_error)
                    if uig:
                        try:
                            return fun(*args, **kwargs)
                        except FSAException as e:
                            return self._Resp(e.message, e.status)
                # else no matching group
                return self._Resp("", 403)

            return wrapper

        return decorate

    #
    # parameters internal decorator
    #
    # translate HTTP or JSON parameters to python parameters based on their
    # declared names, types and default values.
    #
    def _parameters(self):
        """Decorator to handle request parameters."""

        def decorate(fun: Callable):

            # for each parameter name, its expected type, cast and default value
            types: Dict[str, type] = {}
            typings: Dict[str, Callable[[str], Any]] = {}
            defaults: Dict[str, Any] = {}

            # parameters types/casts and defaults taken from signature
            sig = inspect.signature(fun)
            keywords = False

            for n, p in sig.parameters.items():
                if n not in types and \
                   p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL):
                    # guess parameter type
                    t = typeof(p)
                    types[n] = t
                    typings[n] = _CASTS.get(t, t)
                if p.default != inspect._empty:  # type: ignore
                    defaults[n] = p.default
                if p.kind == p.VAR_KEYWORD:
                    keywords = True

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                # NOTE *args and **kwargs are empty before being filled in from HTTP

                # this cannot happen under normal circumstances
                if self._need_authorization and self._check and \
                        not (self._cors and request.method == 'OPTIONS'):  # pragma: no cover
                    log.error("missing authorization check in parameter wrapper")
                    return self._Resp("missing authorization check", self._server_error)

                # translate request parameters to named function parameters
                params = self._params()

                for p, typing in typings.items():
                    # guess which function parameters are request parameters
                    # parameter HTTP name
                    pn = p[1:] if p[0] == '_' and len(p) > 1 else p
                    if p not in kwargs:
                        # parameter p not yet encountered
                        if pn in params:
                            try:
                                kwargs[p] = typing(params[pn])
                            except Exception as e:
                                return self._Resp(f"type error on HTTP parameter \"{pn}\" ({e})", 400)
                        else:
                            if p in defaults:
                                kwargs[p] = defaults[p]
                            else:
                                return self._Resp(f"missing HTTP parameter \"{pn}\"", 400)
                    else:
                        # possibly recast path parameters if needed
                        if not isinstance(kwargs[p], types[p]):
                            try:
                                kwargs[p] = typing(kwargs[p])
                            except Exception as e:
                                return self._Resp(f"type error on path parameter \"{pn}\": ({e})", 404)

                # possibly add others, without shadowing already provided ones
                if keywords:
                    for p in params:
                        if p not in kwargs:
                            kwargs[p] = params[p]

                # then call the initial function
                try:
                    return fun(*args, **kwargs)
                except FSAException as e:
                    return self._Resp(e.message, e.status)
                except Exception as e:
                    log.error(f"internal error on {request.method} {request.path}: {e}")
                    return self._Resp(f"internal error on {request.method} {request.path}", self._server_error)

            return wrapper

        return decorate

    def add_url_rule(self, rule, endpoint=None, view_func=None, authorize=NONE,
                     auth=None, **options):
        """Route decorator helper method."""

        log.debug(f"adding {rule}")

        # lazy initialization
        if not self._initialized:
            self.initialize()

        # make authorize parameter it a list/tuple
        roles = authorize
        if isinstance(roles, str):
            roles = (roles,)
        elif isinstance(roles, int):
            roles = (roles,)

        from collections.abc import Iterable
        assert isinstance(roles, Iterable)

        from uuid import UUID
        # add the expected type to path sections, if available
        # flask converter types: string (default), int, float, path, uuid
        sig = inspect.signature(view_func)

        splits = rule.split("<")
        for i, s in enumerate(splits):
            if i > 0:
                spec, remainder = s.split(">", 1)
                if ":" not in spec and spec in sig.parameters:
                    t = typeof(sig.parameters[spec])
                    # Flask supports 5 types, with string the default?
                    if t in (int, float, UUID, path):
                        splits[i] = f"{t.__name__.lower()}:{spec}>{remainder}"
                    else:
                        splits[i] = f"string:{spec}>{remainder}"
        newpath = "<".join(splits)

        assert self._app
        par = self._parameters()(view_func)
        aut = self._authorize(*roles, auth=auth)(par)
        return flask.Flask.add_url_rule(self._app, newpath, endpoint=endpoint, view_func=aut, **options)

    def route(self, rule, **options):
        """Extended `route` decorator provided by the extension."""
        if "authorize" not in options:
            log.warning(f"missing authorize on route \"{rule}\" makes it 403 Forbidden")

        def decorate(fun):
            return self.add_url_rule(rule, view_func=fun, **options)
        return decorate

    # support Flask 2.0 per-method decorator shortcuts
    # note that app.get("/", methods=["POST"], ...) would do a POST.
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
        if not self._initialized:
            self.initialize()

        flask.Flask.register_blueprint(self, blueprint, **options)
