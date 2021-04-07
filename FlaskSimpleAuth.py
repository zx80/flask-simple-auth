"""
Flask Extension and Wrapper

This extension helps manage:
- authentication
- authorization
- parameters
- and more…

This code is public domain.
"""

from typing import Optional, Callable, Dict, List, Set, Any

import functools
import inspect
import datetime as dt

import flask
# for local use & forwarding
from flask import Response, request
# just for forwarding
from flask import session, jsonify, redirect, url_for, Blueprint
from flask import make_response, abort, render_template, current_app, g

import logging
log = logging.getLogger("fsa")


class AuthException(BaseException):
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
    return int(s, base=0) if s is not None else None


class path(str):
    """Type to distinguish str path parameters."""
    pass


class string(str):
    """Type to distinguish str path parameters."""
    pass


# note: mypy complains wrongly about non-existing _empty.
CASTS: Dict[type, Callable[[str], object]] = {
    bool: bool_cast,
    int: int_cast,
    inspect._empty: str,
    path: str,
    string: str,
    dt.date: dt.date.fromisoformat,
    dt.time: dt.time.fromisoformat,
    dt.datetime: dt.datetime.fromisoformat
}

#
# PREDEFINED GROUP NAMES
#
ANY = "ANY"    # anyone can come in, no authentication required
ALL = "ALL"    # all authenticated users are allowed
NONE = "NONE"  # non can come in, the path is forbidden


def typeof(p: inspect.Parameter):
    """Guess parameter type, possibly with some type inference."""
    if p.kind is p.VAR_KEYWORD:
        return dict
    elif p.kind is p.VAR_POSITIONAL:
        return list
    elif p.annotation is not inspect._empty:
        return p.annotation
    elif p.default is not None and p.default is not inspect._empty:
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
        if obj is not None:
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


#
# TODO
# - LRU? LFU?
# - automatic reset based on cache efficiency? expansion?
#
class CacheOK:
    """Positive caching decorator.

    Cache True answers, but still forwards False answers to the underlying
    function.
    """

    def __init__(self, fun: Callable[[List[Any]], bool]):
        self._fun = fun
        self._cache: Set[Any] = set()
        self.cache_clear = self._cache.clear

    def __call__(self, *args):
        if args in self._cache:
            return True
        else:
            ok = self._fun(*args)
            if ok:
                self._cache.add(args)
            return ok


class Flask(flask.Flask):
    """Flask class wrapper.

    The class behaves mostly as a Flask class, but supports extensions:

    - the `route` decorator manages authentication, authorization and
      parameters transparently.
    - several additional methods are provided: `get_user_pass`,
      `user_in_group`, `check_password`, `hash_password`, `create_token`,
      `get_user`, `current_user`, `clear_caches`.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._fsa = FlaskSimpleAuth(self)
        # needed for blueprint registration
        # overwritten late because called by upper Flask initialization
        self.add_url_rule = self._fsa.add_url_rule

    def get_user_pass(self, gup):
        """Set `get_user_pass` helper function."""
        return self._fsa.get_user_pass(gup)

    def user_in_group(self, uig):
        """Set `user_in_group` helper function."""
        return self._fsa.user_in_group(uig)

    def check_password(self, pwd, ref):
        """Check whether password is ok wrt to current password manager."""
        return self._fsa.check_password(pwd, ref)

    def hash_password(self, pwd):
        """Hash password using current password manager scheme."""
        return self._fsa.hash_password(pwd)

    def create_token(self, user: str = None):
        """Create a token with the current token scheme."""
        return self._fsa.create_token(user)

    def get_user(self):
        """Authenticate remote user."""
        return self._fsa.get_user()

    def current_user(self):
        """Get current authenticated user, if any."""
        return self._fsa.current_user()

    def clear_caches(self):
        """Clear internal caches."""
        self._fsa.clear_caches()


class Resp(Response):
    """Genenerate a text/plain Response."""
    def __init__(self, msg: str, code: int):
        super().__init__(msg, code, content_type="text/plain")


# actual class
class FlaskSimpleAuth:
    """Flask extension to implement authentication, authorization and parameter
    management.
    """

    def __init__(self, app: flask.Flask = None):
        """Constructor parameter: flask application to extend."""
        self._app = app
        self._maxsize = 1024
        self._get_user_pass = None
        self._user_in_group = None
        self._http_auth = None
        # actual initialization is deferred
        self._initialized = False

    #
    # HOOKS
    #
    def _auth_set_user(self):
        """Before request hook to perform early authentication."""
        self._user = None
        self._need_authorization = True
        if self._mode != "always":
            return
        for skip in self._skip_path:
            if skip(request.path):
                return
        try:
            self._user = self.get_user()
        except AuthException as e:
            return Resp(e.message, e.status)
        assert self._user is not None

    def _auth_after_cleanup(self, res: Response):
        """After request hook to cleanup authentication and detect missing
        authorization."""
        self._user = None
        # should it always return 500?
        if res.status_code < 400 and self._need_authorization:
            method, path = request.method, request.path
            log.warning(f"missing authorization on {method} {path}")
            if self._check:
                return Resp("missing authorization check", 500)
        return res

    def _set_auth_cookie(self, res: Response):
        """Set a cookie if needed and none was sent."""
        # note: thanks to max_age the client should not send stale cookies
        if self._carrier == "cookie":
            assert self._token is not None and self._name is not None
            if self._user is not None:
                if self._name in request.cookies:
                    user, exp = self._get_token_auth_exp(request.cookies[self._name])
                    # reset token when 25% time remains
                    limit = self._timestamp(dt.datetime.utcnow() + 0.25 * dt.timedelta(minutes=self._delay))
                    set_cookie = exp < limit
                else:
                    set_cookie = True
                if set_cookie:
                    res.set_cookie(self._name, self.create_token(self._user),
                                   max_age=int(60 * self._delay))
        return res

    def _set_www_authenticate(self, res: Response):
        """Set WWW-Authenticate response header depending on current scheme."""
        if res.status_code == 401:
            if self._auth in ("basic", "password"):
                res.headers["WWW-Authenticate"] = f"Basic realm=\"{self._realm}\""
            elif self._auth in ("http-basic", "http-digest", "http-token", "digest"):
                assert self._http_auth is not None
                res.headers["WWW-Authenticate"] = self._http_auth.authenticate_header()
            elif self._auth == "param":
                # not sure this one makes much sense
                res.headers["WWW-Authenticate"] = f"Param realm=\"{self._realm}\""
            elif self._carrier == "bearer":
                res.headers["WWW-Authenticate"] = f"{self._name} realm=\"{self._realm}\""
        return res

    def _cache_function(self, fun):
        """Generate or regenerate cache for function."""
        if hasattr(fun, "__wrapped__"):
            fun = fun.__wrapped__
        # probaly maxsize should disable with None and unbound with 0.
        return fun if fun is None or self._maxsize == 0 else \
            functools.lru_cache(maxsize=self._maxsize)(fun)

    def get_user_pass(self, gup):
        """Set `get_user_pass` helper, can be used as a decorator."""
        self._get_user_pass = self._cache_function(gup)
        return gup

    def user_in_group(self, uig):
        """Set `user_in_group` helper, can be used as a decorator."""
        self._user_in_group = self._cache_function(uig)
        return uig

    #
    # DEFERRED INITIALIZATION
    #
    def initialize(self):
        """Run late initialization on current app."""
        assert self._app is not None
        self.init_app(self._app)

    def init_app(self, app: flask.Flask):
        """Initialize extension with a Flask application.

        The initialization is performed through `FSA_*` configuration
        directives.
        """
        log.info("FSA initialization…")
        assert app is not None
        self._app = app
        conf = app.config
        #
        # overall auth setup
        #
        self._auth: str = conf.get("FSA_AUTH", "httpd")
        assert self._auth in ("httpd", "none", "fake", "basic", "param", "password",
                              "token", "http-basic", "http-digest", "http-token", "digest")
        self._mode = conf.get("FSA_MODE", "lazy")
        assert self._mode in ("always", "lazy", "all")
        self._check: bool = conf.get("FSA_CHECK", True)
        self._maxsize = conf.get("FSA_CACHE_SIZE", 1024)
        import re
        self._skip_path = [re.compile(r).match for r in conf.get("FSA_SKIP_PATH", [])]
        #
        # token setup
        #
        self._token = conf.get("FSA_TOKEN_TYPE", "fsa")
        if self._token not in (None, "fsa", "jwt"):
            raise Exception(f"Unexpected token type (FSA_TOKEN_TYPE): {self._token}")
        # where to put/look for the token
        need_carrier = self._token is not None
        self._carrier = conf.get("FSA_TOKEN_CARRIER", "bearer" if need_carrier else None)
        if self._carrier not in (None, "bearer", "param", "cookie", "header"):
            raise Exception(f"Unexpected token carrier (FSA_TOKEN_CARRIER): {self._carrier}")
        # sanity checks
        if need_carrier and self._carrier is None:
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
        if need_carrier and self._name is None:
            raise Exception(f"Token carrier {self._carrier} requires a name")
        # token realm…
        realm = conf.get("FSA_TOKEN_REALM", self._app.name)
        if self._token == "fsa":
            # simplify realm for fsa
            keep_char = re.compile(r"[-A-Za-z0-9]").match
            realm = "".join(c if keep_char(c) else "-" for c in realm)
            realm = "-".join(filter(lambda s: s != "", realm.split("-")))
        self._realm = realm
        # time validity
        self._delay = conf.get("FSA_TOKEN_DELAY", 60.0)
        self._grace = conf.get("FSA_TOKEN_GRACE", 0.0)
        # token signature
        if self._token is not None and self._token == "jwt":
            algo = conf.get("FSA_TOKEN_ALGO", "HS256")
            if algo[0] in ("R", "E", "P"):
                assert "FSA_TOKEN_SECRET" in conf and "FSA_TOKEN_SIGN" in conf, \
                    "pubkey kwt signature require explicit secret and sign"
        if "FSA_TOKEN_SECRET" in conf:
            self._secret = conf["FSA_TOKEN_SECRET"]
            if self._secret is not None and len(self._secret) < 16:
                log.warning("token secret is short")
        else:
            import random
            import string
            log.warning("random token secret, only ok for one process app")
            # list of 94 chars, about 6.5 bits per char
            chars = string.ascii_letters + string.digits + string.punctuation
            self._secret = "".join(random.SystemRandom().choices(chars, k=40))
        if self._token is None:
            pass
        elif self._token == "fsa":
            self._sign = self._secret
            self._algo = conf.get("FSA_TOKEN_ALGO", "blake2s")
            self._siglen = conf.get("FSA_TOKEN_LENGTH", 16)
        elif self._token == "jwt":
            algo = conf.get("FSA_TOKEN_ALGO", "HS256")
            self._algo = algo
            if algo[0] in ("R", "E", "P"):
                self._sign = conf["FSA_TOKEN_SIGN"]
            elif algo[0] == "H":
                self._sign = self._secret
            elif algo == "none":
                self._sign = None
            else:
                raise Exception(f"unexpected jwt FSA_TOKEN_ALGO ({algo})")
            self._siglen = 0
        else:
            raise Exception(f"invalid FSA_TOKEN_TYPE ({self._token})")
        #
        # HTTP parameter names
        #
        self._login = conf.get("FSA_FAKE_LOGIN", "LOGIN")
        self._userp = conf.get("FSA_PARAM_USER", "USER")
        self._passp = conf.get("FSA_PARAM_PASS", "PASS")
        #
        # password setup
        #
        # passlib context is a pain, you have to know the scheme name to set its
        # round. Ident "2y" is same as "2b" but apache compatible.
        scheme = conf.get("FSA_PASSWORD_SCHEME", "bcrypt")
        if scheme is not None:
            if scheme == "plaintext":
                log.warning("plaintext password manager is a bad idea")
            options = conf.get("FSA_PASSWORD_OPTIONS",
                               {"bcrypt__default_rounds": 4,
                                "bcrypt__default_ident": "2y"})
            from passlib.context import CryptContext  # type: ignore
            self._pm = CryptContext(schemes=[scheme], **options)
        else:
            self._pm = None
        #
        # hooks
        #
        if "FSA_GET_USER_PASS" in conf:
            self.get_user_pass(conf["FSA_GET_USER_PASS"])
        if "FSA_USER_IN_GROUP" in conf:
            self.user_in_group(conf["FSA_USER_IN_GROUP"])
        #
        # http auth setup
        #
        if self._auth in ("http-basic", "http-digest", "http-token", "digest"):
            opts = conf.get("FSA_HTTP_AUTH_OPTS", {})
            import flask_httpauth as fha  # type: ignore
            if self._auth == "http-basic":
                self._http_auth = fha.HTTPBasicAuth(realm=self._realm, **opts)
                self._http_auth.verify_password(self._check_password)
            elif self._auth in ("http-digest", "digest"):
                self._http_auth = fha.HTTPDigestAuth(realm=self._realm, **opts)
                # FIXME? nonce & opaque callbacks? session??
            elif self._auth == "http-token":
                if self._carrier == "header" and "header" not in opts and self._name is not None:
                    opts["header"] = self._name
                self._http_auth = fha.HTTPTokenAuth(scheme=self._name, realm=self._realm, **opts)
                self._http_auth.verify_token(self._get_token_auth)
            self._http_auth.get_password(self._get_user_pass)
            # FIXME? error_handler?
        else:
            self._http_auth = None
        #
        # register auth request hooks
        #
        app.before_request(self._auth_set_user)
        app.after_request(self._auth_after_cleanup)
        app.after_request(self._set_auth_cookie)
        app.after_request(self._set_www_authenticate)
        #
        # blueprint hacks
        #
        self.blueprints = self._app.blueprints
        self._blueprint_order = self._app._blueprint_order
        self.debug = False
        #
        # caches
        #
        self._set_caches()
        # done!
        self._initialized = True
        return

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
        assert request.environ["REMOTE_ADDR"][:4] == "127.", \
            "fake auth only on localhost"
        params = request.json or request.values
        user = params.get(self._login, None)
        # it could check that the user exists in db
        if user is None:
            raise AuthException("missing login parameter", 401)
        return user

    #
    # PASSWORD MANAGEMENT
    #
    # FSA_PASSWORD_SCHEME: name of password scheme for passlib context
    # FSA_PASSWORD_OPTIONS: further options for passlib context
    #
    # note: passlib bcrypt is Apache compatible
    #

    def check_password(self, pwd, ref):
        """Verify whether a password is correct."""
        return self._pm.verify(pwd, ref)

    def hash_password(self, pwd):
        """Hash password according to the current password scheme."""
        return self._pm.hash(pwd)

    def _check_password(self, user, pwd):
        """Check user password against internal credentials.

        Raise an exception if not ok, otherwise simply proceeds."""
        if not request.is_secure:
            log.warning("password authentication over an insecure request")
        ref = self._get_user_pass(user)
        if ref is None:
            log.debug(f"AUTH (password): no such user ({user})")
            raise AuthException(f"no such user: {user}", 401)
        if not self.check_password(pwd, ref):
            log.debug(f"AUTH (password): invalid password for {user}")
            raise AuthException(f"invalid password for {user}", 401)
        return user

    #
    # FLASK HTTP AUTH (BASIC, DIGEST, TOKEN)
    #
    def _get_http_auth(self):
        """Delegate user authentication to HTTPAuth."""
        assert self._http_auth is not None
        auth = self._http_auth.get_auth()
        # log.debug(f"auth = {auth}")
        password = self._http_auth.get_auth_password(auth) \
            if self._auth != "http-token" else None
        # log.debug(f"password = {password}")
        try:
            # note: "authenticate" signature is not very clean…
            user = self._http_auth.authenticate(auth, password)
            if user is not None and user is not False:
                return auth.username if user is True else user
        except AuthException as error:
            log.debug(f"AUTH (http-*): bad authentication {error}")
            raise error
        log.debug("AUTH (http-*): bad authentication")
        raise AuthException("failed HTTP authentication", 401)

    #
    # HTTP BASIC AUTH
    #
    def _get_basic_auth(self):
        """Get user with basic authentication."""
        import base64 as b64
        assert request.remote_user is None
        auth = request.headers.get("Authorization", None)
        log.debug(f"auth: {auth}")
        if auth is None:
            log.debug("AUTH (basic): missing authorization header")
            raise AuthException("missing authorization header", 401)
        if auth[:6] != "Basic ":
            log.debug(f"AUTH (basic): unexpected auth \"{auth}\"")
            raise AuthException("unexpected authorization header", 401)
        try:
            user, pwd = b64.b64decode(auth[6:]).decode().split(":", 1)
        except Exception as e:
            log.debug(f"AUTH (basic): error while decoding auth \"{auth}\" ({e})")
            raise AuthException("decoding error on authorization header", 401)
        finally:
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
        params = request.json or request.values
        user = params.get(self._userp, None)
        if user is None:
            raise AuthException(f"missing login parameter: {self._userp}", 401)
        pwd = params.get(self._passp, None)
        if pwd is None:
            raise AuthException(f"missing password parameter: {self._passp}", 401)
        self._check_password(user, pwd)
        return user

    def _get_password_auth(self):
        """Get user from basic or param authentication."""
        try:
            return self._get_basic_auth()
        except AuthException:  # failed, let's try param
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
    # FSA_TOKEN_REALM: token realm (lc simplified app name)
    #
    def _cmp_sig(self, data, secret):
        """Compute signature for data."""
        import hashlib
        h = hashlib.new(self._algo)
        h.update(f"{data}:{secret}".encode())
        return h.digest()[:self._siglen].hex()

    def _timestamp(self, ts):
        """Build a timestamp string."""
        return "%04d%02d%02d%02d%02d%02d" % ts.timetuple()[:6]

    def _get_fsa_token(self, realm, user, delay, secret):
        """Compute a signed token for "user" valid for "delay" minutes."""
        limit = self._timestamp(dt.datetime.utcnow() + dt.timedelta(minutes=delay))
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
        exp = dt.datetime.utcnow() + dt.timedelta(minutes=delay)
        import jwt
        return jwt.encode({"exp": exp, "sub": user, "aud": realm},
                          secret, algorithm=self._algo)

    def create_token(self, user: str = None):
        """Create a new token for user depending on the configuration."""
        assert self._token is not None
        user = user or self.get_user()
        realm, delay = self._realm, self._delay
        if self._token == "fsa":
            return self._get_fsa_token(realm, user, delay, self._secret)
        else:
            return self._get_jwt_token(realm, user, delay, self._sign)

    def _get_fsa_token_auth(self, token):
        """Tell whether FSA token is ok: return validated user or None."""
        # token format: "realm:calvin:20380119031407:<signature>"
        realm, user, limit, sig = token.split(":", 3)
        # check realm
        if realm != self._realm:
            log.debug(f"AUTH (fsa token): unexpected realm {realm}")
            raise AuthException(f"unexpected realm: {realm}", 401)
        # check signature
        ref = self._cmp_sig(f"{realm}:{user}:{limit}", self._secret)
        if ref != sig:
            log.debug("AUTH (fsa token): invalid signature")
            raise AuthException("invalid fsa auth token signature", 401)
        # check limit with a grace time
        now = self._timestamp(dt.datetime.utcnow() - dt.timedelta(minutes=self._grace))
        if now > limit:
            log.debug("AUTH (fsa token): token {token} has expired")
            raise AuthException("expired fsa auth token", 401)
        # all is well
        return user, limit

    def _get_jwt_token_auth_real(self, token):
        """Tell whether JWT token is ok: return validated user or None.

        This function is expected to be cached, so it returns the token
        expiration so that it can be rechecked later.
        """
        import jwt
        try:
            data = jwt.decode(token, self._secret, leeway=self._delay * 60,
                              audience=self._realm, algorithms=[self._algo])
            exp = dt.datetime.fromtimestamp(data["exp"])
            return data["sub"], exp
        except jwt.ExpiredSignatureError:
            log.debug(f"AUTH (jwt token): token {token} has expired")
            raise AuthException("expired jwt auth token", 401)
        except Exception as e:
            log.debug(f"AUTH (jwt token): invalide token ({e})")
            raise AuthException("invalid jwt token", 401)

    def _get_jwt_token_auth(self, token):
        """Tell whether JWT token is ok: return validated user or None.

        This function is not cached, it uses the cached version and rechecks
        the expiration limit."""
        user, exp = self._get_jwt_token_auth_real(token)
        # recheck token expiration
        now = dt.datetime.utcnow() - dt.timedelta(minutes=self._grace)
        if now > exp:
            log.debug(f"AUTH (jwt token): token {token} has expired")
            raise AuthException("expired jwt auth token", 401)
        return user, self._timestamp(exp)

    def _get_token_auth_exp(self, token):
        """Tell whether token is ok: return validated user or None."""
        log.debug(f"{self._token} token: {token}")
        if token is None or token == "":
            log.debug("AUTH (token): no token")
            raise AuthException("missing auth token", 401)
        return \
            self._get_fsa_token_auth(token) if self._token == "fsa" else \
            self._get_jwt_token_auth(token)

    def _get_token_auth(self, token):
        """Tell whether token is ok: return validated user or None."""
        return self._get_token_auth_exp(token)[0]

    def _get_cookie_auth(self):
        """Get user from cookie authentication."""
        return self._get_token_auth(request.cookies[self._name]) \
            if self._name in request.cookies else None

    # map auth types to their functions
    _FSA_AUTH = {
        "basic": _get_basic_auth,
        "param": _get_param_auth,
        "password": _get_password_auth,
        "fake": _get_fake_auth,
        "http-basic": _get_http_auth,
        "http-digest": _get_http_auth,
        "digest": _get_http_auth,
        "http-token": _get_http_auth,
    }

    def get_user(self):
        """Authenticate user or throw exception."""
        log.debug(f"get_user for {self._auth}")

        # _user is reset before/after requests
        # so relying on in-request persistance is safe
        if self._user is not None:
            return self._user

        a = self._auth
        if a is None:
            raise AuthException("FlaskSimpleAuth not initialized", 500)

        elif a == "none":
            return None

        elif a == "httpd":
            self._user = request.remote_user

        elif a in ("fake", "basic", "param", "password", "token", "http-basic",
                   "http-digest", "http-token", "digest"):

            # check for token
            if self._token is not None:
                if self._auth == "http-token":
                    # force Flask HTTPAuth token
                    self._user = self._get_http_auth()
                elif self._carrier == "bearer":
                    auth = request.headers.get("Authorization", None)
                    if auth is not None:
                        slen = len(self._name) + 1
                        if auth[:slen] == f"{self._name} ":  # FIXME lower case?
                            self._user = self._get_token_auth(auth[slen:])
                    # else we ignore… maybe it will be resolved later
                elif self._carrier == "cookie":
                    self._user = self._get_cookie_auth()
                elif self._carrier == "param":
                    params = request.json or request.values
                    token = params.get(self._name, None)
                    if token is not None:
                        self._user = self._get_token_auth(token)
                elif self._carrier == "header":
                    token = request.headers.get(self._name, None)
                    if token is not None:
                        self._user = self._get_token_auth(token)
                # else: cannot get there

            # else try other schemes
            if self._user is None:
                if a in self._FSA_AUTH:
                    self._user = self._FSA_AUTH[a](self)
                else:
                    raise AuthException("auth token is required", 401)

        else:
            raise AuthException(f"unexpected authentication type: {a}", 500)

        assert self._user is not None  # else an exception would have been raised
        log.info(f"get_user({self._auth}): {self._user}")
        return self._user

    def current_user(self):
        """Return current authenticated user, if any."""
        return self._user

    def _set_caches(self):
        """Create caches around jwt token and hooks."""
        for name in ("_get_jwt_token_auth_real", "_get_user_pass", "_user_in_group"):
            fun = getattr(self, name)
            if fun is not None and hasattr(fun, "__wrapped__"):
                fun = fun.__wrapped__
            setattr(self, name, self._cache_function(fun))

    def clear_caches(self):
        """Clear internal caches."""
        for name in ("_get_jwt_token_auth_real", "_get_user_pass", "_user_in_group"):
            fun = getattr(self, name)
            if fun is not None and hasattr(fun, "cache_clear"):
                fun.cache_clear()

    #
    # authorize internal decorator
    #
    def _authorize(self, *groups):
        """Decorator to authorize groups."""

        if len(groups) > 1 and \
           (ANY in groups or ALL in groups or NONE in groups or None in groups):
            raise Exception("must not mix ANY/ALL/NONE and other groups")

        if ANY not in groups and ALL not in groups and \
           NONE not in groups and None not in groups:
            assert self._user_in_group is not None, \
                "user_in_group callback needed for authorize"

        def decorate(fun: Callable):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                # track that some autorization check was performed
                self._need_authorization = False
                # shortcuts
                if NONE in groups or None in groups:
                    return Resp("", 403)
                if ANY in groups:
                    return fun(*args, **kwargs)
                # get user if needed
                if self._user is None:
                    # no current user, try to get one?
                    if self._mode != "always":
                        try:
                            self._user = self.get_user()
                        except AuthException:
                            return Resp("", 401)
                    else:
                        return Resp("", 401)
                if self._user is None:
                    return Resp("", 401)
                # shortcut for authenticated users
                if ALL in groups:
                    return fun(*args, **kwargs)
                # check against all authorized groups/roles
                for r in groups:
                    if self._user_in_group(self._user, r):
                        return fun(*args, **kwargs)
                # else no matching group
                return Resp("", 403)

            return wrapper

        return decorate

    #
    # parameters internal decorator
    #
    # required:
    # - None: function parameters are required unless there is a default value
    # - True: all function parameters are required
    # - False: all function parameters are optional,
    #   with default value None unless explicitely provided
    #
    # allparams:
    # - whether all request parameters are automatically translated to function
    #   parameters with a str value.
    #
    def _parameters(self, required=None, allparams=False):
        """Decorator to handle request parameters."""

        def decorate(fun: Callable):

            types: Dict[str, type] = {}
            typings: Dict[str, Callable[[str], Any]] = {}
            defaults: Dict[str, Any] = {}

            # parameters types/casts and defaults from signature
            sig = inspect.signature(fun)

            for n, p in sig.parameters.items():
                if n not in types and \
                   p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL):
                    # guess parameter type
                    t = typeof(p)
                    types[n] = t
                    typings[n] = CASTS.get(t, t)
                if p.default != inspect._empty:
                    defaults[n] = p.default

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                # this cannot happen under normal circumstances
                if self._need_authorization and self._check:
                    return Resp("missing authorization check", 500)

                # translate request parameters to named function parameters
                params = request.json or request.values
                for p, typing in typings.items():
                    # guess which function parameters are request parameters
                    if p not in kwargs:
                        if p in params:
                            try:
                                kwargs[p] = typing(params[p])
                            except Exception as e:
                                return Resp(f"type error on HTTP parameter \"{p}\" ({e})", 400)
                        else:
                            if required is None:
                                if p in defaults:
                                    kwargs[p] = defaults[p]
                                else:
                                    return Resp(f"missing HTTP parameter \"{p}\"", 400)
                            elif required:
                                return f"missing HTTP parameter \"{p}\"", 400
                            else:
                                kwargs[p] = defaults.get(p, None)
                    else:
                        # possibly recast path parameters if needed
                        if not isinstance(kwargs[p], types[p]):
                            try:
                                kwargs[p] = typing(kwargs[p])
                            except Exception as e:
                                return Resp(f"type error on path parameter \"{p}\": ({e})", 404)

                # possibly add others, without shadowing already provided ones
                if allparams:
                    for p in params:
                        if p not in kwargs:
                            kwargs[p] = params[p]

                # then call the initial function
                return fun(*args, **kwargs)

            return wrapper

        return decorate

    def add_url_rule(self, rule, endpoint=None, view_func=None, authorize=NONE, required=None, allparams=False, **options):

        """Route decorator helper method."""

        # lazy initialization
        if not self._initialized:
            self.init_app(self._app)

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

        assert self._app is not None
        par = self._parameters(required=required, allparams=allparams)(view_func)
        aut = self._authorize(*roles)(par)
        return flask.Flask.add_url_rule(self._app, newpath, endpoint=endpoint, view_func=aut, **options)

    def route(self, rule, **options):
        """Extended `route` decorator provided by the extension."""
        if "authorize" not in options:
            log.warning(f"missing authorize on route \"{rule}\" makes it 403 Forbidden")

        def decorate(fun):
            self.add_url_rule(rule, view_func=fun, **options)
        return decorate

    # duck-typing blueprint code stealing: needs blueprints, _blueprint_order, debug
    def register_blueprint(self, blueprint, **options):
        """Register a blueprint."""
        flask.Flask.register_blueprint(self, blueprint, **options)
