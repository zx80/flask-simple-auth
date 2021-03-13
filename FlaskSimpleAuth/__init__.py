#
# Debatable flask-side auth management, and more.
#
# This code is public domain.
#

from typing import Optional, Callable, Dict, Any
import functools
import inspect
import datetime as dt

from flask import Flask as RealFlask
from flask import Response, request, session, jsonify, redirect, url_for
from flask import make_response, abort, render_template

import logging
log = logging.getLogger("fsa")


# carry data for error Response
class AuthException(BaseException):
    def __init__(self, message: str, status: int):
        self.message = message
        self.status = status


#
# special type casts
#
def bool_cast(s: str) -> Optional[bool]:
    return None if s is None else \
        False if s.lower() in ("", "0", "false", "f") else \
        True


def int_cast(s: str) -> Optional[int]:
    return int(s, base=0) if s is not None else None


# note: mypy complains wrongly about non-existing _empty.
CASTS = {bool: bool_cast, int: int_cast, inspect._empty: str}

# special group names
ANY = "anyone can come in, no authentication required"
ALL = "all authentified users are allowed"
NONE = "none can come int, forbidden path"


# guess parameter type
def typeof(p: inspect.Parameter):
    if p.kind == p.VAR_KEYWORD:
        return dict
    elif p.kind == p.VAR_POSITIONAL:
        return list
    elif p.annotation != inspect._empty:
        return p.annotation
    elif p.default is not None and p.default != inspect._empty:
        return type(p.default)  # type inference!
    else:
        return str


# Flask wrapper
class Flask(RealFlask):

    # constructor
    def __init__(self, *args, **kwargs):
        RealFlask.__init__(self, *args, **kwargs)
        self._fsa_get_user_pass = None
        self._fsa_user_in_group = None
        self._fsa_initialized = False
        return

    # set, or possibly just reset, the current authentication
    def _fsa_auth_set_user(self):
        self._fsa_user = None
        self._fsa_need_authorization = True
        if not self._fsa_always:
            return
        for skip in self._fsa_skip_path:
            if skip(request.path):
                return
        try:
            self._fsa_user = self.get_user()
        except AuthException as e:
            return e.message, e.status
        assert self._fsa_user is not None

    # wipe out current authentication
    def _fsa_auth_after_cleanup(self, res: Response):
        self._fsa_user = None
        if res.status_code < 400 and self._fsa_need_authorization:
            method, path = request.method, request.path
            log.warning(f"missing authorization on {method} {path}")
            if self._fsa_check:
                return Response("missing authorization check", 500)
        return res

    def get_user_pass(self, gup):
        self._fsa_get_user_pass = gup
        return gup

    def user_in_group(self, uig):
        self._fsa_user_in_group = uig
        return uig

    # actually initialize module…
    def _fsa_initialize(self):
        log.warning("FSA initialization…")
        conf = self.config
        #
        # auth setup
        #
        self._fsa_auth = conf.get("FSA_TYPE", "httpd")
        self._fsa_lazy = conf.get("FSA_LAZY", True)
        self._fsa_always = conf.get("FSA_ALWAYS", True)
        self._fsa_check = conf.get("FSA_CHECK", True)
        # register auth request hooks
        self.before_request(self._fsa_auth_set_user)
        self.after_request(self._fsa_auth_after_cleanup)
        import re
        self._fsa_skip_path = [re.compile(r).match for r in conf.get("FSA_SKIP_PATH", [])]
        #
        # token setup
        #
        self._fsa_type = conf.get("FSA_TOKEN_TYPE", "fsa")
        self._fsa_name = conf.get("FSA_TOKEN_NAME", None)
        realm = conf.get("FSA_TOKEN_REALM", self.name).lower()
        # tr -cd "[a-z0-9_]" "": is there a better way to do that?
        keep_char = re.compile(r"[-a-z0-9_]").match
        self._fsa_realm = "".join(c for c in realm if keep_char(c))
        self._fsa_delay = conf.get("FSA_TOKEN_DELAY", 60.0)
        self._fsa_grace = conf.get("FSA_TOKEN_GRACE", 0.0)
        if self._fsa_type is not None and self._fsa_type == "jwt":
            algo = conf.get("FSA_TOKEN_ALGO", "HS256")
            if algo[0] in ("R", "E", "P"):
                assert "FSA_TOKEN_SECRET" in conf and "FSA_TOKEN_SIGN" in conf, \
                    "pubkey kwt signature require explicit secret and sign"
        if "FSA_TOKEN_SECRET" in conf:
            self._fsa_secret = conf["FSA_TOKEN_SECRET"]
            if self._fsa_secret is not None and len(self._fsa_secret) < 16:
                log.warning("token secret is short")
        else:
            # list of 94 chars, about 6.5 bits per char
            import random
            import string
            log.warning("random token secret, only ok for one process app")
            chars = string.ascii_letters + string.digits + string.punctuation
            self._fsa_secret = ''.join(random.SystemRandom().choices(chars, k=40))
        if self._fsa_type is None:
            pass
        elif self._fsa_type == "fsa":
            self._fsa_sign = self._fsa_secret
            self._fsa_algo = conf.get("FSA_TOKEN_ALGO", "blake2s")
            self._fsa_siglen = conf.get("FSA_TOKEN_LENGTH", 16)
        elif self._fsa_type == "jwt":
            algo = conf.get("FSA_TOKEN_ALGO", "HS256")
            self._fsa_algo = algo
            if algo[0] in ("R", "E", "P"):
                self._fsa_sign = conf["FSA_TOKEN_SIGN"]
            elif algo[0] == "H":
                self._fsa_sign = self._fsa_secret
            elif algo == "none":
                self._fsa_sign = None
            else:
                raise Exception("unexpected jwt FSA_TOKEN_ALGO ({algo})")
            self._fsa_siglen = 0
        else:
            raise Exception(f"invalid FSA_TOKEN_TYPE ({self._fsa_type})")
        #
        # parameters
        #
        self._fsa_login = conf.get("FSA_FAKE_LOGIN", "LOGIN")
        self._fsa_userp = conf.get("FSA_PARAM_USER", "USER")
        self._fsa_passp = conf.get("FSA_PARAM_PASS", "PASS")
        #
        # password setup
        #
        # passlib context is a pain, you have to know the scheme name to set its
        # round. Ident '2y' is same as '2b' but apache compatible.
        scheme = conf.get("FSA_PASSWORD_SCHEME", "bcrypt")
        if scheme is not None:
            options = conf.get("FSA_PASSWORD_OPTIONS",
                               {'bcrypt__default_rounds': 4,
                                'bcrypt__default_ident': '2y'})
            from passlib.context import CryptContext  # type: ignore
            self._fsa_pm = CryptContext(schemes=[scheme], **options)
        else:
            self._fsa_pm = None
        #
        # hooks
        #
        if "FSA_GET_USER_PASS" in conf:
            self._fsa_get_user_pass = conf["FSA_GET_USER_PASS"]
        if "FSA_USER_IN_GROUP" in conf:
            self._fsa_user_in_group = conf["FSA_USER_IN_GROUP"]
        # done!
        self._fsa_initialized = True
        return

    #
    # HTTP FAKE AUTH
    #
    # Just trust a parameter, *only* for local testing.
    #
    # FSA_FAKE_LOGIN: name of parameter holding the login ("LOGIN")
    #
    def _fsa_get_fake_auth(self):
        assert request.remote_user is None, "do not shadow web server auth"
        assert request.environ["REMOTE_ADDR"][:4] == "127.", \
            "fake auth only on localhost"
        params = request.values if request.json is None else request.json
        user = params.get(self._fsa_login, None)
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

    # verify password
    def check_password(self, pwd, ref):
        return self._fsa_pm.verify(pwd, ref)

    # hash password consistently with above check, can be used by app
    def hash_password(self, pwd):
        return self._fsa_pm.hash(pwd)

    # check user password against internal credentials
    # raise an exception if not ok, otherwise simply proceeds
    def _fsa_check_password(self, user, pwd):
        ref = self._fsa_get_user_pass(user)
        if ref is None:
            log.debug(f"LOGIN (password): no such user ({user})")
            raise AuthException(f"no such user: {user}", 401)
        if not self.check_password(pwd, ref):
            log.debug(f"LOGIN (password): invalid password for {user}")
            raise AuthException(f"invalid password for {user}", 401)

    #
    # HTTP BASIC AUTH
    #
    def _fsa_get_basic_auth(self):
        import base64 as b64
        assert request.remote_user is None
        auth = request.headers.get("Authorization", None)
        log.debug(f"auth: {auth}")
        if auth is None or auth[:6] != "Basic ":
            log.debug(f"LOGIN (basic): unexpected auth {auth}")
            raise AuthException("missing or unexpected authorization header", 401)
        user, pwd = b64.b64decode(auth[6:]).decode().split(':', 1)
        if not request.is_secure:
            log.warning("password authentication over an insecure request")
        self._fsa_check_password(user, pwd)
        return user

    #
    # HTTP PARAM AUTH
    #
    # User credentials provided from http or json parameters.
    #
    # FSA_PARAM_USER: parameter name for login ("USER")
    # FSA_PARAM_PASS: parameter name for password ("PASS")
    #
    def _fsa_get_param_auth(self):
        assert request.remote_user is None
        params = request.values if request.json is None else request.json
        user = params.get(self._fsa_userp, None)
        if user is None:
            raise AuthException(f"missing login parameter: {self._fsa_userp}", 401)
        pwd = params.get(self._fsa_passp, None)
        if pwd is None:
            raise AuthException(f"missing password parameter: {self._fsa_passp}", 401)
        if not request.is_secure:
            log.warning("password authentication over an insecure request")
        self._fsa_check_password(user, pwd)
        return user

    #
    # TOKEN AUTH
    #
    # The token can be checked locally with a simple hash, without querying the
    # database and validating a possibly expensive salted password (+400 ms!).
    #
    #
    # FSA_TOKEN_TYPE: 'jwt' or 'fsa'
    # for fsa, the format is: <realm>:<user>:<validity-limit>:<signature>
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
    # sign data with secret
    def _fsa_cmp_sig(self, data, secret):
        import hashlib
        h = hashlib.new(self._fsa_algo)
        h.update(f"{data}:{secret}".encode())
        return h.digest()[:self._fsa_siglen].hex()

    # build a timestamp string
    def _fsa_timestamp(self, ts):
        return "%04d%02d%02d%02d%02d%02d" % ts.timetuple()[:6]

    # compute a token for "user" valid for "delay" minutes, signed with "secret"
    def _fsa_get_fsa_token(self, realm, user, delay, secret):
        limit = self._fsa_timestamp(dt.datetime.utcnow() + dt.timedelta(minutes=delay))
        data = f"{realm}:{user}:{limit}"
        sig = self._fsa_cmp_sig(data, secret)
        return f"{data}:{sig}"

    # jwt generation
    # exp = expiration, sub = subject, iss = issuer, aud = audience
    def _fsa_get_jwt_token(self, realm, user, delay, secret):
        exp = dt.datetime.utcnow() + dt.timedelta(minutes=delay)
        import jwt
        return jwt.encode({"exp": exp, "sub": user, "aud": realm},
                          secret, algorithm=self._fsa_algo)

    # create a new token for user depending on the configuration
    def create_token(self, user):
        assert self._fsa_type is not None
        realm, delay = self._fsa_realm, self._fsa_delay
        if self._fsa_type == "fsa":
            return self._fsa_get_fsa_token(realm, user, delay, self._fsa_secret)
        else:
            return self._fsa_get_jwt_token(realm, user, delay, self._fsa_sign)

    # tell whether token is ok: return validated user or None
    # token form: "realm:calvin:20380119031407:<signature>"
    def _fsa_get_fsa_token_auth(self, token):
        realm, user, limit, sig = token.split(':', 3)
        # check realm
        if realm != self._fsa_realm:
            log.debug(f"LOGIN (token): unexpected realm {realm}")
            raise AuthException(f"unexpected realm: {realm}", 401)
        # check signature
        ref = self._fsa_cmp_sig(f"{realm}:{user}:{limit}", self._fsa_secret)
        if ref != sig:
            log.debug("LOGIN (token): invalid signature")
            raise AuthException("invalid jsa auth token signature", 401)
        # check limit with a grace time
        now = self._fsa_timestamp(dt.datetime.utcnow() - dt.timedelta(minutes=self._fsa_grace))
        if now > limit:
            log.debug("LOGIN (token): token {token} has expired")
            raise AuthException("expired jsa auth token", 401)
        # all is well
        return user

    def _fsa_get_jwt_token_auth(self, token):
        import jwt
        try:
            data = jwt.decode(token, self._fsa_secret, leeway=self._fsa_delay * 60,
                              audience=self._fsa_realm, algorithms=[self._fsa_algo])
            return data['sub']
        except jwt.ExpiredSignatureError:
            log.debug(f"LOGIN (token): token {token} has expired")
            raise AuthException("expired jwt auth token", 401)
        except Exception as e:
            log.debug(f"LOGIN (token): invalide token ({e})")
            raise AuthException("invalid jwt token", 401)

    def _fsa_get_token_auth(self, token):
        log.debug(f"checking token: {token}")
        return \
            self._fsa_get_fsa_token_auth(token) if self._fsa_type == "fsa" else \
            self._fsa_get_jwt_token_auth(token)

    def _fsa_get_password_auth(self):
        try:
            return self._fsa_get_basic_auth()
        except AuthException:  # try param
            return self._fsa_get_param_auth()

    # map auth types to their functions
    _FSA_AUTH = {"basic": _fsa_get_basic_auth,
                 "param": _fsa_get_param_auth,
                 "password": _fsa_get_password_auth,
                 "fake": _fsa_get_fake_auth}

    # return authenticated user or throw exception
    def get_user(self):
        log.debug(f"get_user for {self._fsa_auth}")

        # _fsa_user is reset before/after requests
        # so relying on in-request persistance is safe
        if self._fsa_user is not None:
            return self._fsa_user

        AUTH = self._fsa_auth
        if AUTH is None:
            raise AuthException("FlaskSimpleAuth not initialized", 500)

        if AUTH == "httpd":

            self._fsa_user = request.remote_user

        elif AUTH in ("fake", "param", "basic", "token", "password"):

            # check for token
            if self._fsa_type is not None:
                params = request.values if request.json is None else request.json
                if self._fsa_name is None:
                    auth = request.headers.get("Authorization", None)
                    if auth is not None and auth[:7] == "Bearer ":
                        self._fsa_user = self._fsa_get_token_auth(auth[7:])
                else:
                    token = params.get(self._fsa_name, None)
                    if token is not None:
                        self._fsa_user = self._fsa_get_token_auth(token)

            # else try other schemes
            if self._fsa_user is None:
                if AUTH in self._FSA_AUTH:
                    self._fsa_user = self._FSA_AUTH[AUTH](self)
                else:
                    raise AuthException("auth token is required", 401)

        else:
            raise AuthException(f"unexpected authentication type: {AUTH}", 500)

        assert self._fsa_user is not None  # else an exception would have been raised
        log.info(f"get_user({self._fsa_auth}): {self._fsa_user}")
        return self._fsa_user

    #
    # authorize internal decorator
    #
    def _fsa_authorize(self, *groups):

        if len(groups) > 1 and \
           (ANY in groups or ALL in groups or NONE in groups or None in groups):
            raise Exception("must not mix OPEN/AUTHENTICATED/FORBIDDEN "
                            "and other groups")

        if ANY not in groups and ALL not in groups and \
           NONE not in groups and None not in groups:
            assert self._fsa_user_in_group is not None, \
                "user_in_group callback needed for authorize"

        def decorate(fun):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                # track that some autorization check was performed
                self._fsa_need_authorization = False
                # shortcuts
                if NONE in groups or None in groups:
                    return "", 403
                if ANY in groups:
                    return fun(*args, **kwargs)
                # get user if needed
                if self._fsa_user is None:
                    # no current user, try to get one?
                    if self._fsa_lazy:
                        try:
                            self._fsa_user = self.get_user()
                        except AuthException:
                            return "", 401
                    else:
                        return "", 401
                if self._fsa_user is None:
                    return "", 401
                # shortcut for authenticated users
                if ALL in groups:
                    return fun(*args, **kwargs)
                # check against all authorized groups/roles
                for g in groups:
                    if self._fsa_user_in_group(self._fsa_user, g):
                        return fun(*args, **kwargs)
                # else no matching group
                return "", 403

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
    # others:
    # - args: list of expected parameters, implicit type is str
    # - kwargs: list of expected parameters, explicit type as a value
    #
    def _fsa_parameters(self, *args, required=None, allparams=False, **kwargs):

        def decorate(fun):

            types: Dict[str, Callable] = {}
            defaults: Dict[str, Any] = {}

            # parameters types from **kwargs
            for n, t in kwargs.items():
                if n not in types:
                    types[n] = CASTS.get(t, t)
                else:
                    log.warning(f"ignoring *kwargs decorator parameter {n}")

            # parameters from *args
            for n in args:
                if n not in types:
                    types[n] = str
                else:
                    log.warning(f"ignoring *args decorator parameter {n}")

            # parameters types/casts and defaults from signature
            sig = inspect.signature(fun)

            for n, p in sig.parameters.items():
                if n not in types and \
                   p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL):
                    # guess parameter type
                    t = typeof(p)
                    types[n] = CASTS.get(t, t)
                if p.default != inspect._empty:
                    defaults[n] = p.default

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                # this cannot happen under normal circumstances because
                if self._fsa_need_authorization and self._fsa_check:
                    return "missing authorization check", 500

                # translate request parameters to named function parameters
                params = request.values if request.json is None else request.json
                for p, typing in types.items():
                    # guess which function parameters are request parameters
                    if p not in kwargs:
                        if p in params:
                            try:
                                kwargs[p] = typing(params[p])
                            except Exception as e:
                                return f"type error on parameter {p} ({e})", 400
                        else:
                            if required is None:
                                if p in defaults:
                                    kwargs[p] = defaults[p]
                                else:
                                    return f"missing parameter {p}", 400
                            elif required:
                                return f"missing parameter {p}", 400
                            else:
                                kwargs[p] = defaults.get(p, None)

                # possibly add others, without shadowing already provided ones
                if allparams:
                    for p in params:
                        if p not in kwargs:
                            kwargs[p] = params[p]

                # then call the initial function
                return fun(*args, **kwargs)

            return wrapper

        return decorate

    #
    # route decorator wrapper
    #
    def route(self, path, *args, **kwargs):

        # lazy initialization
        if not self._fsa_initialized:
            self._fsa_initialize()

        # we intercept the authorize parameter
        if 'authorize' in kwargs:
            roles = kwargs['authorize']
            del kwargs['authorize']
        else:
            roles = NONE

        # and make it a list/tuple
        if isinstance(roles, str):
            roles = (roles,)
        elif isinstance(roles, int):
            roles = (roles,)

        from collections.abc import Iterable
        assert isinstance(roles, Iterable)

        # named parameters for parameters decorator
        authkw = {}
        for kw in ('allparams', 'required'):
            if kw in kwargs:
                authkw[kw] = kwargs[kw]
                del kwargs[kw]

        def decorate(fun: Callable):
            from uuid import UUID
            # add the expected type to path sections, if available
            # flask converter types: string (default), int, float, path, uuid
            sig = inspect.signature(fun)

            splits = path.split("<")
            for i, s in enumerate(splits):
                if i > 0:
                    spec, remainder = s.split(">", 1)
                    if ":" not in spec and spec in sig.parameters:
                        t = typeof(sig.parameters[spec])
                        if t in (int, float, UUID):
                            splits[i] = f"{t.__name__.lower()}:{spec}>{remainder}"
                        else:
                            splits[i] = f"string:{spec}>{remainder}"
            newpath = '<'.join(splits)

            apar = self._fsa_authorize(*roles)(self._fsa_parameters(**authkw)(fun))
            return RealFlask.route(self, newpath, *args, **kwargs)(apar)

        return decorate
