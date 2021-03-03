#
# Debatable flask-side auth management
#
# This code is public domain.
#

from typing import Optional, Union, Callable, Dict, List, Any
import functools
import inspect
import datetime as dt

from flask import Flask, Response, request
from passlib.context import CryptContext  # type: ignore

import logging
log = logging.getLogger("auth")


# carry data for error Response
class AuthException(BaseException):
    def __init__(self, message: str, status: int):
        self.message = message
        self.status = status

#
# AUTH CONFIGURATION
#


# application configuration
APP: Optional[Flask] = None
CONF: Optional[Dict[str, Any]] = None

# auth type
AUTH: str = "httpd"
LAZY: bool = True
ALWAYS: bool = True
skip_path: List[Callable] = []

# auth token
TYPE: str = 'fsa'
NAME: Optional[str] = None
REALM: Optional[str] = None
SECRET: Optional[Union[str, bytes]] = None
DELAY: int = 60
GRACE: int = 0
HASH: Optional[str] = None
SIGLEN: Optional[int] = None

# parameter names
LOGIN: str = "LOGIN"
USERP: str = "USER"
PASSP: str = "PASS"

# password management
PM: Optional[CryptContext] = None

GetUserPasswordType = Optional[Callable[[str], str]]
get_user_password: GetUserPasswordType = None

# autorisation management
UserInGroupType = Optional[Union[Callable[[str, str], bool],
                                 Callable[[str, int], bool]]]
user_in_group: UserInGroupType = None

# current authenticated user
USER: Optional[str] = None


# set, or possibly just reset, the current authentication
def auth_set_user():
    global USER
    USER = None
    if not ALWAYS:
        return
    for skip in skip_path:
        if skip(request.path):
            return
    try:
        USER = get_user()
    except AuthException as e:
        return e.message, e.status
    assert USER is not None


# wipe out current authentication
def auth_after_cleanup(res: Response):
    global USER
    USER = None
    return res


# initialize module
def setConfig(app: Flask,
              gup: GetUserPasswordType = None,
              uig: UserInGroupType = None):
    #
    # overall setup
    #
    global APP, CONF, AUTH, LAZY, ALWAYS, skip_path
    APP = app
    CONF = app.config
    # auth setup
    AUTH = CONF.get("FSA_TYPE", "httpd")
    LAZY = CONF.get("FSA_LAZY", True)
    ALWAYS = CONF.get("FSA_ALWAYS", True)
    app.before_request(auth_set_user)
    app.after_request(auth_after_cleanup)
    import re
    skip_path = [re.compile(r).match for r in CONF.get("FSA_SKIP_PATH", [])]
    #
    # token setup
    #
    global TYPE, NAME, REALM, SECRET, DELAY, GRACE, HASH, SIGLEN
    TYPE = CONF.get("FSA_TOKEN_TYPE", "fsa")
    NAME = CONF.get("FSA_TOKEN_NAME", None)
    realm = CONF.get("FSA_TOKEN_REALM", app.name).lower()
    # tr -cd "[a-z0-9_]" "": is there a better way to do that?
    keep_char = re.compile(r"[-a-z0-9_]").match
    REALM = "".join(c for c in realm if keep_char(c))
    import random
    import string
    # list of 94 chars, about 6.5 bits per char
    chars = string.ascii_letters + string.digits + string.punctuation
    if "FSA_TOKEN_SECRET" in CONF:
        SECRET = CONF["FSA_TOKEN_SECRET"]
        if SECRET is not None and len(SECRET) < 16:
            log.warning("token secret is short")
    else:
        log.warning("random token secret, only ok for one process app")
        SECRET = ''.join(random.SystemRandom().choices(chars, k=40))
    DELAY = CONF.get("FSA_TOKEN_DELAY", 60)
    GRACE = CONF.get("FSA_TOKEN_GRACE", 0)
    if TYPE == "fsa":
        HASH = CONF.get("FSA_TOKEN_HASH", "blake2s")
        SIGLEN = CONF.get("FSA_TOKEN_LENGTH", 16)
    elif TYPE == "jwt":
        HASH = "HS256"
        SIGLEN = None
    else:
        raise Exception(f"invalid FSA_TOKEN_TYPE ({TYPE})")
    #
    # parameters
    #
    global LOGIN, USERP, PASSP
    LOGIN = CONF.get("FSA_FAKE_LOGIN", "LOGIN")
    USERP = CONF.get("FSA_PARAM_USER", "USER")
    PASSP = CONF.get("FSA_PARAM_PASS", "PASS")
    #
    # password setup
    #
    global PM
    # passlib context is a pain, you have to know the scheme name to set its
    # round which make it impossible to configure directly.
    scheme = CONF.get("FSA_PASSWORD_SCHEME", "bcrypt")
    options = CONF.get("FSA_PASSWORD_OPTIONS", {'bcrypt__default_rounds': 4})
    PM = CryptContext(schemes=[scheme], **options)
    #
    # hooks
    #
    global get_user_password, user_in_group
    get_user_password = gup
    user_in_group = uig


#
# HTTP FAKE AUTH
#
# Just trust a parameter, *only* for local testing.
#
# FSA_FAKE_LOGIN: name of parameter holding the login ("LOGIN")
#
def get_fake_auth():
    assert request.remote_user is None, "do not shadow web server auth"
    assert request.environ["REMOTE_ADDR"][:4] == "127.", \
        "fake auth only on localhost"
    params = request.values if request.json is None else request.json
    user = params.get(LOGIN, None)
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
def check_password(pwd, ref):
    return PM.verify(pwd, ref)


# hash password consistently with above check, can be used by app
def hash_password(pwd):
    return PM.hash(pwd)


# check user password against internal credentials
# raise an exception if not ok, otherwise simply proceeds
def check_db_password(user, pwd):
    ref = get_user_password(user)
    if ref is None:
        log.debug(f"LOGIN (password): no such user ({user})")
        raise AuthException(f"no such user: {user}", 401)
    if not check_password(pwd, ref):
        log.debug(f"LOGIN (password): invalid password for {user}")
        raise AuthException(f"invalid password for {user}", 401)


#
# HTTP BASIC AUTH
#
def get_basic_auth():
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
    check_db_password(user, pwd)
    return user


#
# HTTP PARAM AUTH
#
# User credentials provided from http or json parameters.
#
# FSA_PARAM_USER: parameter name for login ("USER")
# FSA_PARAM_PASS: parameter name for password ("PASS")
#
def get_param_auth():
    assert request.remote_user is None
    params = request.values if request.json is None else request.json
    user, pwd = params.get(USERP, None), params.get(PASSP, None)
    if user is None:
        raise AuthException(f"missing login parameter: {USERP}", 401)
    if pwd is None:
        raise AuthException(f"missing password parameter: {PASSP}", 401)
    if not request.is_secure:
        log.warning("password authentication over an insecure request")
    check_db_password(user, pwd)
    return user


#
# TOKEN AUTH
#
# The token can be checked locally with a simple hash, without querying the
# database and validating a possibly expensive salted password (+400 ms!).
#
# Its form is: <realm>:<user>:<validity-limit>:<signature>
#
# FSA_TOKEN_TYPE: 'jwt' or 'fsa'
# FSA_TOKEN_NAME: name of parameter holding the token, or None for bearer auth
# FSA_TOKEN_HASH:
# - for 'fsa': hashlib algorithm for token authentication ("blake2s")
# - for 'jwt': signature algorithm ("HS256")
# FSA_TOKEN_LENGTH:
# - for 'fsa': number of signature bytes (16)
# - for 'jwt': unused
# FSA_TOKEN_DELAY: token validity in minutes (60)
# FSA_TOKEN_GRACE: grace delay for token validity in minutes (0)
# FSA_TOKEN_SECRET: signature secret for tokens (mandatory!)
# FSA_TOKEN_REALM: token realm (lc simplified app name)
#

# sign data with secret
def compute_signature(data, secret):
    import hashlib
    h = hashlib.new(HASH)
    h.update(f"{data}:{secret}".encode())
    return h.digest()[:SIGLEN].hex()


# build a timestamp string
def get_timestamp(ts):
    return "%04d%02d%02d%02d%02d%02d" % ts.timetuple()[:6]


# compute a token for "user" valid for "delay" minutes, signed with "secret"
def get_fsa_token(realm, user, delay, secret):
    limit = get_timestamp(dt.datetime.utcnow() + dt.timedelta(minutes=delay))
    data = f"{realm}:{user}:{limit}"
    sig = compute_signature(data, secret)
    return f"{data}:{sig}"


# jwt generation
# exp = expiration, sub = subject, iss = issuer, aud = audience
def get_jwt_token(realm, user, delay, secret):
    exp = dt.datetime.utcnow() + dt.timedelta(minutes=delay)
    import jwt
    return jwt.encode({"exp": exp, "sub": user, "aud": realm},
                      secret, algorithm=HASH)


# create a new token for user depending on the configuration
def create_token(user):
    return get_fsa_token(REALM, user, DELAY, SECRET) if TYPE == "fsa" else \
           get_jwt_token(REALM, user, DELAY, SECRET)


# tell whether token is ok: return validated user or None
# token form: "realm:calvin:20380119031407:<signature>"
def get_fsa_token_auth(token):
    realm, user, limit, sig = token.split(':', 3)
    # check realm
    if realm != REALM:
        log.debug(f"LOGIN (token): unexpected realm {realm}")
        raise AuthException(f"unexpected realm: {realm}", 401)
    # check signature
    ref = compute_signature(f"{realm}:{user}:{limit}", SECRET)
    if ref != sig:
        log.debug("LOGIN (token): invalid signature")
        raise AuthException("invalid jsa auth token signature", 401)
    # check limit with a grace time
    now = get_timestamp(dt.datetime.utcnow() - dt.timedelta(minutes=GRACE))
    if now > limit:
        log.debug("LOGIN (token): token {token} has expired")
        raise AuthException("expired jsa auth token", 401)
    # all is well
    return user


def get_jwt_token_auth(token):
    import jwt
    try:
        data = jwt.decode(token, SECRET, leeway=GRACE * 60,
                          audience=REALM, algorithms=[HASH])
        return data['sub']
    except jwt.ExpiredSignatureError:
        log.debug(f"LOGIN (token): token {token} has expired")
        raise AuthException("expired jwt auth token", 401)
    except Exception as e:
        log.debug(f"LOGIN (token): invalide token ({e})")
        raise AuthException("invalid jwt token", 401)


def get_token_auth(token):
    return get_fsa_token_auth(token) if TYPE == "fsa" else \
           get_jwt_token_auth(token)


# return authenticated user or throw exception
def get_user():

    global USER

    # USER is reset before/after requests
    # so relying on in-request persistance is safe
    if USER is not None:
        return USER

    if AUTH is None:
        raise AuthException("FlaskSimpleAuth module not initialized", 500)

    if AUTH == "httpd":

        USER = request.remote_user

    elif AUTH in ("fake", "param", "basic", "token", "password"):

        # always check for token
        if SECRET is not None and SECRET != "":
            params = request.values if request.json is None else request.json
            if NAME is None:
                auth = request.headers.get("Authorization", None)
                if auth is not None and auth[:7] == "Bearer ":
                    USER = get_token_auth(auth[7:])
            else:
                token = params.get(NAME, None)
                if token is not None:
                    USER = get_token_auth(token)

        # else try other schemes
        if USER is None:
            if AUTH == "param":
                USER = get_param_auth()
            elif AUTH == "basic":
                USER = get_basic_auth()
            elif AUTH == "fake":
                USER = get_fake_auth()
            elif AUTH == "password":
                try:
                    USER = get_basic_auth()
                except AuthException:  # try param
                    USER = get_param_auth()
            else:
                raise AuthException("auth token is required", 401)

    else:

        raise AuthException(f"unexpected authentication type: {AUTH}", 500)

    assert USER is not None  # else an exception would have been raised
    log.info(f"get_user({AUTH}): {USER}")
    return USER


#
# authorize decorator
#
class authorize:

    def __init__(self, *args):
        assert user_in_group is not None, \
            "user_in_group callback needed for authorize"
        self.groups = args

    def __call__(self, fun):
        @functools.wraps(fun)
        def wrapper(*args, **kwargs):
            global USER
            if USER is None:
                # no current user, try to get one?
                if LAZY:
                    try:
                        USER = get_user()
                    except AuthException:
                        return "", 401
                else:
                    return "", 401
            if USER is None:
                return "", 401
            for g in self.groups:
                if user_in_group(USER, g):
                    return fun(*args, **kwargs)
            # else no matching group
            return "", 403
        # work around flask unwitty reliance on the function name
        return wrapper


def bool_cast(s: str) -> Optional[bool]:
    return None if s is None else \
        False if s.lower() in ("", "0", "false") else \
        True


def int_cast(s: str) -> Optional[int]:
    return None if s is None else int(s, base=0)


# note: mypy complains wrongly about non-existing _empty.
CASTS = {bool: bool_cast, int: int_cast, inspect._empty: str}


#
# autoparams decorator
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
def parameters(*args, required=None, allparams=False, **kwargs):

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
                types[n] = CASTS.get(p.annotation, p.annotation)
            if p.default != inspect._empty:
                defaults[n] = p.default

        @functools.wraps(fun)
        def wrapper(*args, **kwargs):

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
