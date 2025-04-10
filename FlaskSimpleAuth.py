"""
Flask Extension and Wrapper

This extension helps manage:

- authentication
- authorization
- parameters
- and more…

This code is public domain.
"""

# TODO refactoring
# - clarify manager public/private interfaces

import os
import sys
from typing import Callable, Any
import typing
import types
from enum import IntEnum
import dataclasses
import functools
import inspect

import base64
import datetime as dt
import json
import uuid

try:
    import re2 as re  # type: ignore
except ModuleNotFoundError:
    import re  # type: ignore

import flask
import werkzeug.exceptions as exceptions
from werkzeug.datastructures import FileStorage, CombinedMultiDict

import ProxyPatternPool as ppp  # type: ignore

# for local use & forwarding
# NOTE the only missing should be "Flask"
from flask import (
    Response, Request, request, session, Blueprint, make_response,
    abort, redirect, url_for, after_this_request, send_file, current_app, g,
    send_from_directory, render_template, get_flashed_messages,
    has_app_context, has_request_context, render_template_string,
    stream_with_context,
)

from importlib.metadata import version as pkg_version

import logging
log = logging.getLogger("fsa")

# get module version (should it be deprecated?)
__version__ = pkg_version("FlaskSimpleAuth")


class Hooks:
    """This class holds all hook types used by FlaskSimpleAuth."""

    ErrorResponseFun = Callable[[str, int, dict[str, str]|None, str|None], Response]
    """Generate an error response for message and status.

    :param description: description string of the error.
    :param status: HTTP status code.
    :param headers: dict of additional headers.
    :param content_type: HTTP content type.

    Must return a Response.

    The function mimics flask.Response("message", status, headers, content_type).
    """

    GetUserPassFun = Callable[[str], str|None]
    """Get password from user login, None if unknown.

    :param login: user name to retrieve password for.

    Returns the string, or None if no password for user.
    """

    GroupCheckFun = Callable[[str], bool]
    """Tell whether a user belongs to some group.

    :param login: user name.

    Returns whether the user belongs to some group by calling
    the appropriate callback.
    """

    UserInGroupFun = Callable[[str, str|int], bool|None]
    """Is user login in group (str or int): yes, no, unknown.

    :param login: user name to check for group membership.
    :param group: group name or number to check for membership.

    Returns whether the user belongs to the group.
    This is a fallback for the previous per-group method.
    """

    ObjectPermsFun = Callable[[str, Any, str|None], bool|None]
    """Check object access in domain, for parameter, in mode.

    :param login: user name.
    :param oid: object identifier, must a key.
    :param mode: optional operation the user wants to perform on the object.

    Returns whether permission is granted.
    """

    PasswordCheckFun = Callable[[str, str], bool|None]
    """Low level check login/password validity.

    :param login: user name.
    :param password: the password as provided.

    Returns whether password is valid for user.
    """

    PasswordQualityFun = Callable[[str], bool|Any]
    """Is this password quality suitable?

    :param password: the submitted password.

    Returns whether the password is acceptable.
    """

    CastFun = Callable[[str|Any], object]
    """Cast parameter value to some object.

    :param data: initial data, usually a string.

    Returns the converted object.
    """

    SpecialParameterFun = Callable[[str], Any]
    """Generate a "special" parameter, with the parameter name.

    :param name: parameter name (usually not needed).
    :param ...: optional special parameters.

    Returns an object which will be the parameter value.
    """

    HeaderFun = Callable[[Response, str], str|None]
    """Add a header to the current response.

    :param response: response to consider.
    :param header: name of header.

    Returns the header value, or *None*.
    """

    BeforeRequestFun = Callable[[Request], Response|None]
    """Before request hook, with request provided.

    :param request: current request.

    Returns a response (to shortcut), or *None* to continue.
    """

    BeforeExecFun = Callable[[Request, str|None, str|None], Response|None]
    """After authentication and right before execution.

    :param request: current request.
    :param login: user name of authenticated user.
    :param auth: authentication scheme used.
    """

    AfterRequestFun = Callable[[Response], Response]
    """After request hook."""

    # FIXME Any is really FlaskSimpleAuth, but python lacks forward declarations
    AuthenticationFun = Callable[[Any, Request], str|None]
    """Authentication hook.

    :param app: current application.
    :param request: current request.

    Returns the authenticated user name, or *None*.
    """

    JSONConversionFun = Callable[[Any], Any]
    """JSON conversion hook.

    :param o: object of some type.

    Returns a JSON serializable something from an object instance.
    """

    PathCheckFun = Callable[[str, str], str|None]
    """Path checking hook.

    :param method: method used on path.
    :param path: path to be checked.

    Allow to check path rules.
    Returns an error message or *None* if all is well.
    """


@dataclasses.dataclass
class ErrorResponse(BaseException):
    """Exception class to carry fields for an error Response.

    Use this exception from hooks to trigger an error response.
    """
    # NOTE this should maybe inherit from exceptions.HTTPException?
    message: str
    status: int
    headers: dict[str, str]|None = None
    content_type: str|None = None


def err(*args, **kwargs):
    """Shorcut function to trigger an error response.

    It can be used inside an expression, eg: ``_ = res or err("no data", 404)``
    """
    raise ErrorResponse(*args, **kwargs)


class ConfigError(BaseException):
    """FSA User Configuration Error.

    This error is raised on errors detected while initializing the application.
    """
    pass


class _Mode(IntEnum):
    """FSA running modes."""
    UNDEF = 0
    PROD = 1
    DEV = 2
    DEBUG = 3
    DEBUG1 = 3
    DEBUG2 = 4
    DEBUG3 = 5
    DEBUG4 = 6


_MODES = {
    "debug1": _Mode.DEBUG1,
    "debug2": _Mode.DEBUG2,
    "debug3": _Mode.DEBUG3,
    "debug4": _Mode.DEBUG4,
    "debug": _Mode.DEBUG,
    "dev": _Mode.DEV,
    "prod": _Mode.PROD,
}


#
# TYPE CASTS
#
class path(str):
    """Type to distinguish str path parameters.

    Use this type as hint for a route parameter to trigger a Flask route path
    parameter. A path may contain ``/`` characters.
    """
    pass


class string(str):
    """Type to distinguish str string parameters.

    Use this type as hint for a route parameter to trigger a Flask route string
    parameter. A string may not contain ``/`` characters.
    """
    pass


# "JsonData = json.loads" would do:-)
class JsonData:
    """Magic JSON parameter type.

    This triggers interpretting a parameter as JSON when used as a parameter
    type on a route.
    """
    pass


class Session:
    """Session parameter type.

    This provides the session object when used as a parameter type on a route.
    """
    pass


class Globals:
    """Globals parameter type.

    This provides the g (globals) object when used as a parameter type on a route.
    """
    pass


class Environ:
    """Environ parameter type.

    This provides the WSGI environ object when used as a parameter type on a route.
    """
    pass


class CurrentUser(str):
    """CurrentUser parameter type.

    This provides the authenticated user (str) when used as a parameter type on a route.
    """
    pass


class CurrentApp:
    """CurrentApp parameter type.

    This provides the current application object when used as a parameter type on a route.
    """
    pass


class Cookie(str):
    """Application Cookie parameter type.

    This provides the cookie value (str) when used as a parameter type on a route.
    The `name` of the parameter is the cookie name.
    """
    pass


class Header(str):
    """Request Header parameter type.

    This provides the header value (str) when used as a parameter type on a route.
    The `name` of the parameter is the header name (case insensitive, underscore for dash).
    """
    pass


#
# SPECIAL PREDEFINED GROUP NAMES
#
ANY, ALL, NONE = "ANY", "ALL", "NONE"  # deprecated constants and values…

_OPEN = {"OPEN", "ANY", "NOAUTH"}
"""Open route, no authentication."""

_AUTH = {"AUTH", "AUTHENTICATED", "ALL"}
"""Authenticated route."""

_CLOSE = {"CLOSE", "NONE", "NOBODY"}
"""Closed route."""

_PREDEFS = _OPEN | _AUTH | _CLOSE
"""All predefined pseudo-group names."""

_DEPRECATED_GROUPS = {"ANY", "ALL", "NONE"}
"""Deprecated pseudo-group names."""


def _is_predef(la: list[Any], s: set[str]):
    return any(map(lambda i: i in s, la))


def _is_open(la: list[Any]):
    return _is_predef(la, _OPEN)


def _is_auth(la: list[Any]):
    return _is_predef(la, _AUTH)


def _is_close(la: list[Any]):
    return _is_predef(la, _CLOSE)


def _is_optional(t) -> bool:
    """Tell whether type is marked as optional."""
    return (
        # T|None or None|Type
        (isinstance(t, types.UnionType) and len(t.__args__) == 2 and
         (t.__args__[0] == type(None) or t.__args__[0] is None or
          t.__args__[1] == type(None) or t.__args__[1] is None)) or
        (isinstance(t, types.UnionType) and len(t.__args__) == 2 and t.__args__[0] == type(None)) or
        # Optional[T]
        (hasattr(t, "__name__") and t.__name__ == "Optional") or  # type: ignore
        # Union[None, T] or Union[T, None]
        (hasattr(t, "__origin__") and t.__origin__ is typing.Union and  # type: ignore
         len(t.__args__) == 2 and (t.__args__[0] == type(None) or t.__args__[1] == type(None)))
    )


def _type(t) -> str:
    """Return type name for error message display."""
    return type(t).__name__


def _valid_type(t) -> bool:
    """Return if type t is consistent with _check_type expectations."""
    if t in (None, bool, int, float, str, types.NoneType):
        return True
    elif isinstance(t, types.GenericAlias):
        if t.__name__ == "list":
            assert len(t.__args__) == 1
            return _valid_type(t.__args__[0])
        elif t.__name__ == "dict":
            assert len(t.__args__) == 2
            ktype, vtype = t.__args__
            return issubclass(ktype, str) and _valid_type(ktype) and _valid_type(vtype)
        else:  # TODO tuple set named-dict (?)
            return False
    elif isinstance(t, types.UnionType):
        return all(_valid_type(a) for a in t.__args__)
    elif hasattr(t, "__origin__") and t.__origin__ is typing.Union:  # pragma: no cover
        return any(_valid_type(a) for a in t.__args__)
    elif hasattr(t, "__name__") and t.__name__ == "Optional":  # type: ignore  # pragma: no cover
        assert len(t.__args__) == 1
        return _valid_type(t.__args__[0])
    else:  # FIXME should accept reasonable types? Allow convertion?
        return False


# TODO caster?
def _check_type(t, v) -> bool:
    """Dynamically and recursively check whether v is compatible with t."""
    if t is None or t == types.NoneType:
        return v is None
    elif t == int:  # beware that bool is also an int
        return isinstance(v, int) and not isinstance(v, bool)
    elif t in (bool, float, str):  # simple types
        return isinstance(v, t)
    elif isinstance(t, types.GenericAlias):  # generic types
        if t.__name__ == "list":
            assert len(t.__args__) == 1
            item_type, = t.__args__
            return isinstance(v, list) and all(_check_type(item_type, i) for i in v)
        elif t.__name__ == "dict":
            assert len(t.__args__) == 2
            key_type, val_type = t.__args__
            return isinstance(v, dict) and all(
                _check_type(key_type, key) and _check_type(val_type, val) for key, val in v.items())
        # TODO set? tuple?
        else:  # pragma: no cover
            raise ValueError(f"unsupported generic type: {t.__name__}")
    elif isinstance(t, types.UnionType):  # |
        return any(_check_type(a, v) for a in t.__args__)
    elif hasattr(t, "__origin__") and t.__origin__ is typing.Union:  # Union  # pragma: no cover
        return any(_check_type(a, v) for a in t.__args__)
    elif hasattr(t, "__name__") and t.__name__ == "Optional":  # type: ignore  # pragma: no cover
        assert len(t.__args__) == 1
        return v is None or _check_type(t.__args__[0], v)
    else:  # whatever type
        return isinstance(v, t)


def _is_list_of(t) -> Any:
    if isinstance(t, types.GenericAlias) and t.__name__ == "list":
        if len(t.__args__) == 1:
            return t.__args__[0]
        else:  # pragma: no cover  # cannot happen, "list" is not "list[*]"
            return str
    return None


def _is_generic_type(p: inspect.Parameter) -> bool:
    """Tell whether parameter is a generic type."""
    a = p.annotation
    if a is inspect._empty:
        return False
    elif _is_optional(a):
        a = a.__args__[0]
    return isinstance(a, (types.GenericAlias, types.UnionType))


def _typeof(p: inspect.Parameter):
    """Guess parameter type, possibly with some type inference."""
    if p.kind is inspect.Parameter.VAR_KEYWORD:  # **kwargs
        return dict
    elif p.kind is inspect.Parameter.VAR_POSITIONAL:  # *args
        return list
    elif p.annotation is not inspect._empty:
        anno = p.annotation
        if _is_optional(anno):  # skip optional (3 forms)
            a = anno.__args__[0]
            if a in (None, types.NoneType):
                a = anno.__args__[1]
        else:
            a = anno
        return a
    elif p.default and p.default is not inspect._empty:
        return type(p.default)
    else:
        return str


def _json_prepare(a: Any):
    """Extended JSON conversion for Flask."""
    # special cases for data structures
    if hasattr(a, "model_dump"):  # Pydantic BaseModel
        return a.model_dump()
    elif hasattr(a, "__pydantic_fields__"):  # Pydantic dataclass
        return dataclasses.asdict(a)
    elif hasattr(a, "__dataclass_fields__"):  # standard dataclass
        return dataclasses.asdict(a)
    else:  # do nothing, rely on flask's jsonify
        return a


def _json_stream(gen):
    """Stream a generator output as a JSON array.

    This may or may not be a good idea depending on the database driver and
    WSGI server behavior. To ensure a direct string output, consider setting
    ``FSA_JSON_STREAMING`` to false.
    """
    yield "["
    comma = False
    for i in gen:
        if comma:
            yield ","
        else:
            comma = True
        yield flask.json.dumps(_json_prepare(i))
    yield "]\n"


_fsa_json_streaming = True


class _JSONProvider(flask.json.provider.DefaultJSONProvider):  # type: ignore
    """FlaskSimpleAuth Internal JSON Provider.

    Convertion to str based on types for date, datetime, time, timedelta,
    timezone and UUID.

    :param allstr: whether convert unexpected types to ``str``.
    """

    def __init__(self, app, allstr: bool = False):
        super().__init__(app)
        self._typemap: dict[Any, Hooks.JSONConversionFun] = {
            # override defaults to avoid English-specific RFC822
            dt.date: str,
            dt.datetime: str,
            # add missing types
            dt.time: str,
            dt.timedelta: str,
            dt.timezone: str,
            uuid.UUID: str,
        }
        self._skip: tuple[type, ...] = tuple()
        _ = allstr and self._set_allstr()

    def set_allstr(self):
        self._skip = (str, float, bool, int, list, tuple, dict, type(None))

    def add_converter(self, t: Any, h: Hooks.JSONConversionFun):
        self._typemap[t] = h

    def default(self, o: Any):
        """Extended JSON conversion for Flask."""
        # special cases for data structures
        if hasattr(o, "model_dump"):  # Pydantic BaseModel  # pragma: no cover
            return o.model_dump()
        elif hasattr(o, "__pydantic_fields__"):  # Pydantic dataclass
            return dataclasses.asdict(o)
        elif hasattr(o, "__dataclass_fields__"):  # standard dataclass  # pragma: no cover
            return dataclasses.asdict(o)
        else:
            if encoder := self._typemap.get(type(o), None):
                return encoder(o)
            elif self._skip and not isinstance(o, self._skip):
                return str(o)
            else:  # FIXME # pragma: no cover
                super().default(o)


def jsonify(a: Any) -> Response:
    """Jsonify something, including generators, dataclasses and pydantic stuff.

    This is somehow an extension of Flask own jsonify, although it takes only
    one argument.

    NOTE on generators, the generator output is json-streamed instead of being
    treated as a string or bytes generator.
    """
    if isinstance(a, Response):
        return a
    elif inspect.isgenerator(a) or type(a) in (map, filter, range):
        out = _json_stream(a)
        if not _fsa_json_streaming:  # switch to string
            out = "".join(out)
        return Response(out, mimetype="application/json")
    else:
        return flask.jsonify(_json_prepare(a))


def checkPath(method: str, path: str) -> str|None:
    """Convenient function to use as a path checking hook.

    The path must only contain lower-case ascii characters possibly interspersed
    with dashes `-`, and not contain method names.
    """

    if not re.match(r"(/[a-z]+(-[a-z]+)*|/<[^>]+>)+", path):
        return f"invalid path section: {path}"
    if re.search(r"\b(get|post|put|patch|delete)\b", path, re.I):
        return f"path contains a method name: {path}"


class Reference(ppp.Proxy):
    """Convenient object wrapper class.

    This is a very thin wrapper around ProxyPatternPool Proxy class.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class Flask(flask.Flask):
    """Flask class wrapper.

    The class behaves mostly as a Flask class, but supports extensions:

    - the ``route`` decorator manages authentication, authorization and
      parameters transparently.
    - per-methods shortcut decorators allow to handle root for a given
      method: ``get``, ``post``, ``put``, ``patch``, ``delete``.
    - ``make_response`` slightly extends its parent to allow changing
      the default content type and handle *None* body.
    - several additional methods are provided: ``get_user_pass``,
      ``user_in_group``, ``group_check``, ``check_password``, ``hash_password``,
      ``create_token``, ``get_user``, ``current_user``, ``clear_caches``,
      ``cast``, ``object_perms``, ``user_scope``, ``password_quality``,
      ``password_check``, ``add_group``, ``add_scope``, ``add_headers``,
      ``error_response``, ``authentication``…

    See ``FlaskSimpleAuth`` class documentation about these methods.
    """

    def __init__(self, *args, debug: bool = False, **kwargs):
        # extract FSA-specific directives
        fsaconf: dict[str, Any] = {}
        for key, val in kwargs.items():
            if key.startswith("FSA_"):
                fsaconf[key] = val
        for key in fsaconf:
            del kwargs[key]
        # Flask actual initialization
        super().__init__(*args, **kwargs)
        # FSA extension initialization
        self._fsa = FlaskSimpleAuth(self, debug=debug, **fsaconf)
        # overwritten late because called by upper Flask initialization for "static"
        setattr(self, "add_url_rule", self._fsa.add_url_rule)
        # forward hooks
        self.error_response = self._fsa.error_response
        self.get_user_pass = self._fsa.get_user_pass
        self.user_in_group = self._fsa.user_in_group
        self.group_check = self._fsa.group_check
        self.object_perms = self._fsa.object_perms
        self.user_scope = self._fsa.user_scope
        # decorators
        self.cast = self._fsa.cast
        self.special_parameter = self._fsa.special_parameter
        self.password_quality = self._fsa.password_quality
        self.password_check = self._fsa.password_check
        self.add_group = self._fsa.add_group
        self.add_scope = self._fsa.add_scope
        self.add_headers = self._fsa.add_headers
        self.before_exec = self._fsa.before_exec
        self.authentication = self._fsa.authentication
        self.add_json_converter = self._fsa.add_json_converter
        # forward methods
        self.check_password = self._fsa.check_password
        self.check_user_password = self._fsa.check_user_password
        self.hash_password = self._fsa.hash_password
        self.create_token = self._fsa.create_token
        self.get_user = self._fsa.get_user
        self.current_user = self._fsa.current_user
        self.clear_caches = self._fsa.clear_caches
        self.password_uncache = self._fsa.password_uncache
        self.token_uncache = self._fsa.token_uncache
        self.group_uncache = self._fsa.group_uncache
        self.object_perms_uncache = self._fsa.object_perms_uncache
        self.user_token_uncache = self._fsa.user_token_uncache
        self.auth_uncache = self._fsa.auth_uncache
        self.path_check = self._fsa.path_check
        # overwrite decorators ("route" done through add_url_rule above)
        setattr(self, "get", self._fsa.get)  # FIXME avoid mypy warnings
        setattr(self, "put", self._fsa.put)
        setattr(self, "post", self._fsa.post)
        setattr(self, "patch", self._fsa.patch)
        setattr(self, "delete", self._fsa.delete)
        # json provider
        self.json = self._fsa._app.json

    def make_response(self, rv) -> Response:
        """Create a Response.

        This method handles overriding the default ``Content-Type`` and accepts
        a *None* body.
        """
        # handle None body as empty
        if rv is None:
            rv = ("", 200)
        elif isinstance(rv, tuple) and rv[0] is None:
            rv = ("",) + rv[1:]
        # use flask to create a response
        res = super().make_response(rv)
        # possibly override Content-Type header
        if self._fsa._rm._default_type:
            val = rv[0] if isinstance(rv, tuple) else rv
            if type(val) in (bytes, str):
                res.content_type = self._fsa._rm._default_type if len(val) else "text/plain"
            elif type(rv) in (typing.Generator, typing.Iterator):  # pragma: no cover
                res.content_type = self._fsa._rm._default_type
        return res


# significant default settings are centralized here
class Directives:
    """Documentation for configuration directives.

    This class presents *all* configuration directives, their expected type and
    default value.
    """

    # debugging and deprecation
    FSA_MODE: str = "prod"
    """Execution mode.

    - ``prod``: default terse mode.
    - ``dev``: adds headers with the route, authentication and run time.
    - ``debug1`` to ``debug4``: increasing debug.
    """

    FSA_LOGGING_LEVEL: int = logging.INFO
    """Module internal logging level.

    Upgrade to ``logging.DEBUG`` for maximal verbosity.
    """

    FSA_ALLOW_DEPRECATION: bool = False
    """Whether to allow deprecated features.

    Default is *False*, meaning deprecated features are coldly rejected.
    On *True*, a warning is generated when the feature is encountered.
    This setting may or may not apply to anything depending on the version.
    """

    # general settings
    FSA_SECURE: bool = True
    """Require TLS on non local connexions.

    This should be *True*, unless an external appliance handles TLS decryption.
    """

    FSA_SERVER_ERROR: int = 500
    """Status code on FSA internal server errors.

    This is for debugging help.
    Changing this allows to separate FSA errors from Flask errors or others.
    """

    FSA_NOT_FOUND_ERROR: int = 404
    """Status code on not found errors.

    This is for debugging help.
    Changing this allows to separate FSA generated 404 from others.
    """

    FSA_LOCAL: str = "thread"
    """Isolation requirement for internal per-request objects.

    - ``process``: one process only
    - ``thread``: threaded request handler
    - ``werkzeug``: use werkzeug local
    - ``gevent``: gevent request handler
    - ``eventlet``: eventlet request handler

    Depending on the WSGI server, requests may be managed by process,
    thread, greenlet… this setting must match the WGI context so that FSA
    can isolate requests properly.
    """

    FSA_HANDLE_ALL_ERRORS: bool = True
    """Whether to handle all 4xx and 5xx Flask-generated errors.

    - on *True*: override Flask error processing to use FlaskSimpleAuth
      response generation with FSA internal error handler (FSA_ERROR_RESPONSE).
    - on *False*: some errors may generate their own response in any format
      based on Flask default error response generator.
    """

    FSA_KEEP_USER_ERRORS: bool = False
    """Whether to hide user errors.

    They may occur from any user-provided functions such as various hooks and
    route functions.

    - on *False*: intercept user errors and turned them into 5xx.
    - on *True*: refrain from handling user errors and let them pass to the
      outer WSGI infrastructure instead. User errors are intercepted anyway,
      traced and raised again.
    """

    # register hooks
    FSA_ERROR_RESPONSE: str|Hooks.ErrorResponseFun = "plain"
    """Common hook for generating a response on errors.

    Same as ``error_response`` decorator.

    - ``plain``: generate a simple *text/plain* response.
    - ``json``: generate a simple *application/json* string.
    - ``json:msg``: generate a JSON object with property ``msg``.
    - *callback*: give full control to a callback which is passed
      the message, the status, headers and content type.
    """

    FSA_GET_USER_PASS: Hooks.GetUserPassFun|None = None
    """Password hook for getting a user's salted hashed password.

    Same as ``get_user_pass`` decorator.

    Provide a callback to retrieved the hashed password from the user login.
    Returning *None* will skip internal password checking.
    """

    FSA_AUTHENTICATION: dict[str, Hooks.AuthenticationFun] = {}
    """Authentication hook for adding authentication schemes.

    Same as ``authentication`` decorator.

    For each scheme name, associate a callback which will be given the app and
    request, and should return the authenticated user login (str).
    Returning *None* suggests a 401 for this scheme.
    The implementation may also raise an ``ErrorResponse``.
    """

    FSA_GROUP_CHECK: dict[str, Hooks.GroupCheckFun] = {}
    """Authorization hook for checking whether a user is some groups.

    Same as ``group_check`` decorator.

    For each group name, associate a callback which given a login returns
    whether the user belongs to this group.
    The group name is also registered in passing.
    """

    FSA_USER_IN_GROUP: Hooks.UserInGroupFun|None = None
    """Authorization hook for checking a user group.

    Same as ``user_in_group`` decorator.

    Provide a hook to check whether a user, identified by their login, belogs
    to a group.
    """

    FSA_OBJECT_PERMS: dict[str, Hooks.ObjectPermsFun] = {}
    """Authorization hook for object permissions.

    Same as ``authorization`` decorator.

    For each kind of object (domain), associate a callback which is given
    the object id, the user login and the expected role, and returns whether
    the user has this role for this object id. Return *None* for 404.
    """

    FSA_CAST: dict[Any, Hooks.CastFun] = {}
    """Parameter hook for type conversion.

    Cast function to call on the raw parameter (usually) string value,
    if it does not have the expected type.
    This does not apply to special and pydantic parameters.

    See also ``cast`` function/decorator.
    """

    FSA_SPECIAL_PARAMETER: dict[Any, Hooks.SpecialParameterFun] = {}
    """Parameter hook for special parameters.

    The hook is called with the parameter *name* as an argument.
    It may access ``request`` or whatever to return some value.

    See also ``special_parameter`` function/decorator.
    """

    # FIXME there should be a decorator as well?
    FSA_BEFORE_REQUEST: list[Hooks.BeforeRequestFun] = []
    """Request hook executed before request.

    These hooks are managed internally by FlaskSimpleAuth so that they are
    executed *after* its own (FSA) before request hooks, so as to minimize
    interactions between user hooks registered to Flask directly and its own
    hooks.
    """

    FSA_BEFORE_EXEC: list[Hooks.BeforeExecFun] = []
    """Request hook executed after authentication.

    FlaskSimpleAuth-specific hooks executed after authentication, so that for
    instance the current user is available.

    The hook is executed *after* authentication and *before* the user function.

    It may be used to commit and return a database connection used by the
    authentication phase.

    See also ``before_exec`` function/decorator.
    """

    FSA_AFTER_REQUEST: list[Hooks.AfterRequestFun] = []
    """Request hook executed after request.

    These hooks are managed internally by FlaskSimpleAuth so that they are
    executed *after* its own before request hooks, so as to minimize
    interactions between user hooks registered to Flask directly and its own
    hooks.
    """

    FSA_ADD_HEADERS: dict[str, str|Callable[[], str]] = {}
    """Response hook to add headers.

    Key is the header name, value is the header value or a function generating
    the header value.

    See also ``add_headers`` function.
    """

    # authentication
    FSA_AUTH: str|list[str] = []
    """List of enabled authentication schemes.

    This directive is **mandatory**.

    Note: the result of authentication is the user identification (eg login,
    name or email…) as a string, which is accessible from the application and
    using the ``CurrentUser`` special parameter type in route functions.

    - ``none``: no authentication, implicit if ``FSA_AUTH`` is a scalar, required for OPEN routes.
    - ``httpd``: inherit web-server authentication.
    - ``basic``: HTTP Basic password authentication.
    - ``http-basic``: same with *Flask-HTTPAuth* implementation.
    - ``digest``: HTTP Digest password authentication with *Flask-HTTPAuth*.
    - ``http-digest``: same as previous.
    - ``param``: parameter password authentication.
    - ``password``: try ``basic`` then ``param``.
    - ``fake``: fake authentication using a parameter, for local tests only.
    - ``token``: token authentication (implicit if ``FSA_AUTH`` is a scalar).
    - ``http-token``: same with *Flask-HTTPAuth*.
    - ``oauth``: token authentication variant, where the token holds the list of permissions.
    """

    FSA_AUTH_DEFAULT: str|list[str]|None = None
    """Default authentications to use on a route.

    These authentications **must** be enabled.
    Default is *None*, which means relying on schemes allowed by ``FSA_AUTH``.
    """

    FSA_REALM: str = "<to be set as application name>"
    """Authentication realm, default is application name.

    This realm is used for *basic*, *digest* and *token* authentications.
    """

    FSA_FAKE_LOGIN: str = "LOGIN"
    """Parameter name for fake authentication.

    This parameter string value is taken as the authenticated user name when
    *fake* auth is enabled. Only for local tests, please!
    """

    FSA_PARAM_USER: str = "USER"
    """Parameter name for user for param authentication.

    This parameter string value is the login name for *param* authentication.
    """

    FSA_PARAM_PASS: str = "PASS"
    """Parameter name for password for param authentication.

    This parameter string value is the password for *param* authentication.
    """

    FSA_TOKEN_TYPE: str|None = "fsa"
    """Type of authentication token.

    - ``fsa``: simple custom token
    - ``jwt``: JSON web token standard
    - *None*: disable token authentication
    """

    FSA_TOKEN_ALGO: str = "blake2s"
    """Token signature algorithm.

    Default depends on token type.

    - ``blake2s``: for *fsa* tokens. Other values can be taken from ``hashlib``,
      see ``hashlib.algorithms_available``.
    - ``HS256``: for *jwt* tokens. Other values defined in the JWT standard.
    """

    # default algorithms depending on token type
    _FSA_TOKEN_FSA_ALGO = "blake2s"
    _FSA_TOKEN_JWT_ALGO = "HS256"

    FSA_TOKEN_CARRIER: str = "bearer"
    """Token carrier, i.e. where to find the token.

    - ``bearer``: in the ``Authorization`` header (default)
    - ``cookie``: in a request cookie
    - ``header``: in a custom header
    - ``param``: in a request parameter

    The ``FSA_TOKEN_NAME`` directives provides the additional name.
    """

    FSA_TOKEN_NAME: str = "Bearer"
    """Token carrier name.

    Authentication scheme, or cookie/header/parameter name.
    See defaults in full documentation.
    """

    FSA_TOKEN_DELAY: float = 60.0
    """Token validity delay in minutes."""

    FSA_TOKEN_GRACE: float = 0.0
    """Token grace time after expiration, in minutes."""

    FSA_TOKEN_LENGTH: int = 16
    """FSA token signature length.

    Number of hash characters kept for signing an *fsa* token.
    Default is *16*, meaning a 64-bit signature.
    """

    FSA_TOKEN_SECRET: str = "<to be overriden>"
    """Token verification secret.

    Default is a randomly generated 256-bits string which only works for one
    process.
    """

    FSA_TOKEN_SIGN: str|None = None
    """Token signature secret.

    Only for public-key JWT schemes.
    Default is ``FSA_TOKEN_SECRET``.
    """
    FSA_TOKEN_RENEWAL: float = 0.0
    """Token cookie automatic renewal as a fraction of remaining life time."""

    FSA_TOKEN_ISSUER: str|None = None
    """Token issuer."""

    FSA_PASSWORD_SCHEME: str|list[str]|None = "bcrypt"
    """
    Password hash provider and algorithm name, or list of passlib schemes,
    or password disactivation.

    If the provider is not set, uses ``fsa`` for *bcrypt*, *argon2*, *scrypt*,
    *plaintext*, *a85* and *b64*, otherwise ``passlib``.
    """

    FSA_PASSWORD_OPTS: dict[str, Any]|None = None
    """Password hash algorithm options.

    *None* triggers the defaults, which depend on the provider and scheme:

    - for ``fsa:bcrypt``: ``{"rounds": 4, "prefix"=b"2b"}``
    - for ``fsa:argon2``: ``{"memory_cost": 1000, "time_cost": 1, "parallelism": 1}``
    - for ``fsa:scrypt``: ``{"saltlength": 16, "maxtime": 0.05}``
    - for ``fsa:*``: ``{}``
    - for ``passlib:bcrypt``: ``{"bcrypt__default_rounds": 4, "bcrypt__default_ident": "2y"}``

    With passlib, default for *bcrypt* is ident *2y* (132-bit salt) with *4*
    rounds (2⁴ hash iterations). It is compatible with Apache.
    All _2*_ variants are really equivalent.

    The recommend password rounds is _12_, which results in _x00 ms_ server cpu time.
    This is okay only if you do **not** use password authentication on many routes,
    but only to retrieve some token which would be much easier to check.
    """

    FSA_PASSWORD_LENGTH: int = 0
    """Password quality minimal length.

    Default is *0*, meaning no minimal length is required.
    """

    FSA_PASSWORD_RE: list[str] = []
    """Password quality regular expressions.

    Passwords submitted to ``hash_password`` are checked against this list.
    Default is empty list, meaning no character constraints on passwords.
    """

    FSA_PASSWORD_QUALITY: Hooks.PasswordQualityFun|None = None
    """Password quality hook.

    Arbitrary password quality check.
    Given the password string, returns whether the password is valid.
    """

    FSA_PASSWORD_CHECK: Hooks.PasswordCheckFun|None = None
    """Password check hook.

    Alternate password check function.
    Given the login and clear password, returns whether the authentication is valid.
    This allows to take full control of password checking, possibly as a fallback.

    Consider adding a new authentication scheme, see FSA_AUTHENTICATION.
    """

    FSA_HTTP_AUTH_OPTS: dict[str, Any] = {}
    """Flask-HTTPAuth initialization options."""

    # authorization
    FSA_AUTHZ_GROUPS: list[str] = []
    """Authorized groups declaration.

    Declaring groups allows to detect group name typos at configuration time.
    """

    FSA_AUTHZ_SCOPES: list[str] = []
    """Authorized scopes declaration.

    Declaring scopes allows to detect scope name typos at configuration time.
    """

    FSA_PATH_CHECK: Hooks.PathCheckFun|None = None
    """Check rules on path."""

    # parameter and return handing
    FSA_DEFAULT_CONTENT_TYPE: str|None = None
    """Set default content type for str or bytes responses.

    Default (*None*) is to use Flask's defaults.
    """

    FSA_JSON_STREAMING: bool = True
    """Whether to stream JSON output on generators.

    Default (*True*) is to stream, which may interact badly with driver
    transactions depending on how the WSGI server works.
    Setting this to *False* ensures that JSON is returned as a string by
    FlaskSimpleAuth's ``jsonify``.
    """

    FSA_JSON_CONVERTER: dict[type, Hooks.JSONConversionFun] = {}
    """JSON Converter Mapping.

    Map types to JSON conversion functions.
    """

    FSA_JSON_ALLSTR: bool = False
    """JSON Converter Casting.

    Whether to cast all unexpected types with ``str``.
    """

    FSA_REJECT_UNEXPECTED_PARAM: bool = True
    """Whether to reject unexpected parameters."""

    # internal caching
    FSA_CACHE: str|typing.MutableMapping = "ttl"
    """Cache type.

    - ``none``: disactivate caching
    - ``dict``: simple dictionary
    - ``ttl``, ``lru``, ``tlru``, ``lfu``, …: from *CacheTools*
    - ``memcached`` and ``redis``: external shared caches

    Default is ``ttl``… because it is a good idea.
    """

    FSA_CACHE_SIZE: int = 262144  # a few MB
    """Cache maximum number of entries."""

    _FSA_CACHE_TTL: int = 600  # seconds, 10 mn
    """Cache Time-To-Live in seconds.

    Caching is a performance necessity, but cache management is a pain,
    especially if cache invalidations must be implemented.
    To work around this issue, a simple approach is to rely on automatic
    expiration of cache entries, so that checks are performed from time to time
    and changes take effect after a reasonable delay.
    """

    FSA_CACHE_OPTS: dict[str, Any] = {}
    """Cache initialization options.

    These options as passed when creating the cache instance.
    """

    FSA_CACHE_PREFIX: str|None = None
    """Cache common prefix.

    This prefix is shared by all FSA internal cache entries, so that they may
    not collide with other cache entries when an external cache is shared by
    different part of an application.
    """

    FSA_CACHED_OPTS: dict[str, Any] = {}
    """Options for "cached" decorator."""

    # web-oriented settings
    FSA_401_REDIRECT: str|None = None
    """URL redirection target on 401.

    URL of the web application login page.
    """

    FSA_URL_NAME: str = "URL"
    """URL redirection parameter name.

    The source URL is passed as this parameter to the *401* redirection target
    so that it can be redirected back after authentication.
    """

    FSA_CORS: bool = False
    """Whether to activate Flask-CORS.

    This is needed to work around web browser security checks.
    This implementation is delegated to the Flask-CORS extension.
    """

    FSA_CORS_OPTS: dict[str, Any] = {}
    """Flask-CORS initialization options.

    See `Flask-CORS documentation <https://flask-cors.readthedocs.io/>`_ for details.
    """


class _TokenManager:
    """Internal token management."""

    #
    # TOKEN MANAGEMENT
    #
    # A token can be checked locally with a simple hash, without querying the
    # database and validating a possibly expensive salted password (+400 ms!).
    #
    # FSA_TOKEN_TYPE: 'jwt', 'fsa', or None to disactivate
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

    def __init__(self, fsa):
        assert isinstance(fsa, FlaskSimpleAuth)  # FIXME forward declaration…
        self._fsa = fsa
        # forward some methods
        self._Err = fsa._Err
        self._Bad = fsa._Bad
        # token stuff
        self._token: str|None = Directives.FSA_TOKEN_TYPE
        self._carrier: str = Directives.FSA_TOKEN_CARRIER
        self._name: str = Directives.FSA_TOKEN_NAME
        self._realm: str = fsa._app.name
        self._issuer: str|None = None
        self._delay: float = Directives.FSA_TOKEN_DELAY
        self._grace: float = Directives.FSA_TOKEN_GRACE
        self._renewal: float = Directives.FSA_TOKEN_RENEWAL
        self._secret: str = "to be overriden"
        self._sign: str|None = None
        self._algo: str = Directives.FSA_TOKEN_ALGO
        self._siglen: int = Directives.FSA_TOKEN_LENGTH
        self._token_cache: typing.MutableMapping[str, str]|None = None
        self._initialized = False

    def _initialize(self):
        """After-configuration token manager initialization."""

        if self._initialized:  # pragma: no cover
            log.warning("Token Manager already initialized, skipping…")
            return

        conf = self._fsa._app.config

        # use application configuration to setup tokens
        conf = self._fsa._app.config
        # token type
        self._token = conf.get("FSA_TOKEN_TYPE", "fsa")
        if not self._token:  # pragma: no cover
            return  # desactivated
        if self._token not in ("fsa", "jwt"):
            raise self._Bad(f"unexpected FSA_TOKEN_TYPE: {self._token}")
        # token carrier
        self._carrier = conf.get("FSA_TOKEN_CARRIER", "bearer")
        if self._carrier not in ("bearer", "param", "cookie", "header"):
            raise self._Bad(f"unexpected FSA_TOKEN_CARRIER: {self._carrier}")
        # name of token for cookie or param, Authentication scheme, or other header
        default_name = (
            "AUTH" if self._carrier == "param" else
            "auth" if self._carrier == "cookie" else
            "Bearer" if self._carrier == "bearer" else
            "Auth" if self._carrier == "header" else
            None)
        assert default_name is not None  # mypy…
        self._name = conf.get("FSA_TOKEN_NAME", default_name)
        if not self._name:
            raise self._Bad(f"Token carrier {self._carrier} requires a name")
        if self._carrier == "param":
            assert isinstance(self._name, str)
        # auth and token realm and possible issuer…
        realm: str = conf.get("FSA_REALM", self._fsa._app.name)
        if self._token == "fsa":  # simplify realm for fsa
            keep_char = re.compile(r"[-A-Za-z0-9]").match
            realm = "".join(c if keep_char(c) else "-" for c in realm)
            realm = "-".join(filter(lambda s: s != "", realm.split("-")))
        self._realm = realm
        self._issuer = conf.get("FSA_TOKEN_ISSUER", None)
        # token expiration in minutes
        self._delay = conf.get("FSA_TOKEN_DELAY", Directives.FSA_TOKEN_DELAY)
        self._grace = conf.get("FSA_TOKEN_GRACE", Directives.FSA_TOKEN_GRACE)
        self._renewal = conf.get("FSA_TOKEN_RENEWAL", Directives.FSA_TOKEN_RENEWAL)  # ratio of delay, only for cookies
        # token signature
        if "FSA_TOKEN_SECRET" in conf:
            self._secret = conf["FSA_TOKEN_SECRET"]
            if self._secret and len(self._secret) < 16:
                log.warning("token secret is short")
        else:
            import random
            import string

            log.warning("random token secret, only ok for one process app")
            # list of 94 chars, about 6.5 bits per char, 40 chars => 260 bits
            chars = string.ascii_letters + string.digits + string.punctuation
            self._secret = "".join(random.SystemRandom().choices(chars, k=40))
        if self._token == "fsa":
            self._sign = self._secret
            self._algo = conf.get("FSA_TOKEN_ALGO", Directives._FSA_TOKEN_FSA_ALGO)
            self._siglen = conf.get("FSA_TOKEN_LENGTH", Directives.FSA_TOKEN_LENGTH)
            if "FSA_TOKEN_SIGN" in conf:
                log.warning("ignoring FSA_TOKEN_SIGN directive for fsa tokens")
        elif self._token == "jwt":
            if "FSA_TOKEN_LENGTH" in conf:
                log.warning("ignoring FSA_TOKEN_LENGTH directive for jwt tokens")
            algo = conf.get("FSA_TOKEN_ALGO", Directives._FSA_TOKEN_JWT_ALGO)
            self._algo = algo
            if algo[0] in ("R", "E", "P"):
                self._sign = conf.get("FSA_TOKEN_SIGN", Directives.FSA_TOKEN_SIGN)
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

        # FIXME this check may be too early…
        if "oauth" in self._fsa._local.auth:  # JWT authorizations (RFC 8693)
            if self._token != "jwt":
                raise self._Bad("oauth token authorizations require JWT")
            if not self._issuer:
                raise self._Bad("oauth token authorizations require FSA_TOKEN_ISSUER")

        self._initialized = True

    def _set_auth_cookie(self, res: Response) -> Response:
        """After request hook to set a cookie if needed and none was sent."""
        # NOTE thanks to max_age the client should not send stale cookies
        if self._carrier == "cookie":
            assert self._token and self._name
            local = self._fsa._local
            if local.user and self._can_create_token():
                if self._name in request.cookies and self._renewal:
                    # renew token when closing expiration
                    user, exp, _ = self._get_any_token_auth_exp(request.cookies[self._name], local.token_realm)
                    limit = dt.datetime.now(dt.timezone.utc) + \
                        self._renewal * dt.timedelta(minutes=self._delay)
                    set_cookie = exp < limit
                else:  # no cookie, set it
                    set_cookie = True
                if set_cookie:
                    # path? other parameters?
                    res.set_cookie(self._name, self.create_token(local.user), max_age=int(60 * self._delay))
        return res

    def _cmp_sig(self, data, secret) -> str:
        """Compute signature for data."""
        import hashlib

        h = hashlib.new(self._algo)
        h.update(f"{data}:{secret}".encode())
        return h.digest()[: self._siglen].hex()

    def _to_timestamp(self, ts) -> str:
        """Build a simplistic timestamp string."""
        # this is shorter than an iso format timestamp
        return "%04d%02d%02d%02d%02d%02d" % ts.timetuple()[:6]

    def _from_timestamp(self, ts) -> dt.datetime:
        """Parse a simplistic "YYYYMMDDHHmmSS" timestamp string."""
        p = re.match(r"^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$", ts)
        if not p:
            raise self._Err(f"unexpected timestamp format: {ts}", 400)
        # FIXME mypy strange warning
        # datetime" gets multiple values for keyword argument "tzinfo"  [misc]
        # Argument 1 to "datetime" has incompatible type "*list[int]"; expected "tzinfo|None"  [arg-type]
        return dt.datetime(*[int(p[i]) for i in range(1, 7)], tzinfo=dt.timezone.utc)  # type: ignore

    def _get_fsa_token(self, realm, issuer, user, delay, secret) -> str:
        """Compute a signed token for "user" valid for "delay" minutes."""
        limit = self._to_timestamp(dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=delay))
        data = f"{realm}/{issuer}:{user}:{limit}" if issuer else f"{realm}:{user}:{limit}"
        sig = self._cmp_sig(data, secret)
        return f"{data}:{sig}"

    def _get_jwt_token(self, realm: str, issuer: str|None, user, delay: float,
                       secret, scope: list[str]|None = None) -> str:
        """JSON Web Token (JWT) generation.

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

    def _can_create_token(self) -> bool:
        """Whether it is possible to create a token."""
        return self._token is not None and not (
            self._token == "jwt" and self._algo[0] in ("R", "E", "P") and not self._sign
        )

    def create_token(self, user: str|None = None, realm: str|None = None,
                     issuer: str|None = None, delay: float|None = None,
                     secret: str|None = None, **kwargs) -> str:
        """Create a new token for user depending on the configuration."""
        assert self._token
        user = user or self._fsa.get_user()
        realm = realm or self._fsa._local.token_realm
        issuer = issuer or self._issuer
        delay = delay or self._delay
        secret = secret or (self._secret if self._token == "fsa" else self._sign)
        assert realm is not None  # help type check
        return (
            self._get_fsa_token(realm, issuer, user, delay, secret, **kwargs) if self._token == "fsa" else
            self._get_jwt_token(realm, issuer, user, delay, secret, **kwargs)
        )

    # internal function to check a fsa token
    def _check_fsa_token(self, token: str, realm: str, issuer: str|None, secret: str, grace: float) \
            -> tuple[str, dt.datetime, list[str]|None]:
        """Check FSA token validity against a configuration."""
        # token format: "realm[/issuer]:calvin:20380119031407:<signature>"
        if token.count(":") != 3:
            if self._fsa._mode >= _Mode.DEBUG:
                log.debug(f"AUTH (fsa token): unexpected token ({token})")
            raise self._Err(f"invalid fsa token: {token}", 401)
        trealm, user, slimit, sig = token.split(":", 3)
        try:
            limit = self._from_timestamp(slimit)
        except Exception as e:
            if self._fsa._mode >= _Mode.DEBUG:
                log.debug(f"AUTH (fsa token): malformed timestamp {slimit} ({token}): {e}")
            raise self._Err(f"unexpected fsa token limit: {slimit} ({token})", 401, e)
        # check realm
        if issuer and trealm != f"{realm}/{issuer}" or \
           not issuer and trealm != realm:
            if self._fsa._mode >= _Mode.DEBUG:
                log.debug(f"AUTH (fsa token): unexpected realm {trealm} ({token})")
            raise self._Err(f"unexpected fsa token realm: {trealm} ({token})", 401)
        # check signature
        ref = self._cmp_sig(f"{trealm}:{user}:{slimit}", secret)
        if ref != sig:
            if self._fsa._mode >= _Mode.DEBUG:
                log.debug(f"AUTH (fsa token): invalid signature ({token})")
            raise self._Err(f"invalid fsa auth token signature ({token})", 401)
        # check limit with a grace time
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=self._grace)
        if now > limit:
            if self._fsa._mode >= _Mode.DEBUG:
                log.debug(f"AUTH (fsa token): token {token} has expired ({token})")
            raise self._Err(f"expired fsa auth token ({token})", 401)
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
            if self._fsa._mode >= _Mode.DEBUG:
                log.debug(f"AUTH (jwt token): token has expired ({token})")
            raise self._Err(f"expired jwt auth token: {token}", 401)
        except Exception as e:
            if self._fsa._mode >= _Mode.DEBUG:
                log.debug(f"AUTH (jwt token): invalid token {token}: {e}")
            raise self._Err(f"invalid jwt token: {token}", 401, e)

    # NOTE as the realm can be route-dependent, cached validations include the realm.
    def _get_any_token_auth_exp(self, token: str, realm: str):
        """Return validated user and expiration, cached."""
        return (self._get_fsa_token_auth(token, realm) if self._token == "fsa" else
                self._get_jwt_token_auth(token, realm))

    def token_uncache(self, token: str, realm: str) -> bool:
        """Remove token entry from cache, if token is known."""
        if not self._fsa._cm._cache_gen:  # pragma: no cover
            log.debug("cache is not activated, cannot uncache token, skipping…")
            return False
        return self._get_any_token_auth_exp.cache_del(token, realm)  # type: ignore

    # Hmmm… keep track of last seen token to help cache invalidation?
    def _user_token_cache(self, user: str, realm: str, token: str):
        """Manually memoize a token associated to a user/realm."""
        if self._token_cache:
            self._token_cache[f"{user}/{realm}"] = token

    def user_token_uncache(self, user: str, realm: str) -> bool:
        """Remove cached token associated to a user/realm."""
        if self._token_cache:
            user_realm = f"{user}/{realm}"
            try:
                token = self._token_cache[user_realm]
                if token:
                    del self._token_cache[user_realm]
                    return self.token_uncache(token, realm)
            except KeyError:
                pass
        return False

    # NOTE the realm parameter is really only for testing purposes
    def _get_any_token_auth(self, token: str|None, realm: str|None = None) -> str|None:
        """Tell whether token is ok: return validated user or None, may raise 401."""
        if not token:
            raise self._Err("missing token", 401)
        realm = realm or self._fsa._local.token_realm
        assert realm is not None  # help type check
        user, exp, scopes = self._get_any_token_auth_exp(token, realm)
        # log.debug(f"token: u={user} exp={exp} scopes={scopes}")
        # must recheck token expiration
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=self._grace)
        if now > exp:
            if self._fsa._mode >= _Mode.DEBUG:
                log.debug(f"AUTH (token): token has expired ({token})")
            raise self._Err(f"expired auth token: {token}", 401)
        # store current available scopes for oauth
        self._fsa._local.scopes = scopes
        # memoize?
        if user and realm and token:
            self._user_token_cache(user, realm, token)
        return user

    def _get_token(self) -> str|None:
        """Get authentication token from whereever."""
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
            token = self._fsa._pm._params().get(self._name, None)
        else:
            assert self._carrier == "header" and self._name
            token = request.headers.get(self._name, None)
        return token


class _LDAPAuthBase:
    """Base class for LDAP Authentication.

    :param url: full/partial LDAP URL (``scheme://dn:pw@host:port/base?attr?scope?filter``).
    :param scheme: "ldap" or "ldaps".
    :param host: ldap server hostname.
    :param port: ldap server port number.
    :param base: directory branch for search, defaults to *None* (no search).
    :param dn: distinguished name for binding while searching.
    :param pw: password for binding while searching.
    :param use_tls: use TLS, default is *True*.
    :param attr: attribute name for searching.
    :param scope: scope of search ("sub" or "one" or "base"), defaults to "sub".
    :param filter: extra search filter, defaults to "(objectClass=*)".

    Parameter ``url`` can contain all other parameters at once, but may be
    quite long and hard to read. Other parameters override these settings.
    """

    def __init__(self, url: str|None = None,
                 scheme: str = "", host: str = "", port: int = 0,
                 use_tls: bool = True, base: str|None = None, dn: str|None = None, pw: str|None = None,
                 attr: str = "", scope: str = "", filter: str = ""):
        # clean slate
        self._scheme, self._host, self._port = "", "", 0
        self._base, self._dn, self._pw = None, None, None
        self._attr, self._scope, self._filter = "", "", ""
        # decompose url if provided
        if url:
            from urllib.parse import urlparse
            u = urlparse(url)
            self._scheme = u.scheme
            self._host = u.hostname or ""
            self._port = u.port or 0
            self._base = u.path[1:] if u.path and len(u.path) > 1 else None
            self._dn, self._pw = u.username, u.password
            if u.query:
                self._attr, self._scope, self._filter = u.query.split("?", 2)
        # overrides and defaults
        self._scheme = scheme or self._scheme or "ldap"
        assert self._scheme in ("ldap", "ldaps"), "expecting ldap scheme"
        self._host = host or self._host or "localhost"
        self._port = port or self._port or (389 if self._scheme == "ldap" else 686)
        self._base = base or self._base
        self._dn = dn or self._dn
        self._pw = pw or self._pw
        self._use_tls = use_tls
        self._attr = attr or self._attr or "uid"
        self._scope = scope or self._scope or "sub"
        assert self._scope in ("one", "sub", "base")
        self._filter = filter or self._filter or "(objectClass=*)"

    def url(self):
        """Show LDAP full URL."""
        # pyright helper:
        from urllib.parse import quote as q
        url = self._scheme + "://"
        if self._dn:
            url += q(self._dn)
            if self._pw:
                url += ":" + q(self._pw)
            url += "@"
        url += self._host
        if self._port:
            url += ":" + str(self._port)
        if self._base:
            url += "/" + self._base
        url += "?" + self._attr + "?" + self._scope + "?" + self._filter
        return url

    def check(self, username: str, password: str) -> bool:  # pragma: no cover
        raise Exception("not implemented yet")


class _LDAPAuth(_LDAPAuthBase):
    """LDAP Authentication with ``ldap``."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # python-ldap specific initializations
        import ldap
        self._ldap = ldap
        from ldap.filter import escape_filter_chars
        self._escape = escape_filter_chars
        self._scope_val = (
            ldap.SCOPE_SUBTREE if self._scope == "sub" else  # type: ignore
            ldap.SCOPE_ONELEVEL if self._scope == "one" else  # type: ignore
            ldap.SCOPE_BASE  # type: ignore
        )
        # FIXME the ldap connection is persistent? pooling? thread safety?
        self._conn = None

    def check(self, username: str, password: str):  # pragma: no cover
        """Check username password by binding to LDAP."""
        try:
            if not self._conn:
                uri = self._scheme + "://" + self._host + ":" + str(self._port)
                self._conn = self._ldap.initialize(uri)
            if self._use_tls:  # FIXME is once enough?
                self._conn.start_tls_s()
            if self._base:  # initial search
                if self._dn:  # initial bind
                    self._conn.simple_bind_s(self._dn, self._pw)
                search = f"({self._attr}={self._escape(username)})"
                if self._filter:
                    search = f"(&{self._filter}{search})"
                # log.debug(f"ldap search = {search}")
                result = self._conn.search_s(self._base, self._scope_val, search)
                if not result or len(result) != 1:
                    return False
                user_dn = result[0][0]  # FIXME parametric?
            else:  # maybe the user did really use a DN as a login…
                user_dn = username
            try:
                self._conn.simple_bind_s(user_dn, password)
                return True
            except self._ldap.LDAPError as e:  # type: ignore
                log.info(f"ldap error: {e}")
                return False
            finally:
                self._conn.unbind_s()
        except Exception as e:
            log.error(f"ldap internal error: {e}")
            self._conn = None
            raise
        return False


# TODO server pool…
class _LDAP3Auth(_LDAPAuthBase):
    """LDAP Authentication with ``ldap3``.

    Specific constructor parameters:

    :param server_opts: dictionary of parameters for ldap3 Server constructor.
    :param conn_opts: dictionary of parameters for ldap3 Connection constructor.
    :param search_opts: dictionary of parameters for ldap3 search operation.

    All other parameters are forwarded to LDAPAuthBase.
    """
    def __init__(self,
                 server_opts: dict[str, Any] = {},
                 conn_opts: dict[str, Any] = {},
                 search_opts: dict[str, Any] = {},
                 **kwargs):
        super().__init__(**kwargs)
        # ldap3 specific initializations
        self._server_opts = server_opts
        self._conn_opts = conn_opts
        self._search_opts = search_opts
        import ldap3
        self._ldap3 = ldap3
        from ldap3.utils.conv import escape_filter_chars
        self._escape = escape_filter_chars
        self._scope_val = (
            ldap3.SUBTREE if self._scope == "sub" else
            ldap3.LEVEL if self._scope == "one" else
            ldap3.BASE
        )
        # FIXME the ldap connection is persistent? pooling? thread safety?
        self._server, self._conn = None, None

    def check(self, username: str, password: str):  # pragma: no cover
        try:
            if not self._server:
                self._server = self._ldap3.Server(host=self._host, port=self._port, **self._server_opts)
            if not self._conn:
                if self._dn:
                    self._conn = self._ldap3.Connection(self._server, user=self._dn, password=self._pw, **self._conn_opts)
                else:  # Anonymous…
                    self._conn = self._ldap3.Connection(self._server, **self._conn_opts)
                if self._use_tls:
                    if not self._conn.start_tls():
                        raise Exception(f"cannot start tls: {self._conn.result['message']}")
                else:
                    if not self._conn.open():
                        raise Exception(f"cannot open: {self._conn.result['message']}")
                if not self._conn.bind():
                    raise Exception(f"cannot bind: {self._conn.result['message']}")
            if self._base:
                if not self._conn.bind():
                    log.error(f"cannot bind: {self._conn.result['message']}")
                search = f"({self._attr}={self._escape(username)})"
                if self._filter:
                    search = f"(&{self._filter}{search})"
                if not self._conn.search(self._base, search, self._scope_val, **self._search_opts):  # type: ignore
                    raise Exception(f"cannot search: {self._conn.result['message']}")
                if not self._conn.response or len(self._conn.response) != 1:
                    log.debug(f"ldap search: {self._conn.result}")
                    return False
                user_dn = self._conn.response[0]["dn"]
            else:  # the user is expected to type a full DN…
                user_dn = username
            conn = None
            try:
                # FIXME why do I need a new connection?
                conn = self._ldap3.Connection(self._server, user=user_dn, password=password, **self._conn_opts)
                if self._use_tls:
                    conn.start_tls()
                return conn.bind()
            finally:
                _ = conn and conn.unbind()
        except Exception as e:  # on any error, will start over
            log.error(f"ldap3 internal error: {e}")
            self._server, self._conn = None, None
        return False


class _PasswordManager:
    """Internal password management."""

    #
    # PASSWORD MANAGEMENT
    #
    # FSA_PASSWORD_SCHEME: names of password provider and scheme
    # FSA_PASSWORD_OPTS: further options for passlib/… context
    # FSA_PASSWORD_LENGTH: minimal length of provided passwords
    # FSA_PASSWORD_RE: list of re a password must match
    # FSA_PASSWORD_QUALITY: hook for password strength check
    # FSA_PASSWORD_CHECK: hook for alternate password check
    #
    # NOTE bcrypt is Apache compatible
    # NOTE about caching: if password checks are cached, this could
    #      mean that the clear text password is stored in cache, which
    #      is a VERY BAD IDEA because consulting the cache would give
    #      access to said passwords.
    #      Thus `check_password`, `hash_password`, `_check_password`,
    #      `_password_check` and `_check_with_password_hook` should not be
    #      cached directly, ever, even if expensive.
    #      Make good use of tokens to reduce password check costs.

    def __init__(self, fsa):
        assert isinstance(fsa, FlaskSimpleAuth)  # FIXME forward declaration…
        self._fsa = fsa
        # forward
        self._Exc = fsa._Exc
        self._Bad = fsa._Bad
        self._Err = fsa._Err
        # password stuff
        self._pass_provider_name: str = "fsa"
        self._pass_scheme: str = "bcrypt"
        self._pass_provider = None
        self._pass_check: Hooks.PasswordCheckFun|None = None
        self._pass_quality: Hooks.PasswordQualityFun|None = None
        self._pass_len: int = 0
        self._pass_re: list[Hooks.PasswordQualityFun] = []
        self._get_user_pass: Hooks.GetUserPassFun|None = None
        self._initialized = False

    # only actually initialize with passlib if needed
    # passlib context is a pain, you have to know the scheme name to set its
    # round. Ident "2y" is same as "2b" but apache compatible.
    def __passlib_init(self, schemes: list[str], options: dict[str, Any]|None):
        """Initialization for passlib password management."""

        if options is None:  # bcrypt defaults
            options = {"bcrypt__default_rounds": 4, "bcrypt__default_ident": "2y"}

        try:
            from passlib.context import CryptContext  # type: ignore
        except ModuleNotFoundError:  # pragma: no cover
            log.error("missing module passlib")
            raise

        # this raises errors if dependencies are missing
        try:
            self._pass_provider = CryptContext(schemes=schemes, **options)
        except Exception as e:
            log.error(f"error while initializing passlib {schemes}: {str(e)}")
            raise self._Bad(f"unsupported passlib scheme: {schemes}", str(e))

    def __fsa_init(self, scheme: str, options: dict[str, Any]|None):
        """Initialization for internal password management."""

        class PlainTextPassProvider:
            """Helper class for plaintext password."""

            def hash(self, password: str) -> str:
                return password

            def verify(self, password: str, ref: str) -> bool:
                return password == ref

        class B64PassProvider:
            """Helper class for b64 obfuscated password."""

            def hash(self, password: str) -> str:
                return base64.b64encode(password.encode("UTF8")).decode("ascii")

            def verify(self, password: str, ref: str) -> bool:
                return password == base64.b64decode(ref).decode("UTF8")

        class A85PassProvider:
            """Helper class for a85 obfuscated password."""

            def hash(self, password: str) -> str:
                return base64.a85encode(password.encode("UTF8")).decode("ascii")

            def verify(self, password: str, ref: str) -> bool:
                return password == base64.a85decode(ref).decode("UTF8")

        # simple schemes do not require an external package
        _FSA_PASS_SIMPLE_SCHEMES = {
            "plaintext": PlainTextPassProvider,
            "b64": B64PassProvider,
            "a85": A85PassProvider,
        }

        if scheme in _FSA_PASS_SIMPLE_SCHEMES:

            self._pass_provider = _FSA_PASS_SIMPLE_SCHEMES[scheme]()

        elif scheme == "bcrypt":

            if options is None:
                # NOTE 2y is not supported…
                options = {"rounds": 4, "prefix": b"2b"}

            try:
                import bcrypt
            except ModuleNotFoundError:  # pragma: no cover
                log.error("missing module bcrypt")
                raise

            class BCryptPassProvider:
                """Helper class for bcrypt password."""

                def hash(self, password: str) -> str:
                    return bcrypt.hashpw(password.encode("UTF8"), bcrypt.gensalt(**options)).decode("ascii")

                def verify(self, password: str, ref: str) -> bool:
                    return bcrypt.checkpw(password.encode("UTF8"), ref.encode("ascii"))

            self._pass_provider = BCryptPassProvider()

        elif scheme == "argon2":

            # TODO what about the check_needs_rehash feature?

            if options is None:
                options = {"memory_cost": 1000, "time_cost": 1, "parallelism": 1}

            try:
                import argon2
            except ModuleNotFoundError:  # pragma: no cover
                log.error("missing module argon2")
                raise

            class Argon2PassProvider:
                """Helper class for argon2 password."""

                def __init__(self):
                    self._hasher = argon2.PasswordHasher(**options)  # type: ignore

                def hash(self, password: str) -> str:
                    return self._hasher.hash(password)

                def verify(self, password: str, ref: str) -> bool:
                    try:
                        return self._hasher.verify(ref, password)
                    except argon2.VerificationError:  # type: ignore ; # pragma: no cover
                        return False

            self._pass_provider = Argon2PassProvider()

        elif scheme == "scrypt":

            if options is None:
                options = {"saltlength": 16, "maxtime": 0.05}

            try:
                import scrypt
            except ModuleNotFoundError:  # pragma: no cover
                log.error("missing module scrypt")
                raise

            CLEAR = "FlaskSimpleAuth!"

            class ScryptPassProvider:
                """Helper class for scrypt password."""

                def __init__(self, saltlength: int, maxtime: float = 0.05, **options):
                    self._saltlength = saltlength
                    self._enc_options = dict(options)
                    self._enc_options.update(maxtime=maxtime)
                    self._dec_options = dict(options)
                    # NOTE decrypt can fail when used with the encoding maxtime
                    # FIXME this create a CI hazard…
                    self._dec_options.update(maxtime=1.5 * maxtime)

                def hash(self, password: str) -> str:
                    salt = os.urandom(self._saltlength)
                    clear = base64.a85encode(salt).decode("ascii") + CLEAR
                    encrypted = scrypt.encrypt(clear, password, **self._enc_options)
                    return base64.a85encode(encrypted).decode("ascii")

                def verify(self, password: str, ref: str) -> bool:
                    encrypted = base64.a85decode(ref)
                    try:
                        clear = scrypt.decrypt(encrypted, password, **self._dec_options)
                        return clear.endswith(CLEAR)  # type: ignore
                    except scrypt.error:
                        return False

            self._pass_provider = ScryptPassProvider(**options)

        elif scheme == "otp":

            if options is None:
                options = {}

            import pyotp  # type: ignore

            class PyOTPProvider:

                def __init__(self, **options):
                    self._options = options

                def hash(self, password: str) -> str:
                    return password

                def verify(self, password: str, ref: str) -> bool:
                    totp = pyotp.TOTP(ref, **self._options)
                    return totp.verify(password, valid_window=1)

            self._pass_provider = PyOTPProvider(**options)

        else:

            raise self._Bad(f"unexpected fsa password scheme: {scheme}")

    def __ldap_init(self, provider: str, scheme: str, options: dict[str, Any]):
        """Initialization for LDAP authentication."""

        assert provider in ("ldap", "ldap3")
        # FIXME there are plenty SASL sub schemes. "anonymous" entails two level bindings?.
        assert scheme in ("anonymous", "simple", "sasl"), f"unexpected LDAP authentication scheme: {scheme}"
        assert scheme == "simple"  # for now

        self._ldap_auth = _LDAPAuth(**options) if provider == "ldap" else _LDAP3Auth(**options)
        self._pass_check = self._ldap_auth.check

    def _initialize(self):
        """After-configuration password manager initialization."""

        if self._initialized:  # pragma: no cover
            log.warning("Password Manager already initialized, skipping…")
            return

        conf = self._fsa._app.config

        # configure password management
        scheme = conf.get("FSA_PASSWORD_SCHEME", Directives.FSA_PASSWORD_SCHEME)
        options = conf.get("FSA_PASSWORD_OPTS", Directives.FSA_PASSWORD_OPTS)

        # internally supported schemes
        _FSA_PASSWORD_SCHEMES = {"bcrypt", "argon2", "scrypt", "plaintext", "a85", "b64"}

        # no password manager
        if scheme is None:
            return

        # shortcut for passlib list of schemes
        if isinstance(scheme, list):
            self.__passlib_init(scheme, options)
            return

        # single scheme
        if ":" in scheme:
            provider, scheme = scheme.split(":", 1)
        elif scheme in ("ldap", "ldap3"):
            provider, scheme = scheme, "simple"
        else:  # default depends on scheme
            provider = "fsa" if scheme in _FSA_PASSWORD_SCHEMES else "passlib"

        log.info(f"initializing password manager with {provider}:{scheme}")

        if scheme == "plaintext":
            log.warning("plaintext password manager is a bad idea")

        if provider == "fsa":
            self.__fsa_init(scheme, options)
        elif provider == "passlib":
            self.__passlib_init([scheme], options)
        elif provider in ("ldap", "ldap3"):
            self.__ldap_init(provider, scheme, options)
        else:
            raise self._Bad(f"unexpected password provider: {provider}")

        # TODO warn if redefined or ignored?

        # custom password checking function
        self._pass_check = conf.get("FSA_PASSWORD_CHECK", Directives.FSA_PASSWORD_CHECK)

        # password quality checks
        self._pass_quality = conf.get("FSA_PASSWORD_QUALITY", Directives.FSA_PASSWORD_QUALITY)
        self._pass_len = conf.get("FSA_PASSWORD_LENGTH", Directives.FSA_PASSWORD_LENGTH)
        self._pass_re += [
            re.compile(r).search for r in conf.get("FSA_PASSWORD_RE", Directives.FSA_PASSWORD_RE)
        ]  # type: ignore

        # getting user password if appropriate
        if "FSA_GET_USER_PASS" in conf:
            self.get_user_pass(conf["FSA_GET_USER_PASS"])

        # done
        self._initialized = True

    def get_user_pass(self, gup: Hooks.GetUserPassFun):
        """Set `get_user_pass` helper, can be used as a decorator."""
        if self._get_user_pass:
            log.warning("overriding already defined get_user_pass hook")
        self._get_user_pass = gup
        return gup

    def _check_quality(self, pwd: str) -> None:
        """Check password quality, raising issues or proceeding."""
        if len(pwd) < self._pass_len:
            raise self._Err(f"password is too short, must be at least {self._pass_len}", 400)
        for search in self._pass_re:
            if not search(pwd):
                raise self._Err(f"password must match {search.__self__.pattern}", 400)  # type: ignore
        if self._pass_quality:
            try:
                if not self._pass_quality(pwd):
                    raise self._Err("password quality too low", 400)
            except Exception as e:
                raise self._Err(f"password quality too low: {e}", 400, e)
        # done, quality is okay

    def _check_with_hook(self, user: str, pwd: str):
        """Check user/password with external hook."""
        if self._pass_check:
            try:
                return self._pass_check(user, pwd)
            except ErrorResponse as e:
                raise e
            except Exception as e:
                log.info(f"AUTH (hook) failed: {e}")
                if self._Exc(e):  # pragma: no cover
                    raise
                return False
        return False

    def check_password(self, pwd: str, ref: str) -> bool:
        """Check whether password is ok wrt to reference."""
        if not self._pass_provider:  # pragma: no cover
            raise self._Err("password manager is disabled", self._fsa._server_error)
        try:
            return self._pass_provider.verify(pwd, ref)
        except Exception as e:  # ignore passlib issues
            log.error(f"verify error: {e}")
            return False

    def hash_password(self, pwd: str, check=True) -> str:
        """Hash password according to the current password scheme."""
        if not self._pass_provider:  # pragma: no cover
            raise self._Err("password manager is disabled", self._fsa._server_error)
        if check:
            self._check_quality(pwd)
        return self._pass_provider.hash(pwd)

    def check_user_password(self, user: str, pwd: str) -> str:
        """Check user/password against internal or external credentials.

        Raise an exception if not ok, otherwise simply return the user.
        """
        # first, get user password hash if available
        if self._get_user_pass:
            try:
                ref = self._get_user_pass(user)
            except ErrorResponse as e:
                raise e
            except Exception as e:
                log.error(f"get_user_pass failed: {e}")
                raise self._Err("internal error in get_user_pass", self._fsa._server_error, e)
        else:
            ref = None
        if not ref:  # not available, try alternate check
            if self._check_with_hook(user, pwd):
                return user
            else:  # not ok with hook, generate appropriate error
                if self._get_user_pass:
                    log.debug(f"AUTH (password): no such user ({user})")
                    raise self._Err(f"no such user: {user}", 401)
                else:
                    log.debug(f"AUTH (password): invalid user/password ({user})")
                    raise self._Err(f"invalid user/password for {user}", 401)
        elif not isinstance(ref, (str, bytes)):  # do a type check in passing
            log.error(f"type error in get_user_pass: {_type(ref)} on {user}, expecting None, str or bytes")
            raise self._Err("internal error with get_user_pass", self._fsa._server_error)
        elif self.check_password(pwd, ref):  # does not match, try alternate check
            return user
        else:
            # there is a reference which did not work, try with hook
            if self._check_with_hook(user, pwd):  # pragma: no cover
                return user
            else:
                log.debug(f"AUTH (password): invalid password ({user})")
                raise self._Err(f"invalid password for {user}", 401)

    def password_uncache(self, user: str) -> bool:
        """Remove user password entry from cache."""
        if not self._fsa._cm._cache_gen:  # pragma: no cover
            log.debug("cache is not activated, cannot uncache password, skipping…")
            return False
        elif self._get_user_pass and hasattr(self._get_user_pass, "cache_del"):
            return self._get_user_pass.cache_del(user)  # type: ignore
        else:  # pragma: no cover
            return False


class _AuthenticationManager:
    """Internal authentication management.

    This class holds all authentication methods and related decorator.
    """

    def __init__(self, fsa):
        assert isinstance(fsa, FlaskSimpleAuth)  # FIXME forward declaration…
        self._fsa = fsa
        # forward
        self._Bad = fsa._Bad
        self._Err = fsa._Err
        self._Res = fsa._Res
        self._Exc = fsa._Exc
        self._store = fsa._store
        # initialize all authentication stuff
        self._auth: list[str] = []                     # ordered enabled authentications
        self._default_auth: list[str]|str|None = None  # default route authentication
        # map auth to their hooks
        self._authentication: dict[str, Hooks.AuthenticationFun] = {
            "none": lambda _a, _r: None,
            # internal authentication
            "httpd": self._get_httpd_auth,
            "token": self._get_token_auth,
            "oauth": self._get_token_auth,
            "fake": self._get_fake_auth,
            "basic": self._get_basic_auth,
            "param": self._get_param_auth,
            # HTTPAuth-dependent authentication
            "digest": self._get_httpauth,
            "http-basic": self._get_httpauth,
            "http-digest": self._get_httpauth,
            "http-token": self._get_httpauth,
            # new authentications can be registered
        }
        self._auth_params: set[str] = set()  # authentication parameters to ignore
        self._realm: str = fsa._app.name
        self._login: str = Directives.FSA_FAKE_LOGIN
        self._userp: str = Directives.FSA_PARAM_USER
        self._passp: str = Directives.FSA_PARAM_PASS
        # managers are created even if disactivated
        self._pm: _PasswordManager = _PasswordManager(fsa)
        self._tm: _TokenManager = _TokenManager(fsa)
        self._httpauth: Any|None = None
        self._initialized = False

    def _initialize(self):
        """After-configuration authentication manager initialization."""

        if self._initialized:  # pragma: no cover
            log.warning("Authentication Manager already initialized, skipping…")
            return

        fsa, conf = self._fsa, self._fsa._app.config

        # list of allowed authentication schemes
        auth = conf.get("FSA_AUTH", Directives.FSA_AUTH)
        if isinstance(auth, str):
            # nearly always add "token"
            if auth not in ("oauth", "token", "http-token", "none"):
                auth = ["token", auth, "none"]
            else:
                auth = [auth]
        if not isinstance(auth, list):
            raise self._Bad(f"unexpected FSA_AUTH type: {_type(auth)}")
        # auth list cannot be empty
        if auth is None or auth == []:
            raise self._Bad("empty authentication configuration, please provide FSA_AUTH!")
        # keep the provided list, whatever
        self._auth = self._password_auth(auth)

        # default authentication on a route, unless explicitely stated
        default_auth = conf.get("FSA_AUTH_DEFAULT", Directives.FSA_AUTH_DEFAULT)
        if isinstance(default_auth, str):
            default_auth = [default_auth]
        if default_auth is None:
            self._default_auth = None  # will rely on self._auth
        elif isinstance(default_auth, list):
            default_auth = self._password_auth(default_auth)
            self._default_auth = default_auth
        else:
            raise self._Bad(f"unexpected FSA_AUTH_DEFAULT type: {_type(default_auth)}")

        # FIXME needed for some tm checks
        self._fsa._local.auth = self._auth
        # FIXME there is a token realm, is this consistent?
        self._realm = conf.get("FSA_REALM", self._fsa._app.name)
        #
        # password and token managers setup
        #
        self._pm._initialize()
        self._tm._initialize()
        #
        # HTTP auth parameter names
        #
        if "fake" not in self._auth and "FSA_FAKE_LOGIN" in conf:
            log.warning("ignoring directive FSA_FAKE_LOGIN")
        if "param" not in self._auth:
            if "FSA_PARAM_USER" in conf:
                log.warning("ignoring directive FSA_PARAM_USER")
            if "FSA_PARAM_PASS" in conf:
                log.warning("ignoring directive FSA_PARAM_PASS")
        self._login = conf.get("FSA_FAKE_LOGIN", Directives.FSA_FAKE_LOGIN)
        self._userp = conf.get("FSA_PARAM_USER", Directives.FSA_PARAM_USER)
        self._passp = conf.get("FSA_PARAM_PASS", Directives.FSA_PARAM_PASS)
        #
        # registrations
        #
        # see also authentication decorator
        fsa._set_hooks("FSA_AUTHENTICATION", self.authentication)
        # check existence and possibly trigger auth-related stuff
        for a in self._auth:
            self._add_auth(a)
        # check consistency with enabled authentication schemes
        if default_auth:
            for a in default_auth:
                if a not in self._auth:
                    raise self._Bad(f"default auth is not enabled: {a} / {self._auth}")
        # TODO consistency checks about authentications?
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
                assert self._http_auth  # mypy…
                self._http_auth.verify_password(self._pm.check_user_password)
            elif self._auth_has("http-digest", "digest"):
                self._http_auth = fha.HTTPDigestAuth(realm=self._realm, **opts)
                assert self._http_auth  # mypy…
                # FIXME? nonce & opaque callbacks? session??
            elif "http-token" in self._auth:
                if not self._tm:  # pragma: no cover
                    raise self._Bad("cannot use http-token auth if token is disabled")
                # NOTE incompatible with local realm
                if self._tm._carrier == "header" and "header" not in opts and self._tm._name:
                    opts["header"] = self._tm._name
                self._http_auth = fha.HTTPTokenAuth(scheme=self._tm._name, realm=self._tm._realm, **opts)
                assert self._http_auth  # mypy…
                self._http_auth.verify_token(lambda t: self._tm._get_any_token_auth(t, self._tm._realm))
            assert self._http_auth  # mypy…
            self._http_auth.get_password(self._pm._get_user_pass)
            # FIXME? error_handler?
        # done!
        self._initialized = True

    def _password_auth(self, la: list[str]):
        """password is replaced by basic and param."""
        if "password" in la:
            la.remove("password")
            la.append("basic")
            la.append("param")
        return la

    def _add_auth(self, auth: str):
        """Register that an authentication method is used."""
        if not isinstance(auth, str):  # pragma: no cover
            raise self._Bad(f"unexpected authentication identifier type: {_type(auth)}")
        if auth not in self._authentication:
            raise self._Bad(f"unexpected authentication scheme: {auth}")
        # possibly add parameters to ignore silently
        if auth == "param":
            self._auth_params.add(self._userp)
            self._auth_params.add(self._passp)
        if auth == "fake":
            self._auth_params.add(self._login)
        if auth in ("token", "oauth"):
            if not self._tm:  # pragma: no cover
                raise self._Bad("cannot use token auth if token is disabled")
            if self._tm._carrier == "param":
                assert isinstance(self._tm._name, str)
                self._auth_params.add(self._tm._name)

    def authentication(self, auth: str, hook: Hooks.AuthenticationFun|None = None):
        """Add new authentication hook, can be used as a decorator."""
        return self._store(self._authentication, "authentication", auth, None, hook)

    def _set_www_authenticate(self, res: Response) -> Response:
        """Set WWW-Authenticate response header depending on current scheme."""
        if res.status_code == 401:
            schemes = set()
            local = self._fsa._local
            for a in local.auth:
                if a in ("token", "oauth") and self._tm and self._tm._carrier == "bearer":
                    schemes.add(f'{self._tm._name} realm="{local.token_realm}"')
                elif a == "basic":
                    schemes.add(f'Basic realm="{local.realm}"')
                elif a in ("http-token", "http-basic", "digest", "http-digest"):
                    assert self._http_auth
                    schemes.add(self._http_auth.authenticate_header())
                # else: scheme does not rely on WWW-Authenticate…
                # FIXME what about other schemes?
            if schemes:
                res.headers["WWW-Authenticate"] = ", ".join(sorted(schemes))
        # else: no need for WWW-Authenticate
        return res

    def get_user(self, required=True) -> str|None:
        """Authenticate user or throw exception."""

        assert self._initialized

        local = self._fsa._local

        # memoization is safe because local is reset before a request
        if local.source:
            return local.user

        # try authentication schemes
        lae = None  # last error response (should it be the first?)
        for a in local.auth:
            try:
                local.user = self._authentication[a](self, request)
                if local.user:
                    local.source = a
                    break
            except ErrorResponse as e:  # keep last one
                lae = e
            except Exception as e:  # pragma: no cover
                log.error(f"internal error in {a} authentication: {e}")
                self._Exc(e)  # just for recording

        # we tried, even if not set, we say that the answer is the right one
        if not local.source:
            local.source = "none"

        # rethrow last auth exception on failure
        if required and not local.user:
            # we do not leak allowed authentication schemes
            raise lae or self._Err("missing authentication", 401)

        return local.user

    def _authenticate(self, path: str, auth: list[str]|None = None, realm: str|None = None):
        """Decorator to authenticate current user."""

        # check auth parameter
        if auth:
            assert isinstance(auth, list)
            # probably already caught before
            for a in auth:
                if a not in self._authentication:  # pragma: no cover
                    raise self._Bad(f"unexpected authentication scheme {auth} on {path}")

        def decorate(fun: Callable):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                fsa, local = self._fsa, self._fsa._local

                # get user if needed
                if not local.source:
                    # possibly overwrite the authentication scheme
                    # NOTE this may or may not work because other settings may
                    #   not be compatible with the provided scheme…
                    # TODO add coverage
                    if realm:  # pragma: no cover
                        local.realm = realm
                        local.token_realm = realm
                    if auth:  # override allowed authentications
                        local.auth = auth
                    try:
                        self.get_user()
                    except ErrorResponse as e:
                        return self._Res(e.message, e.status, e.headers, e.content_type)

                if not local.user:  # pragma no cover
                    return self._Res("no auth", 401)

                return fsa._safe_call(path, "authenticate", fun, *args, **kwargs)

            return wrapper

        return decorate

    def _auth_has(self, *auth):
        """Tell whether current authentication includes any of these schemes."""
        for a in auth:
            if a in self._fsa._local.auth:
                return True
        return False

    #
    # INHERITED HTTP AUTH
    #
    def _get_httpd_auth(self, app, req: Request) -> str|None:
        """Inherit HTTP server authentication."""
        return req.remote_user

    #
    # HTTP FAKE AUTH
    #
    # Just trust a parameter, *only* for local testing.
    #
    # FSA_FAKE_LOGIN: name of parameter holding the login ("LOGIN")
    #
    def _get_fake_auth(self, app, req: Request) -> str:
        """Return fake user. Only for local tests."""
        assert req.remote_addr.startswith("127.") or req.remote_addr == "::1", \
            "fake auth only on localhost"
        params = self._fsa._pm._params()
        user = params.get(self._login, None)
        if not user:
            raise self._Err(f"missing fake login parameter: {self._login}", 401)
        return user

    #
    # FLASK HTTP AUTH (BASIC, DIGEST, TOKEN)
    #
    def _get_httpauth(self, app, req: Request) -> str:
        """Delegate user authentication to HTTPAuth."""
        assert self._http_auth
        auth = self._http_auth.get_auth()
        assert auth is not None  # help type check
        password = self._http_auth.get_auth_password(auth) if "http-token" not in self._fsa._local.auth else None
        try:
            # NOTE "authenticate" signature is not very clean…
            user = self._http_auth.authenticate(auth, password)
            if user is not None and user is not False:
                if isinstance(user, bool) and user:  # pragma: no cover
                    assert isinstance(auth.username, str)  # type check help
                    return auth.username
                else:
                    assert isinstance(user, str)  # type check help
                    return user
        except ErrorResponse as e:  # pragma: no cover
            log.debug(f"AUTH (http-*): bad authentication {e}")
            raise e
        log.debug("AUTH (http-*): bad authentication")  # pragma: no cover
        raise self._Err("failed HTTP authentication", 401)  # pragma: no cover

    #
    # HTTP BASIC AUTH
    #
    def _get_basic_auth(self, app, req: Request) -> str:
        """Get user with basic authentication."""
        auth = req.headers.get("Authorization", None)
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
        if not self._pm:  # pragma: no cover
            raise self._Err("password manager is disabled", self._fsa._server_error)
        return self._pm.check_user_password(user, pwd)

    #
    # HTTP PARAM AUTH
    #
    # User credentials provided from http or json parameters.
    #
    # FSA_PARAM_USER: parameter name for login ("USER")
    # FSA_PARAM_PASS: parameter name for password ("PASS")
    #
    def _get_param_auth(self, app, req: Request) -> str:
        """Get user with parameter authentication."""
        fsa = self._fsa
        assert fsa._pm  # mypy…
        params = fsa._pm._params()
        user = params.get(self._userp, None)
        if not user:
            raise self._Err(f"missing param login parameter: {self._userp}", 401)
        pwd = params.get(self._passp, None)
        if not pwd:
            raise self._Err(f"missing param password parameter: {self._passp}", 401)
        if not self._pm:  # pragma: no cover
            raise self._Err("password manager is disabled", fsa._server_error)
        return self._pm.check_user_password(user, pwd)

    #
    # TOKEN AUTH
    #
    def _get_token_auth(self, app, req: Request) -> str|None:
        """Authenticate with current token."""
        login = None
        if self._tm:
            token = self._tm._get_token()
            login = self._tm._get_any_token_auth(token)
            if login:  # keep track of token
                self._fsa._local.token = token
        return login


class _NoCache:
    """No cache class."""

    def __init__(self):
        pass

    def __len__(self):
        return 0

    def hits(self):
        return 0.0

    def clear(self):  # pragma: no cover
        return


class _CacheManager:
    """Internal cache management."""

    def __init__(self, fsa):
        assert isinstance(fsa, FlaskSimpleAuth)
        self._fsa = fsa
        self._Bad = fsa._Bad
        # caching stuff
        self._cache: typing.MutableMapping[str, str]|_NoCache|None = None
        self._cache_gen: Callable|None = None
        self._cache_opts: dict[str, Any] = {}
        self._cached_opts: dict[str, Any] = {}
        self._cached = False
        self._cachable: list[tuple[object, str, str]] = []
        self._cache_prefixes: set[str] = set()
        self._initialized = False

    def _initialize(self):
        """After-configuration cache manager initialization."""

        if self._initialized:  # pragma: no cover
            log.warning("Cache Manager is already initialized, skipping…")
            return

        log.info("initializing CacheManager")

        self._cachable.extend([
            (self._fsa._zm, "_check_groups", "c."),
            (self._fsa._zm, "_user_in_group", "g."),
            (self._fsa._zm, "_check_object_perms", "p."),
            (self._fsa._am._tm, "_get_any_token_auth_exp", "t."),
            (self._fsa._am._pm, "_get_user_pass", "u."),
            # see also _token_cache
        ])

        conf = self._fsa._app.config

        cache = conf.get("FSA_CACHE", Directives.FSA_CACHE)
        if cache is None or cache == "none":
            log.warning("Cache management is disactivated")
            self._cache = _NoCache()
            self._cache_gen = None
            self._initialized = True
            return

        self._cache_opts.update(conf.get("FSA_CACHE_OPTS", Directives.FSA_CACHE_OPTS))
        self._cached_opts.update(conf.get("FSA_CACHED_OPTS", Directives.FSA_CACHED_OPTS))

        # NOTE no try/except because the dependency is mandatory
        import cachetools as ct
        import CacheToolsUtils as ctu  # type: ignore

        prefix: str|None = conf.get("FSA_CACHE_PREFIX", None)

        if isinstance(cache, typing.MutableMapping):
            log.info("CacheManager cache shorcut")
            if prefix:
                cache = ctu.PrefixedCache(cache, prefix)
            # FIXME should not add a stats cache if there is already one!
            self._cache = ctu.StatsCache(cache)
            self._cache_gen = ctu.PrefixedCache
        elif cache in ("ttl", "lru", "tlru", "lfu", "mru", "fifo", "rr", "dict"):
            maxsize = conf.get("FSA_CACHE_SIZE", Directives.FSA_CACHE_SIZE)
            # build actual storage tier
            if cache == "ttl":
                ttl = self._cache_opts.pop("ttl", Directives._FSA_CACHE_TTL)
                rcache: typing.MutableMapping = ct.TTLCache(maxsize, **self._cache_opts, ttl=ttl)
            elif cache == "lru":
                rcache = ct.LRUCache(maxsize, **self._cache_opts)
            elif cache == "lfu":
                rcache = ct.LFUCache(maxsize, **self._cache_opts)
            elif cache == "mru":  # pragma: no cover
                rcache = ct.MRUCache(maxsize, **self._cache_opts)  # deprecated…
            elif cache == "fifo":
                rcache = ct.FIFOCache(maxsize, **self._cache_opts)
            elif cache == "rr":
                rcache = ct.RRCache(maxsize, **self._cache_opts)
            elif cache == "tlru":
                rcache = ct.TLRUCache(maxsize, **self._cache_opts)
            elif cache == "dict":
                rcache = dict()
            else:  # pragma: no cover
                raise self._Bad(f"unexpected simple cache type: {cache}")
            if prefix:
                rcache = ctu.PrefixedCache(rcache, prefix)
            self._cache = ctu.StatsCache(rcache)
            self._cache_gen = ctu.PrefixedCache
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
            self._cache = ctu.MemCached(pmc.Client(**self._cache_opts))
            self._cache_gen = ctu.PrefixedMemCached
        elif cache == "redis":
            try:
                import redis
            except ModuleNotFoundError:  # pragma: no cover
                log.error("missing module: install FlaskSimpleAuth[redis]")
                raise

            ttl = self._cache_opts.pop("ttl", Directives._FSA_CACHE_TTL)
            rc = redis.Redis(**self._cache_opts)
            if prefix:
                self._cache = ctu.PrefixedRedisCache(rc, prefix=prefix, ttl=ttl)
            else:
                self._cache = ctu.RedisCache(rc, ttl=ttl)
            self._cache_gen = ctu.PrefixedRedisCache
        else:
            raise self._Bad(f"unexpected FSA_CACHE: {cache}")

        # cache locking
        local = conf.get("FSA_LOCAL", "thread")
        if local == "process":
            pass
        else:
            if local in ("thread", "werkzeug", "eventlet"):
                from threading import RLock
            elif local == "gevent":  # pragma: no cover
                from gevent.lock import RLock  # type: ignore
            else:  # pragma: no cover
                raise self._Bad(f"unexpected FSA_LOCAL: {local}")
            self._cache = ctu.LockedCache(self._cache, RLock())

        # done!
        self._initialized = True

    def _cache_init(self):
        """Check for cache availability."""

        if not self._initialized:  # pragma: no cover
            self._initialize()

    # wrap _cache_gen by checking that prefix is not used yet
    def _cache_new(self, cache, prefix: str) -> typing.MutableMapping[str, str]:
        """Create a new unique prefix cache."""

        assert self._initialized and self._cache_gen

        if prefix in self._cache_prefixes:  # pragma: no cover
            raise self._Bad(f"Cache prefix \"{prefix}\" is already used")

        self._cache_prefixes.add(prefix)
        return self._cache_gen(cache=self._cache, prefix=prefix)

    def _set_cache(self, prefix: str):  # pragma: no cover
        """Decorator to cache function calls with a prefix."""

        self._cache_init()

        def decorate(fun: Callable):
            import CacheToolsUtils as ctu
            return ctu.cached(cache=self._cache_new(self._cache, prefix), **self._cached_opts)(fun)

        return decorate

    def _set_caches(self):
        """Deferred creation of caches around some functions."""

        self._cache_init()

        if self._cache_gen is None:
            log.warning("Cache is disabled, cannot set caches")
            self._cached = True  # Hmmm…
            return

        if self._cached:  # pragma: no cover
            log.warning("Caches already set, skipping…")
            return

        log.info("setting up cache…")
        import CacheToolsUtils as ctu

        assert isinstance(self._cache, typing.MutableMapping)  # help type check

        for obj, meth, prefix in self._cachable:
            if obj and hasattr(obj, meth) and getattr(obj, meth) is not None:
                log.debug(f"cache: caching {meth[1:]}")
                ctu.cacheMethods(cache=self._cache, obj=obj, gen=self._cache_new, **{meth: prefix})  # type: ignore
            else:
                log.info(f"cache: skipping {meth[1:]}")

        # manual cache: user/realm -> last seen token
        self._fsa._am._tm._token_cache = self._cache_new(cache=self._cache, prefix="T.")

        # do not process again!
        self._cached = True


class _AuthorizationManager:
    """Internal authorization management.

    This class holds special group, oauth and object authorization methods
    and related decorators.
    """

    def __init__(self, fsa):
        assert isinstance(fsa, FlaskSimpleAuth)  # forward declaration needed…
        self._fsa = fsa
        # forward
        self._Bad = fsa._Bad
        self._Res = fsa._Res
        self._Exc = fsa._Exc
        self._store = fsa._store
        # authorization stuff
        self._group_checks: dict[int|str, Hooks.GroupCheckFun] = dict()
        self._object_perms: dict[Any, Hooks.ObjectPermsFun] = dict()
        self._user_in_group: Hooks.UserInGroupFun|None = None
        self._groups: set[str|int] = set()
        self._scopes: set[str] = set()
        self._initialized = False

    def _initialize(self):
        """After-configuration authorization manager initialization."""

        if self._initialized:  # pragma: no cover
            log.warning("Authorization Manager already initialized, skipping…")
            return

        conf = self._fsa._app.config
        self._groups.update(conf.get("FSA_AUTHZ_GROUPS", []))
        self._scopes.update(conf.get("FSA_AUTHZ_SCOPES", []))
        self._fsa._set_hooks("FSA_GROUP_CHECK", self.group_check)
        self._fsa._set_hooks("FSA_OBJECT_PERMS", self.object_perms)
        if "FSA_USER_IN_GROUP" in conf:
            self._user_in_group = conf["FSA_USER_IN_GROUP"]
        self._initialized = True

    def group_check(self, group: str|int, checker: Hooks.GroupCheckFun|None = None):
        """Add a check hook for a group."""
        self._groups.add(group)
        return self._store(self._group_checks, "group authz checker", group, None, checker)

    def _check_groups(self, login: str, group: str|int) -> bool|None:
        """Return whether login belongs to group, or *None* if no group check hook."""
        return self._group_checks[group](login) if group in self._group_checks else None

    def group_uncache(self, user: str, group: str|int) -> bool:
        """Remove group membership entry from cache."""
        if not self._fsa._cm._cache_gen:  # pragma: no cover
            log.debug("cache is not activated, cannot uncache group, skipping…")
            return False
        r1 = self._check_groups.cache_del(user, group)  # type: ignore
        if self._user_in_group and hasattr(self._user_in_group, "cache_del"):
            r2 = self._user_in_group.cache_del(user, group)  # type: ignore
        else:  # pragma: no cover
            r2 = False
        return r1 or r2

    def object_perms(self, domain: str, checker: Hooks.ObjectPermsFun|None = None):
        """Add an object permission helper for a given domain."""
        return self._store(self._object_perms, "object permission checker", domain, None, checker)

    def _check_object_perms(self, domain: str, user: str, *args) -> bool|None:
        """Can user access object in domain for, cached."""
        assert domain in self._object_perms
        return self._object_perms[domain](user, *args)

    def object_perms_uncache(self, domain: str, user: str, *args) -> bool:
        """Remove object perm entry from cache."""
        if not self._fsa._cm._cache_gen:  # pragma: no cover
            log.debug("cache is not activated, cannot uncache object perms, skipping…")
            return False
        return self._check_object_perms.cache_del(domain, user, *args)  # type: ignore

    def _oauth_authz(self, path, *scopes):
        """Decorator to authorize OAuth scopes (token-provided authz)."""

        if self._scopes:
            for scope in scopes:
                if scope not in self._scopes:
                    raise self._Bad(f"unexpected scope {scope}")

        def decorate(fun: Callable):
            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                self._fsa._local.need_authorization = False

                for scope in scopes:
                    if not self._fsa.user_scope(scope):
                        return self._Res(f'missing permission "{scope}"', 403)

                return self._fsa._safe_call(path, "oauth authorization", fun, *args, **kwargs)

            return wrapper

        return decorate

    def _group_authz(self, path, *groups):
        """Decorator to authorize user groups."""

        # predefs cannot be mixed with other groups
        for grp in _PREDEFS:
            if grp in groups:
                raise self._Bad(f"unexpected predefined {grp}")

        if self._groups:  # check against declared groups
            for grp in groups:
                if grp not in self._groups:
                    raise self._Bad(f"unexpected group {grp}")

        for grp in groups:  # check whether it can be tested
            if grp not in self._group_checks and not self._user_in_group:
                raise self._Bad(f"cannot check group {grp} authz")

        def decorate(fun: Callable):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                fsa = self._fsa
                local = fsa._local

                # track that some authorization check was performed
                local.need_authorization = False

                # check against all authorized groups/roles
                for grp in groups:
                    try:
                        if grp in self._group_checks:
                            ok = self._check_groups(local.user, grp)
                        else:
                            assert self._user_in_group  # redundant, please mypy
                            ok = self._user_in_group(local.user, grp)
                    except ErrorResponse as e:
                        return self._Res(e.message, e.status, e.headers, e.content_type)
                    except Exception as e:
                        log.error(f"group check failed: {e}")
                        if self._Exc(e):  # pragma: no cover
                            raise
                        return self._Res(f"internal error while checking group {grp}", fsa._server_error)
                    if not isinstance(ok, bool):
                        log.error(f"type error in group check: {ok}: {_type(ok)}, must return a boolean")
                        return self._Res(f"internal error in group check for {grp}", fsa._server_error)
                    elif not ok:
                        return self._Res(f'not in group "{grp}"', 403)

                # all groups are ok, proceed to call underlying function
                return fsa._safe_call(path, "group authorization", fun, *args, **kwargs)

            return wrapper

        return decorate

    # just to record that no authorization check was needed
    def _no_authz(self, path, *groups):
        """Decorator for skipping authorizations (authz="AUTH")."""

        def decorate(fun: Callable):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                self._fsa._local.need_authorization = False
                return self._fsa._safe_call(path, "no authorization", fun, *args, **kwargs)

            return wrapper

        return decorate

    def _perm_authz(self, path, first, *perms):
        """Decorator for per-object permissions."""
        # check perms wrt to recorded per-object checks

        # normalize tuples length to 3 and split names
        perms = list(map(lambda a: (a + (first, None)) if len(a) == 1 else
                                   (a + (None,)) if len(a) == 2 else
                                   a, perms))

        # perm checks
        for perm in perms:
            if not len(perm) == 3:
                raise self._Bad(f"per-object permission tuples must have 3 data {perm} on {path}")
            domain, names, mode = perm
            if domain not in self._object_perms:
                raise self._Bad(f"missing object permission checker for {perm} on {path}")
            if not isinstance(names, str):
                raise self._Bad(f"unexpected identifier name type ({_type(names)}) for {perm} on {path}")
            if mode is not None and type(mode) not in (int, str):
                raise self._Bad(f"unexpected mode type ({_type(mode)}) for {perm} on {path}")

        # split names
        perms = [(d, names.split(":"), m) for d, names, m in perms]

        # check names in passing
        for domain, names, _ in perms:
            for name in names:
                if not re.match(r"[_A-Za-z][_A-Za-z0-9]*$", name):
                    raise self._Bad(f"unexpected permission identifier name {name} for {domain} permission on {path}")

        def decorate(fun: Callable):

            # check perms wrt fun signature
            for domain, names, _ in perms:
                for name in names:
                    if name not in fun.__code__.co_varnames:
                        raise self._Bad(f"missing function parameter {name} for {domain} permission on {path}")
                    # FIXME should parameter type be restricted to int or str?

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                fsa = self._fsa
                local = fsa._local

                # track that some autorization check was performed
                local.need_authorization = False

                for domain, names, mode in perms:
                    vals = [kwargs[name] for name in names]

                    try:
                        ok = self._check_object_perms(domain, local.user, *vals, mode)
                    except ErrorResponse as e:
                        return self._Res(e.message, e.status, e.headers, e.content_type)
                    except Exception as e:
                        log.error(f"internal error on {request.method} {request.path} permission {perms} check: {e}")
                        if self._Exc(e):  # pragma: no cover
                            raise
                        return self._Res("internal error in permission check", fsa._server_error)

                    if ok is None:
                        log.warning(f"none object permission on {domain} {vals} {mode}")
                        return self._Res("object not found", fsa._not_found_error)
                    elif not isinstance(ok, bool):  # paranoid?
                        log.error(f"type error on on {request.method} {request.path} permission {perms} check: {_type(ok)}")
                        return self._Res("internal error with permission check", fsa._server_error)
                    elif not ok:
                        return self._Res(f"permission denied on {domain}:{vals} ({mode})", 403)
                    # else: all is well, check next!

                # then call the initial function
                return fsa._safe_call(path, "perm authorization", fun, *args, **kwargs)

            return wrapper

        return decorate


class _ParameterHandler:
    """Internal handler for one parameter.

    Handle a request parameter depending on its type hint.

    :param pm: parameter manager
    :param hint: parameter description from inspect
    :param where: parameter location for error messages
    :param is_special: function is a special parameter hook
    """

    def __init__(self, pm, name: str, hint: inspect.Parameter, where: str, is_special: bool):

        assert hint.kind not in (inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL)

        self._pm = pm  # parameter manager

        # python and request names
        self._name = name
        self._rname = name[1:] if len(name) > 1 and name[0] == "_" else name

        # special parameter, otherwise standard route function?
        self._is_special = is_special

        # expected type
        self._type = _typeof(hint)
        self._type_is_json = self._type == JsonData
        self._type_is_optional = self._type_is_json or _is_optional(hint.annotation)
        self._type_is_generic = _is_generic_type(hint)
        self._type_list_item = _is_list_of(self._type)
        self._type_is_list = self._type_list_item is not None
        self._type_list_item_caster = self._pm._casts.get(self._type_list_item, self._type_list_item)

        if self._type_is_json:  # anything converted from JSON, really
            self._type_isinstance = None
        else:
            try:
                isinstance("", self._type)
                self._type_isinstance = lambda v: self._type_is_optional and v is None or isinstance(v, self._type)
            except Exception:  # FIXME TypeError instead?
                self._type_isinstance = None

        # typing
        self._extract: Hooks.SpecialParameterFun|None
        self._convert_para: Callable[[str], Any]|None
        self._convert_json: Callable[[Any], Any]|None
        self._caster: Hooks.CastFun|None
        self._checker: Callable[[Any], bool]|None

        # build extract/convert/check functions as necessary
        if self._type in self._pm._special_parameters:

            # directly get the parameter from wherever
            self._extract = self._pm._special_parameters[self._type]
            self._convert_para = None
            self._convert_json = None
            self._caster = self._type if issubclass(self._type, str) else None
            self._checker = None

        elif self._type_is_json:

            self._extract = None
            self._convert_para = json.loads
            self._convert_json = lambda v: v
            self._caster = None
            self._checker = None

        elif self._type_is_list:

            # NOTE for http we assume b=1&b=2

            # lists a handled differently for http parameters
            def not_provided(_):  # pragma: no cover
                raise self._pm._Err("not provided")

            # FIXME do we want to convert or be strict?
            # - http: we do want to convert otherwise everything is a string
            # - json: it could depend… eg [1,2] is a list[str]?
            def cast_list_items(la):
                assert isinstance(la, list)
                for i in range(len(la)):
                    if not isinstance(la[i], self._type_list_item):
                        try:
                            la[i] = self._type_list_item_caster(la[i])
                        except Exception as e:
                            raise self._pm._Err(f"parameter \"{self._rname}\" item {i} type error: {e}", 400)
                return la

            self._extract = None
            self._convert_para = not_provided
            self._convert_json = lambda v: v
            self._caster = cast_list_items
            self._checker = lambda v: _check_type(self._type, v)

        elif self._type_is_generic:
            # only handle generics on simple types

            # check that a is a simple generic consistent with _check_type
            if not _valid_type(self._type):
                raise self._pm._Bad(f"unsupported generic type {self._type}", where)

            self._extract = None
            self._convert_para = json.loads
            self._convert_json = lambda v: v
            self._caster = None
            self._checker = lambda v: _check_type(self._type, v)

        elif (self._pm._pydantic_base_model is not None and
              isinstance(self._type, type) and
              issubclass(self._type, self._pm._pydantic_base_model) or
              hasattr(self._type, "__dataclass_fields__")):

            def is_dict(val):
                if not isinstance(val, dict):
                    raise self._pm._Err(f"unexpected value {val} for dict", 400)
                return val

            self._extract = None
            self._convert_para = json.loads
            self._convert_json = is_dict
            self._caster = lambda v: self._type(**v)  # type: ignore
            self._checker = None

        elif self._type == FileStorage:  # special case

            def no_json(_):  # pragma: no cover
                raise self._pm._Err("cannot upload files as JSON", 400)

            assert self._type_isinstance is not None
            self._extract = None
            self._convert_para = lambda v: v
            self._convert_json = no_json
            self._caster = None
            self._checker = None

        else:  # default

            self._extract = None
            self._convert_para = lambda x: x
            self._convert_json = lambda x: x
            self._caster = self._pm._casts.get(self._type, self._type)
            self._checker = None

        # special parameter functions can only have special parameters beyond
        # the first parameter which holds the parameter name
        if is_special and self._extract is None:
            raise self._pm._Bad(f"parameter {name} in special parameter is not a special parameter", where)

        for caster in (self._caster, self._type_list_item_caster):
            if caster and (not callable(caster) or caster.__module__ == "typing"):
                raise self._pm._Bad(f"parameter {name} type cast {caster} is not callable", where)

        # default value if any
        self._has_default = hint.default != inspect._empty
        self._default_value = hint.default if self._has_default else None

        if self._has_default:  # check default value consistency
            # FIXME should also check list items if appropriate?

            if is_special:
                raise self._pm._Bad(f"special parameter {name} cannot have a default value", where)

            if self._default_value is None:
                if not self._type_is_optional:
                    log.warning(f"parameter {name} is not optional but defaults to None")
                # else: pass
            elif self._type_isinstance:
                val = self._default_value
                if isinstance(val, str) and self._type != str and self._caster:
                    try:
                        val = self._caster(val)
                    except Exception as e:
                        raise self._pm._Bad(f"parameter {name} cannot cast default value: {e}")
                if not isinstance(val, self._type):
                    raise self._pm._Bad(f"parameter {name} bad type for default value ({val}: {self._type})")

            if self._checker:
                if self._type_is_optional and self._default_value is None:
                    pass  # skip check call on optional values
                else:
                    try:
                        if not self._checker(self._default_value):
                            raise self._pm._Bad(f"parameter {name} bad check for default value ({self._default_value})")
                    except Exception as e:  # pragma: no cover
                        raise self._pm._Bad(f"parameter {name} error while checking default value: {e}")

    def __call__(self, req, params, kwargs, e400):
        """Extract value for parameters."""

        # special parameters are handled directly
        if self._extract:
            if self._rname in params:
                e400(f"unexpected request parameter \"{self._rname}\"")
                return None
            try:
                return self._extract(self._rname)
            except Exception:  # on error, return the default if any
                if self._has_default:
                    return self._default_value
                else:
                    raise

        # path & request parameter
        if self._rname in params and self._name in kwargs:
            e400(f"parameter \"{self._rname}\" both from path and request")
            return None

        # missing/default parameters
        if self._rname not in params and self._name not in kwargs:
            if not self._has_default:
                e400(f"parameter \"{self._rname}\" is missing")
                return None
            return self._default_value

        # get parameter raw value
        if self._name in kwargs:  # path parameter
            val = kwargs[self._name]
        else:  # rname in params: request parameter
            assert self._convert_json and self._convert_para  # mypy
            if self._type_is_list and not req.is_json:
                # FIXME unconvincing adhoc partial implementation
                val = params.getlist(self._rname)
            else:
                try:
                    val = (self._convert_json if req.is_json else self._convert_para)(params[self._rname])
                except Exception as e:  # pragma: no cover
                    e400(f"parameter \"{self._rname}\" conversion error: {e}")
                    return None

        # cast? also for path parameters??
        if self._caster:
            try:
                if self._type_is_optional and val is None:
                    pass
                elif self._type_isinstance:
                    if not self._type_isinstance(val):
                        val = self._caster(val)
                    # else just keep it as is!
                else:  # blind cast
                    val = self._caster(val)
            except Exception as e:
                e400(f"parameter \"{self._rname}\" cast error on {val}: {e}")
                return None
        elif self._type_isinstance:
            if not self._type_isinstance(val):
                e400(f"parameter \"{self._rname}\" type error on {val} for {self._type}")
                return None

        # check value if needed, exceptions are sent upwards
        if self._checker and not self._checker(val):
            e400(f"parameter \"{self._rname}\" unexpected value {val} for type {self._type}")
            return None

        return val


class _ParameterManager:
    """Internal parameter management."""

    def __init__(self, fsa):
        assert isinstance(fsa, FlaskSimpleAuth)  # forward declaration…
        self._fsa = fsa
        # forward
        self._Err = fsa._Err
        self._Bad = fsa._Bad
        self._Exc = fsa._Exc
        self._Res = fsa._Res
        self._store = fsa._store

        # parameter management
        def bool_cast(s):
            if isinstance(s, bool):  # pragma: no cover
                return s
            if isinstance(s, str):
                return s.lower() not in ("", "0", "false", "f")
            raise self._Err(f"cannot cast to bool: {_type(s)}", 400)  # pragma: no cover

        def int_cast(s):
            if isinstance(s, bool):  # pragma: no cover
                raise self._Err("will not cast bool to int", 400)
            if isinstance(s, int):  # pragma: no cover
                return s
            if isinstance(s, str):
                return int(s, base=0)
            raise self._Err(f"cannot cast to int: {_type(s)}", 400)  # pragma: no cover

        # predefined cases, extend with cast
        self._casts: dict[type, Hooks.CastFun] = {
            bool: bool_cast,
            int: int_cast,
            inspect._empty: str,
            path: str,
            string: str,
            dt.date: dt.date.fromisoformat,
            dt.time: dt.time.fromisoformat,
            dt.datetime: dt.datetime.fromisoformat,
            FileStorage: None,  # type: ignore
        }
        # predefined special parameter types, extend with special_parameter
        self._special_parameters: dict[type, Hooks.SpecialParameterFun] = {
            Request: lambda _: request,
            Environ: lambda _: request.environ,
            Session: lambda _: session,
            Globals: lambda _: g,
            CurrentUser: lambda _: fsa.current_user(),
            CurrentApp: lambda _: current_app,
            Cookie: lambda p: request.cookies[p],
            Header: lambda p: request.headers[p],
        }
        # whether to error on unexpected parameters
        self._reject_param = Directives.FSA_REJECT_UNEXPECTED_PARAM
        # pydantic generated class support
        try:
            import pydantic
            self._pydantic_base_model = pydantic.BaseModel  # type: ignore
        except ModuleNotFoundError:  # pragma: no cover
            self._pydantic_base_model = None  # type: ignore
        self._initialized = False

    def _initialize(self):
        """After-configuration parameter manager initialization."""

        if self._initialized:  # pragma: no cover
            log.warning("Parameter Manager already initialized, skipping…")
            return

        fsa, conf = self._fsa, self._fsa._app.config

        self._reject_param = conf.get("FSA_REJECT_UNEXPECTED_PARAM", Directives.FSA_REJECT_UNEXPECTED_PARAM)
        fsa._set_hooks("FSA_CAST", self.cast)
        fsa._set_hooks("FSA_SPECIAL_PARAMETER", self.special_parameter)
        self._initialized = True

    def cast(self, t, cast: Hooks.CastFun|None = None):
        """Add a cast function associated to a type."""
        return self._store(self._casts, "type casting", t, None, cast)

    def special_parameter(self, t, sp: Hooks.SpecialParameterFun|None = None):
        """Add a special parameter type."""
        return self._store(self._special_parameters, "special parameter", t,
                           # wrapper to handle special parameters…
                           lambda f: self._parameters("*", False, True)(f), sp)

    def _params(self):
        """Get request parameters wherever they are."""
        if request.is_json:
            self._fsa._local.params = "json"
            # FIXME should it always be a dict? if not the CombinedMultiDict will fail
            if not isinstance(request.json, dict):  # pragma: no cover
                log.warning(f"request.json is expected to be a dict, got {_type(request.json)}.")
            # NOTE json + args may result in unexpected corner case behavior…
            # NOTE form and files cannot co-exists with json
            return CombinedMultiDict([request.json, request.args])
        else:
            self._fsa._local.params = "http"
            # reimplement "request.values" after Flask 2.0 regression
            # the logic of web-oriented HTTP does not make sense for a REST API
            # https://github.com/pallets/werkzeug/pull/2037
            # https://github.com/pallets/flask/issues/4120
            return CombinedMultiDict([request.args, request.form, request.files])

    def _noparams(self, path):
        """Check that there are no unused parameters."""

        def decorate(fun: Callable):

            @functools.wraps(fun)
            def wrapper(*args, **kwargs):

                fsa = self._fsa
                am = fsa._am
                local = fsa._local
                assert am  # mypy…

                if self._reject_param:
                    params = self._params()
                    if params:
                        sparams = set(params.keys())
                        if not sparams.issubset(am._auth_params):
                            bads = ' '.join(sorted(list(sparams - am._auth_params)))
                            return f"unexpected {local.params} parameters: {bads}", 400

                return fsa._safe_call(path, "no params", fun, *args, **kwargs)

            return wrapper

        return decorate

    def _parameters(self, path: str, is_open: bool, is_special: bool = False):
        """Decorator to handle route/special function parameters.

        :param path: route path
        :param is_open: whether route is open, i.e. not authenticated
        :param is_special: whether decorated function is a special parameter hook
        """

        assert not is_special or path == "*" and not is_open

        def decorate(fun: Callable):

            # how to handle parameters
            handlers: dict[str, _ParameterHandler] = {}
            names: dict[str, str] = {}
            has_kwargs = False

            # parameters types/casts and defaults taken from signature
            sigs = inspect.signature(fun)
            where = f"{fun.__name__}() at {fun.__code__.co_filename}:{fun.__code__.co_firstlineno}"

            # build helpers
            nparam = 0
            for name, param in sigs.parameters.items():
                nparam += 1
                if is_special and nparam == 1:
                    # check first parameter kind and type in passing for special parameter function
                    if param.kind != inspect.Parameter.POSITIONAL_OR_KEYWORD:
                        raise self._Bad("invalid first parameter kind for special parameter function", where)
                    if param.annotation not in (str, inspect._empty):
                        raise self._Bad("first parameter of special parameter function must be str", where)
                    continue
                if name in handlers or name in names:
                    raise self._Bad(f"parameter name collision on {name}", where)
                elif param.kind == inspect.Parameter.VAR_KEYWORD:
                    has_kwargs = True
                elif param.kind == inspect.Parameter.VAR_POSITIONAL:
                    raise self._Bad(f"unsupported positional parameter: {name}", where)
                else:
                    handler = _ParameterHandler(self, name, param, where, is_special)
                    handlers[name] = handler
                    names[handler._rname] = name
                # reject CurrentUser special parameter under authz="OPEN"
                if is_open and _typeof(param) == CurrentUser:
                    raise self._Bad(f"cannot get {name} current user on open (non authenticated) route {path}", where)

            if is_special:
                # sanity checks in passing
                assert not has_kwargs
                if nparam == 0:
                    raise self._Bad("special parameter function must have a str first parameter", where)
                if nparam == 1:  # shortcut, no wrapping needed
                    return fun

            # debug helpers
            def getNames(pl):
                return sorted(map(lambda n: handlers[n]._rname, pl))

            mandatory = getNames(filter(lambda n: not handlers[n]._has_default, handlers.keys()))
            optional = getNames(filter(lambda n: handlers[n]._has_default, handlers.keys()))
            signature = f"{fun.__name__}({', '.join(mandatory)}, [{', '.join(optional)}])"

            def debugParam():
                params = sorted(self._params().keys())
                mtype = request.headers.get("Content-Type", "?")
                return f"{signature}: {' '.join(params)} [{mtype}]"

            # translate request parameters to named function parameters
            @functools.wraps(fun)
            def wrapper(*args, **kwargs):
                # NOTE *args and **kwargs are more or less empty before being filled in from HTTP

                fsa = self._fsa
                am = fsa._am
                local = fsa._local
                assert am  # mypy…

                if is_special:
                    assert len(args) == 1, "expecting target parameter name as first parameter"
                    params = []
                else:
                    params = self._params()  # HTTP or JSON params

                # detect all possible 400 errors before returning
                error_400: list[str] = []
                e400 = error_400.append

                # process all expected parameters
                for name, handler in handlers.items():
                    rname = handler._rname
                    # TODO list[str] ?
                    # if tp == list[str] and self._fsa._local.params == "http":
                    #     val = params.getlist(pn)
                    # else:
                    #     val = params[pn]
                    try:
                        kwargs[name] = handler(request, params, kwargs, e400)
                    except ErrorResponse as e:
                        if e.status == 400:
                            e400(f"error on parameter \"{rname}\": {e.message}")
                            continue
                        else:  # pragma: no cover
                            raise  # rethrow?
                    except Exception as e:
                        if self._Exc(e):  # pragma: no cover
                            raise
                        # this is some unexpected internal error
                        return self._Res(f"unexpected error on parameter \"{rname}\" ({e})",
                                         self._fsa._server_error)

                # possibly add others, without shadowing already provided ones
                if is_special:
                    pass
                elif has_kwargs:  # handle **kwargs
                    for rname in params:
                        if rname not in kwargs and rname not in am._auth_params:
                            kwargs[rname] = params[rname]  # cold copy
                elif fsa._mode >= _Mode.DEBUG or self._reject_param:
                    # detect unused parameters and warn or reject them
                    for rname in params:
                        if rname not in names and rname not in am._auth_params:
                            if fsa._mode >= _Mode.DEBUG:
                                log.debug(f"unexpected {local.params} parameter \"{rname}\"")
                                if fsa._mode >= _Mode.DEBUG2:
                                    log.debug(debugParam())
                            if self._reject_param:
                                e400(f"unexpected {local.params} parameter \"{rname}\"")
                                continue

                if error_400:
                    return self._Res("\n".join(error_400), 400)

                return fsa._safe_call(path, "parameters", fun, *args, **kwargs)

            return wrapper

        return decorate


class _RequestManager:
    """Internal request management."""

    def __init__(self, fsa):
        assert isinstance(fsa, FlaskSimpleAuth)  # forward declaration…
        self._fsa, app = fsa, fsa._app
        # forward
        self._Bad = fsa._Bad
        self._Res = fsa._Res
        self._Exc = fsa._Exc
        self._Err = fsa._Err
        # request-related stuff
        self._secure: bool = True
        self._secure_warning = True
        # request hooks
        self._before_requests: list[Hooks.BeforeRequestFun] = []
        self._before_exec_hooks: list[Hooks.BeforeExecFun] = []
        # registered here to avoid being bypassed by user hooks, executed in order
        # FIXME not always?
        app.before_request(self._show_request)
        app.before_request(self._auth_reset_user)
        app.before_request(self._check_secure)
        app.before_request(self._run_before_requests)
        self._initialized = False

    def _initialize(self) -> None:
        """After-configuration request manager initialization."""

        if self._initialized:  # pragma: no cover
            log.warning("Request Manager already initialized, skipping…")
            return

        # whether to only allow secure requests
        conf = self._fsa._app.config

        self._secure = conf.get("FSA_SECURE", True)
        if not self._secure:
            log.warning("not secure: non local http queries are accepted")
        # request hooks
        self._before_requests = conf.get("FSA_BEFORE_REQUEST", [])
        self._before_exec_hooks += conf.get("FSA_BEFORE_EXEC", [])
        self._initialized = True

    # run hooks
    def _execute_hooks(self, path: str, what: str, fun: Callable, hooks: list[Hooks.BeforeExecFun]):
        """Run a hook, handling possible errors if necessary."""

        @functools.wraps(fun)
        def wrapper(*args, **kwargs) -> Response:

            fsa, login, auth = self._fsa, self._fsa.current_user(), self._fsa._local.auth

            # apply all hooks
            for hook in hooks:
                try:
                    res = hook(request, login, auth)
                    if res:
                        if fsa._mode >= _Mode.DEBUG2:
                            log.debug(f"returning on {request.method} {request.path} {what}")
                        return res
                except Exception as e:
                    if self._Exc(e):  # pragma: no cover
                        raise
                    return self._Res(f"internal error in {what}", fsa._server_error)

            # then call the initial function
            return fsa._safe_call(path, what, fun, *args, **kwargs)

        return wrapper

    #
    # PREDEFINED HOOKS
    #
    def _check_secure(self) -> Response|None:
        """Before request hook to reject insecure (non-TLS) requests."""
        if not request.is_secure and request.remote_addr and not (
            request.remote_addr.startswith("127.") or request.remote_addr == "::1"
        ):  # pragma: no cover
            if self._secure:
                log.error("insecure HTTP request, allow with FSA_SECURE=False")
                return self._Res("insecure HTTP request denied", self._fsa._server_error)
            else:  # one warning is issued
                if self._secure_warning:
                    log.warning("insecure HTTP request seen")
                    self._secure_warning = False
        return None

    def _auth_reset_user(self) -> None:
        """Before request hook to cleanup authentication and authorization."""
        fsa, local = self._fsa, self._fsa._local
        # measure execution time
        local.start = dt.datetime.timestamp(dt.datetime.now())
        # whether some routing has occurred, vs a before_request generated response
        local.routed = False
        # authentication and authorizations
        local.source = None              # what authn has been used
        local.user = None                # for this user
        local.need_authorization = True  # whether some authz occurred
        assert fsa._am and fsa._am._tm   # mypy…
        local.auth = fsa._am._default_auth or fsa._am._auth  # allowed authn schemes
        local.realm = fsa._am._realm     # authn realm
        local.token_realm = fsa._am._tm._realm if fsa._am._tm else None
        local.scopes = None              # current oauth scopes
        local.params = None              # json|http parameters
        local.token = None               # current token if any

    def _show_request(self) -> None:
        """Show request in logs when in debug mode."""
        fsa = self._fsa
        if fsa._mode >= _Mode.DEBUG4:
            # FIXME is there a decent request prettyprinter?
            assert fsa._pm  # mypy…
            r = request
            rpp = f"{r}\n"
            params = fsa._pm._params()
            if params:
                show = [f"{name} ({_type(params[name])})" for name in sorted(params.keys())]
                rpp += "\t- params: " + ", ".join(show) + "\n"
            else:
                rpp += "\t- no params\n"
            # detailed parameter sources
            # rpp += " - args: " + ", ".join(sorted(request.args.keys())) + "\n"
            # rpp += " - form: " + ", ".join(sorted(request.form.keys())) + "\n"
            # rpp += " - files: " + ", ".join(sorted(request.files.keys())) + "\n"
            rpp += f"\t{r.method} {r.path} HTTP/?\n\t" + \
                "\n\t".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n"
            cookies = "; ".join(f"{k}={v}" for k, v in r.cookies.items())
            if cookies:  # pragma: no cover
                rpp += f"\tCookie: {cookies}\n"
            log.debug(rpp)

    def _run_before_requests(self) -> Response|None:
        """Run internal before request hooks."""
        for fun in self._before_requests:
            rep = fun(request)
            if rep is not None:
                return rep
        return None


class _ResponseManager:
    """Internal response management."""

    def __init__(self, fsa):
        assert isinstance(fsa, FlaskSimpleAuth)  # forward declaration…
        self._fsa = fsa
        # forward
        self._Bad = fsa._Bad
        self._Res = fsa._Res
        self._Exc = fsa._Exc
        self._Err = fsa._Err
        # response-related stuff
        self._error_response: Hooks.ErrorResponseFun = lambda m, s, h, c: Response(m, s, h, c)
        self._cors: bool = False
        self._cors_opts: dict[str, Any] = {}
        self._401_redirect: str|None = None
        self._url_name: str|None = None
        self._after_requests: list[Hooks.AfterRequestFun] = []
        self._headers: dict[str, Hooks.HeaderFun|str] = {}
        self._default_type: str|None = None
        self._initialized = False

    def _initialize(self):
        """After-configuration response manager initialization."""

        if self._initialized:  # pragma: no cover
            log.warning("Response Manager already initialized, skipping…")
            return

        fsa, app, conf = self._fsa, self._fsa._app, self._fsa._app.config

        # default content type
        self._default_type = conf.get("FSA_DEFAULT_CONTENT_TYPE", Directives.FSA_DEFAULT_CONTENT_TYPE)

        global _fsa_json_streaming
        _fsa_json_streaming = conf.get("FSA_JSON_STREAMING", Directives.FSA_JSON_STREAMING)

        # FIXME should check default_type type?
        # generate response on errors
        error = conf.get("FSA_ERROR_RESPONSE", Directives.FSA_ERROR_RESPONSE)
        if error is None:
            raise self._Bad("unexpected FSA_ERROR_RESPONSE: None")
        elif callable(error):
            self._error_response = error  # type: ignore
        elif not isinstance(error, str):
            raise self._Bad(f"unexpected FSA_ERROR_RESPONSE type: {_type(error)}")
        elif error == "plain":
            self._error_response = \
                lambda m, c, h, _m: Response(m, c, h, content_type="text/plain")
        elif error == "json":
            self._error_response = \
                lambda m, c, h, _m: Response(json.dumps(m), c, h, content_type="application/json")
        elif error.startswith("json:"):
            key = error.split(":", 1)[1]
            self._error_response = \
                lambda m, c, h, _m: Response(json.dumps({key: m}), c, h, content_type="application/json")
        else:
            raise self._Bad(f"unexpected FSA_ERROR_RESPONSE value: {error}")
        # CORS handling
        self._cors = conf.get("FSA_CORS", False)
        self._cors_opts.update(conf.get("FSA_CORS_OPTS", {}))
        if self._cors:
            try:
                from flask_cors import CORS  # type: ignore
            except ModuleNotFoundError:  # pragma: no cover
                log.error("missing module: install FlaskSimpleAuth[cors]")
                raise
            CORS(fsa._app, **self._cors_opts)
        # url
        self._401_redirect = conf.get("FSA_401_REDIRECT", None)
        self._url_name = conf.get("FSA_URL_NAME", "URL" if self._401_redirect else None)
        # hooks stuff
        self._after_requests.extend(conf.get("FSA_AFTER_REQUEST", []))
        self._headers.update(conf.get("FSA_ADD_HEADERS", {}))
        # register fsa hooks to flask, executed in reverse order
        if fsa._mode >= _Mode.DEBUG4:
            app.after_request(self._show_response)
        if fsa._mode >= _Mode.DEV:
            app.after_request(self._add_fsa_headers)
        # always, because more may be register after initialization
        app.after_request(self._run_after_requests)
        if self._headers:
            app.after_request(self._add_headers)
        assert fsa._am  # mypy…
        if fsa._am:  # FIXME always, because of auth=…
            app.after_request(fsa._am._set_www_authenticate)
        if fsa._am and fsa._am._tm and fsa._am._tm._carrier == "cookie":
            app.after_request(fsa._am._tm._set_auth_cookie)
        if self._401_redirect:
            app.after_request(self._possible_redirect)
        app.after_request(self._auth_post_check)
        # done!
        self._initialized = True

    def _run_after_requests(self, res: Response) -> Response:
        """Run internal after request hooks."""
        for fun in self._after_requests:
            res = fun(res)
        return res

    def _auth_post_check(self, res: Response) -> Response:
        """After request hook to detect missing authorizations."""
        fsa = self._fsa
        if not hasattr(fsa._local, "routed"):  # pragma: no cover
            # may be triggered by an early return from a before_request hook?
            log.warn(f"external response on {request.method} {request.path}")
            return res
        if fsa._local.routed and res.status_code < 400 and fsa._local.need_authorization:  # pragma: no cover
            # this case is really detected when building the app
            method, path = request.method, request.path
            if not (self._cors and method == "OPTIONS"):
                log.error(f"missing authorization on {method} {path}")
                return self._Res("missing authorization check", fsa._server_error)
        return res

    def _possible_redirect(self, res: Response) -> Response:
        """After request hook to turn a 401 into a redirect."""
        if res.status_code == 401 and self._401_redirect:
            location = self._401_redirect
            # allow to come back later in some cases
            if self._url_name and request.method == "GET":
                from urllib.parse import urlencode

                sep = "&" if "?" in self._url_name else "?"
                location += sep + urlencode({self._url_name: request.url})
            return redirect(location, 307)  # type: ignore
        return res

    def _add_headers(self, res: Response) -> Response:
        """Add arbitrary headers to response."""
        for name, value in self._headers.items():
            val = value(res, name) if callable(value) else value
            if val:
                res.headers[name] = val
        return res

    def _add_fsa_headers(self, res: Response) -> Response:
        """Add convenient FSA-related headers."""
        fsa = self._fsa
        res.headers["FSA-Request"] = f"{request.method} {request.path}"
        # NOTE resilience seems necessary in some cases?
        if hasattr(fsa._local, "source"):
            res.headers["FSA-User"] = f"{fsa.current_user()} ({fsa._local.source})"
        if hasattr(fsa._local, "start"):
            delay = dt.datetime.timestamp(dt.datetime.now()) - fsa._local.start
            res.headers["FSA-Delay"] = f"{delay:.6f}"
        return res

    def _show_response(self, res: Response) -> Response:
        """Show response in logs when in debug mode."""
        if self._fsa._mode >= _Mode.DEBUG4:
            # FIXME there is no decent response prettyprinter
            r = res
            rpp = (f"{r}\n\tHTTP/? {r.status}\n\t" +
                   "\n\t".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n")
            log.debug(rpp)
        return res


# actual extension
class FlaskSimpleAuth:
    """Flask extension for authentication, authorization and parameters.

    Although this class can be used as a Flask extension, the prefered approach
    is to use the Flask class provided in this module, which overrides directly
    Flask internals so as to provide our declarative security layer, so that
    you may not shortcut the extension.
    """

    def __init__(self, app: flask.Flask, debug: bool = False, **config):
        """Constructor parameters: flask application to extend and FSA directives."""
        # A basic minimal non functional initialization.
        # Actual initializations are deferred to init_app called later,
        # so as to allow updating the configuration.
        self._mode = _Mode.DEBUG2 if debug else _Mode.UNDEF
        self._app = app
        self._app.config.update(**config)
        # managers
        self._am = _AuthenticationManager(self)
        self._zm = _AuthorizationManager(self)
        self._pm = _ParameterManager(self)
        self._qm = _RequestManager(self)
        self._rm = _ResponseManager(self)
        self._cm = _CacheManager(self)
        # path checking
        self._path_check: Hooks.PathCheckFun|None = None
        # override default json provider
        self._app.json = _JSONProvider(app)
        # fsa-generated errors
        self._server_error: int = Directives.FSA_SERVER_ERROR
        self._not_found_error: int = Directives.FSA_NOT_FOUND_ERROR
        self._keep_user_errors: bool = Directives.FSA_KEEP_USER_ERRORS
        # misc
        self._local: Any = None              # per-request data
        # COLDLY override Flask route decorator…
        self._app.route = self.route  # type: ignore
        # actual main initialization is deferred to `_initialize`
        self._initialized = False

    #
    # DEFERRED INITIALIZATIONS
    #
    def _initialize(self) -> None:
        """Run late initialization.

        The initialization is performed through `FSA_*` configuration directives.
        """
        if self._initialized:
            return

        log.info("FSA initialization…")
        conf = self._app.config

        # running mode
        if self._mode and self._mode >= _Mode.DEBUG and "FSA_MODE" in conf:
            log.warning("ignoring FSA_MODE because already in debug mode")
        else:
            mode = conf.get("FSA_MODE", Directives.FSA_MODE)
            if mode in _MODES:
                self._mode = _MODES[mode]
            else:
                raise self._Bad(f"unexpected FSA_MODE value: {mode}")
        if self._mode >= _Mode.DEBUG:
            log.warning("FlaskSimpleAuth running in debug mode")
            log.setLevel(logging.DEBUG)
            if "FSA_LOGGING_LEVEL" in conf:
                log.warning("ignoring FSA_LOGGING_LEVEL because already in debug mode")
        elif "FSA_LOGGING_LEVEL" in conf:
            log.setLevel(conf["FSA_LOGGING_LEVEL"])

        # check directives for typos
        all_directives = set(Directives.__dict__.keys())
        for name in conf:
            if name.startswith("FSA_") and name not in all_directives:
                raise self._Bad(f"unexpected FSA_* directive: {name}")

        # set self._local internal holder
        local = conf.get("FSA_LOCAL", "thread")
        if local == "process":
            class Local(object):  # type: ignore
                pass
        elif local == "thread":
            from threading import local as Local  # type: ignore
        elif local == "werkzeug":
            from werkzeug.local import Local  # type: ignore
        elif local == "gevent":  # pragma: no cover
            from gevent.local import local as Local  # type: ignore
        elif local == "eventlet":  # pragma: no cover
            from eventlet.corolocal import local as Local  # type: ignore
        else:
            raise self._Bad(f"unexpected FSA_LOCAL value: {local}")
        self._local = Local()

        # status code for some errors errors
        self._server_error = conf.get("FSA_SERVER_ERROR", Directives.FSA_SERVER_ERROR)
        self._not_found_error = conf.get("FSA_NOT_FOUND_ERROR", Directives.FSA_NOT_FOUND_ERROR)
        # error response generation
        if conf.get("FSA_HANDLE_ALL_ERRORS", True):
            # take responsability for handling errors
            self._app.register_error_handler(exceptions.HTTPException, lambda e: self._Res(e.description, e.code))
        # override FSA internal error handling user errors
        self._keep_user_errors = conf.get("FSA_KEEP_USER_ERRORS", Directives.FSA_KEEP_USER_ERRORS)

        # JSON serialization helpers
        if conf.get("FSA_JSON_ALLSTR", Directives.FSA_JSON_ALLSTR):
            self._app.json.set_allstr()
        for t, h in conf.get("FSA_JSON_CONVERTER", Directives.FSA_JSON_CONVERTER).items():
            self.add_json_converter(t, h)

        #
        # initialize managers
        #
        self._am._initialize()
        self._zm._initialize()
        self._pm._initialize()
        self._qm._initialize()
        self._rm._initialize()
        self._cm._initialize()  # keep last

        # Path Check
        self._path_check = conf.get("FSA_PATH_CHECK", None)

        #
        # blueprint hacks
        #
        self.blueprints = self._app.blueprints
        self.debug = False
        if hasattr(self._app, "_check_setup_finished"):
            # Flask 2.2, 2.3, 3.0, 3.1…
            self._check_setup_finished = self._app._check_setup_finished
            self.before_request_funcs = self._app.before_request_funcs
            self.after_request_funcs = self._app.after_request_funcs
            self.teardown_request_funcs = self._app.teardown_request_funcs
            self.url_default_functions = self._app.url_default_functions
            self.url_value_preprocessors = self._app.url_value_preprocessors
            self.template_context_processors = self._app.template_context_processors
        else:  # pragma: no cover
            raise self._Bad("unexpected Flask version while dealing with blueprints?")

        # done!
        self._initialized = True

    #
    # COMMON UTILS
    #
    def _Res(self, msg: str, code: int, headers: dict[str, str]|None = None, content_type: str|None = None) -> Response:
        """Generate a error actual Response with a message."""
        if self._mode >= _Mode.DEBUG:
            log.debug(f"error response: {code} {msg}")
        return self._rm._error_response(msg, code, headers, content_type)

    def _Exc(self, exc: BaseException|None) -> BaseException|None:
        """Handle an internal error."""
        # trace once with subtle tracking
        if exc and not hasattr(exc, "_fsa_traced"):
            log.error(exc, exc_info=True)
            setattr(exc, "_fsa_traced", True)
        return exc if self._keep_user_errors else None

    def _Err(self, msg: str, code: int, exc: Exception|None = None) -> BaseException:
        """Build and trace an ErrorResponse exception with a message."""
        if self._mode >= _Mode.DEBUG3:
            log.debug(f"error: {code} {msg}")
        return self._Exc(exc) or ErrorResponse(msg, code)

    def _Bad(self, msg: str, misc: str|None = None) -> ConfigError:
        """Build and trace an exception on a bad configuration."""
        if misc:
            msg += "\n" + misc
        log.critical(msg)
        return ConfigError(msg)

    def _store(self, store: dict[Any, Any], what: str, key: Any,
               wrapper: Callable|None, val: Callable|None = None):
        """Add a function associated to something in a dict.

        This can be used as a decorator if the last parameter is None.
        """
        if self._mode >= _Mode.DEBUG2:
            log.debug(f"registering {what} for {key} ({val})")
        if val:  # direct
            if key in store:
                log.warning(f"overriding {what} function for {key}")
            store[key] = wrapper(val) if wrapper else val
        else:  # decorator use

            def decorate(fun: Callable):
                assert fun is not None
                self._store(store, what, key, wrapper, fun)
                return fun

            return decorate

    def _set_hooks(self, directive: str, set_hook: Callable[[Any, Callable], Any]) -> None:
        """Convenient method to add new hooks."""
        conf = self._app.config
        if directive in conf:
            hooks = conf[directive]
            if not isinstance(hooks, dict):
                raise self._Bad(f"{directive} must be a dict")
            for key, hook in hooks.items():
                if not callable(hook):  # pragma: no cover
                    raise self._Bad(f"{directive} {key} value must be callable")
                set_hook(key, hook)

    #
    # REGISTER HOOKS
    #
    def get_user_pass(self, gup: Hooks.GetUserPassFun) -> Hooks.GetUserPassFun:
        """Set `get_user_pass` helper, can be used as a decorator."""
        self._initialize()
        return self._am._pm.get_user_pass(gup)

    def user_in_group(self, uig: Hooks.UserInGroupFun) -> Hooks.UserInGroupFun:
        """Set `user_in_group` helper, can be used as a decorator."""
        self._initialize()
        if self._zm._user_in_group:
            log.warning("overriding already defined user_in_group hook")
        self._zm._user_in_group = uig
        return uig

    def password_quality(self, pqc: Hooks.PasswordQualityFun) -> Hooks.PasswordQualityFun:
        """Set `password_quality` hook."""
        self._initialize()
        if self._am._pm._pass_quality:
            log.warning("overriding already defined password_quality hook")
        self._am._pm._pass_quality = pqc
        return pqc

    def password_check(self, pwc: Hooks.PasswordCheckFun) -> Hooks.PasswordCheckFun:
        """Set `password_check` hook."""
        self._initialize()
        if self._am._pm._pass_check:
            log.warning("overriding already defined password_check hook")
        self._am._pm._pass_check = pwc
        return pwc

    def path_check(self, pc: Hooks.PathCheckFun) -> Hooks.PathCheckFun:
        """Set `path_check` hook."""
        self._initialize()
        if self._path_check:
            log.warning("overriding already defined path_check hook")
        self._path_check = pc
        return pc

    def error_response(self, erh: Hooks.ErrorResponseFun) -> Hooks.ErrorResponseFun:
        """Set `error_response` hook."""
        self._initialize()
        log.warning("overriding error_response hook")
        self._rm._error_response = erh
        return erh

    def cast(self, t, cast: Hooks.CastFun|None = None):
        """Add a cast function associated to a type.

        This function is called for type conversion on parameters.
        """
        self._initialize()
        return self._pm.cast(t, cast)

    def special_parameter(self, t, sp: Hooks.SpecialParameterFun|None = None):
        """Add a special parameter type.

        These special parameters are managed by calling the hook with a
        the parameter name as an argument.
        """
        self._initialize()
        return self._pm.special_parameter(t, sp)

    def group_check(self, group: str|int, checker: Hooks.GroupCheckFun|None = None):
        """Add a group helper for a given group."""
        self._initialize()
        return self._zm.group_check(group, checker)

    def object_perms(self, domain: str, checker: Hooks.ObjectPermsFun|None = None):
        """Add an object permission helper for a given domain."""
        self._initialize()
        return self._zm.object_perms(domain, checker)

    def authentication(self, auth: str, hook: Hooks.AuthenticationFun|None = None):
        """Add new authentication hook."""
        return self._am.authentication(auth, hook)

    def add_group(self, *groups) -> None:
        """Add some groups."""
        self._initialize()
        for grp in groups:
            if not isinstance(grp, (str, int)):
                raise self._Bad(f"invalid group type: {_type(grp)}")
            self._zm._groups.add(grp)

    def add_scope(self, *scopes) -> None:
        """Add some scopes."""
        self._initialize()
        for scope in scopes:
            if not isinstance(scope, str):
                raise self._Bad(f"invalid scope type: {_type(scope)}")
            self._zm._scopes.add(scope)

    def add_headers(self, **kwargs) -> None:
        """Add some headers."""
        self._initialize()
        for k, v in kwargs.items():
            if not isinstance(k, str):  # pragma: no cover
                raise self._Bad(f"header name must be a string: {_type(k)}")
            if not (isinstance(v, str) or callable(v)):
                raise self._Bad(f"header value must be a string or a callable: {_type(v)}")
            self._store(self._rm._headers, "header", k, None, v)  # type: ignore

    def before_exec(self, hook: Hooks.BeforeExecFun) -> None:
        """Register an after auth/just before exec hook."""
        self._initialize()
        self._qm._before_exec_hooks.append(hook)

    def add_json_converter(self, t: Any, h: Hooks.JSONConversionFun) -> None:
        """Register a JSON serialization conversion hook for a type."""
        self._app.json.add_converter(t, h)

    #
    # PASSWORD CHECKS
    #
    def check_user_password(self, user, pwd) -> bool:
        """Verify whether a user password is correct according to internals.

        This allows to check the prior password for a change password route.
        """
        self._initialize()
        try:
            return user == self._am._pm.check_user_password(user, pwd)
        except ErrorResponse:  # silently ignore auth failures.
            return False

    def check_password(self, pwd, ref):
        """Verify whether a password is correct compared to a reference (eg salted hash).

        This allows to check the prior password for a change password route.
        """
        self._initialize()
        return self._am._pm.check_password(pwd, ref)

    def hash_password(self, pwd, check=True):
        """Hash password according to the current password scheme.

        Setting check to *False* disables automatic password quality checks.
        """
        self._initialize()
        return self._am._pm.hash_password(pwd, check)

    #
    # TOKEN
    #
    def create_token(self, *args, **kwargs) -> str:
        self._initialize()
        return self._am._tm.create_token(*args, **kwargs)

    #
    # AUTHENTICATE WITH ANY MEAN
    #
    def get_user(self, required=True) -> str|None:
        """Authenticate user or throw exception.

        Tries all possible authentication schemes allowed on the route,
        and returns the authenticated user or throws an exception.
        The result is memoized.
        """
        return self._am.get_user(required)

    def current_user(self) -> str|None:
        """Return current authenticated user, if any.

        Returns `None` if no user has been authenticated.
        """
        # FIXME the hasattr test should not be necessary?
        return self._local.user if hasattr(self._local, "user") else None

    def user_scope(self, scope) -> bool:
        """Is `scope` in the `current user` scopes."""
        return self._local.scopes and scope in self._local.scopes

    #
    # UNCACHE
    #
    def clear_caches(self) -> None:
        """Clear internal shared cache.

        Probably a bad idea because:

        - of the performance impact
        - for a local cache in a multi-process setup, other processes are out

        The best option is to wait for cache entries to expire with a TTL,
        or to use one of the specific ``_uncache`` methods.
        """
        if not self._cm._cache:  # pragma: no cover
            log.warning("cache is not activated, cannot be cleared, skipping…")
            return
        self._cm._cache.clear()

    def password_uncache(self, user: str) -> bool:
        """Remove user password entry from cache."""
        return self._am._pm.password_uncache(user)

    def token_uncache(self, token: str, realm: str) -> bool:
        """Remove token entry from cache."""
        return self._am._tm.token_uncache(token, realm)

    def user_token_uncache(self, user: str, realm: str) -> bool:
        """Remove token associated to user/realm from cache."""
        return self._am._tm.user_token_uncache(user, realm)

    def group_uncache(self, user: str, group: str|int) -> bool:
        """Remove group membership entry from cache."""
        return self._zm.group_uncache(user, group)

    def object_perms_uncache(self, domain: str, user: str, oid, mode: str|None) -> bool:
        """Remove permission entry from cache."""
        return self._zm.object_perms_uncache(domain, user, oid, mode)

    def auth_uncache(self, user: str) -> int:
        """Attempt at removing all user authn and authz cache entries."""
        dones = 0
        if self.password_uncache(user):
            dones += 1
        if self.user_token_uncache(user, self._app.name):
            dones += 1
        if self._zm._groups:
            for grp in self._zm._groups:
                if self.group_uncache(user, grp):
                    dones += 1
        # cannot really do object perms…
        return dones

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
    def _safe_call(self, path, level, fun, *args, **kwargs) -> Response:
        """Call a route function ensuring a response whatever."""
        try:  # the actual call
            return fun(*args, **kwargs)
        except ErrorResponse as e:  # something went wrong
            return self._Res(e.message, e.status, e.headers, e.content_type)
        except Exception as e:  # something went *really* wrong
            log.error(f"internal error on {request.method} {request.path}: {e}")
            if self._Exc(e):
                raise
            return self._Res(f"internal error caught at {level} on {path}", self._server_error)

    # FIXME endpoint?
    def add_url_rule(self, rule, endpoint=None, view_func=None, authz=None, authn=None, realm=None, **options):
        """Route decorator helper method.

        This is the main function which takes a route function and adds all
        the necessary wrappers to manage authentication, authorization and
        parameters, before registering the endpoint to Flask WSGI dispatcher.

        - ``authz``: authorization constraints.
        - ``authn``: authentication constraints.
        - ``realm``: realm for this route, supercedes global settings.

        NOTE ``authorize`` and ``auth`` are deprecated versions of ``authz`` and ``authn``.
        """

        # handle authz/authorize and authn/auth
        deprecation = self._app.config.get("FSA_ALLOW_DEPRECATION", Directives.FSA_ALLOW_DEPRECATION)

        if "authorize" in options:
            if deprecation:
                log.warning(f"deprecated use of 'authorize' on {rule}")
            else:
                raise self._Bad(f"cannot use deprecated 'authorize', use 'authz' on {rule}")
            if authz is not None:
                raise self._Bad(f"cannot use both 'authz' and 'authorize' on {rule}")
            authz = options["authorize"]
            del options["authorize"]

        if "auth" in options:
            if deprecation:
                log.warning(f"deprecated use of 'auth' on route {rule}")
            else:
                raise self._Bad(f"cannot use deprecated 'auth', use 'authn' on {rule}")
            if authn is not None:
                raise self._Bad(f"cannot use both 'authn' and 'auth' on {rule}")
            authn = options["auth"]
            del options["auth"]

        # lazy initialization
        self._initialize()

        # check that path matches project rules
        if self._path_check:
            method = options.get("methods", ["GET"])[0]
            bad_path = self._path_check(method, rule)
            if bad_path:
                raise self._Bad(f"bad path on {method} {path}: {bad_path}")

        # ensure that authz is a list
        if authz is None:
            authz = ["CLOSE"]
        elif type(authz) in (int, str, tuple):
            authz = [authz]

        # ensure that authn is registered as used
        if isinstance(authn, str):
            authn = [authn]
        if authn is None:
            pass
        elif isinstance(authn, list):
            authn = self._am._password_auth(authn)
            # this also checks that list items are str
            for a in authn:
                if a not in self._am._auth:
                    raise self._Bad(f"auth is not enabled: {a}")
        else:
            raise self._Bad(f"unexpected authn type, should be str or list: {_type(authn)}")

        # FIXME should be in a non existing ready-to-run hook
        if self._cm and not self._cm._cached:
            self._cm._set_caches()

        # normalize None to CLOSE
        authz = list(map(lambda a: "CLOSE" if a is None else a, authz))

        # ensure non emptyness
        if len(authz) == 0:
            authz = ["CLOSE"]

        # special handling of "oauth" rule-specific authentication
        if authn and isinstance(authn, list) and "oauth" in authn:
            if len(authn) != 1:
                raise self._Bad(f"oauth authentication cannot be mixed with other schemes on {rule}")
            assert authn == ["oauth"]
            if not self._am._tm._issuer:
                raise self._Bad(f"oauth token authorizations require FSA_TOKEN_ISSUER on {rule}")

        # pseudo-group deprecation
        deprecated_groups = list(filter(lambda a: a in _DEPRECATED_GROUPS, authz))
        if deprecated_groups:
            if deprecation:
                log.warning(f"use of deprecated pseudo-group {deprecated_groups} on {rule}")
            else:
                raise self._Bad(f"cannot use deprecated pseudo-group {deprecated_groups} on {rule}")

        # separate predefs, groups and perms
        predefs = list(filter(lambda a: a in _PREDEFS, authz))
        groups = list(filter(lambda a: type(a) in (int, str) and a not in _PREDEFS, authz))
        perms = list(filter(lambda a: isinstance(a, tuple), authz))

        # authz are either in groups or in perms
        if len(authz) != len(groups) + len(perms) + len(predefs):
            bads = list(filter(lambda a: a not in groups and a not in perms and a not in _PREDEFS, authz))
            raise self._Bad(f"unexpected authorizations on {rule}: {bads}")

        if _is_close(predefs):
            # overwrite all perms, a route is closed just by appending "CLOSE"
            # NOTE the handling is performed later to allow for some checks
            predef, groups, perms = "CLOSE", [], []
        elif _is_open(predefs):
            predef = "OPEN"
            if _is_auth(predefs):
                raise self._Bad(f"cannot mix OPEN/AUTH predefined groups on {path}")
            if groups:
                raise self._Bad(f"cannot mix OPEN and other groups on {path}")
            if perms:
                raise self._Bad(f"cannot mix OPEN with per-object permissions on {path}")
            # OPEN authz requires none authn, otherwise it means AUTH
            # NOTE we know that self._am._auth is not empty
            if "none" not in self._am._auth:
                predef = "AUTH"
                log.warning(f"OPEN authorization but none authentication is not allowed on {path}")
            if authn:  # explicit authentication list
                if "none" not in authn:
                    predef = "AUTH"
                    log.warning(f"OPEN authorization but none authentication is not set on {path}")
            elif self._am._default_auth and "none" not in self._am._default_auth:  # implicit
                predef = "AUTH"
                log.warning(f"OPEN authorization but none authentication is not set in defaults on {path}")
        elif _is_auth(predefs):
            predef = "AUTH"
            # change to CLOSE if no authentication is enabled
            if (self._am._auth == ["none"] or
                authn and authn == ["none"] or
                self._am._default_auth and self._am._default_auth == ["none"]):
                log.warning(f"AUTH authorization but only none authentication on {path}")
                predef = "CLOSE"
        else:  # trigger auth anyway
            assert groups or perms
            predef = "AUTH"

        del predefs
        assert predef in {"OPEN", "AUTH", "CLOSE"}

        # add the expected type to path sections, if available
        # flask converters: string (default), int, float, path, uuid
        # NOTE it can be extended (`url_map`), but we are managing through annotations
        sig = inspect.signature(view_func)  # type: ignore

        # path parameters
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
                           conv == "uuid" and atype != uuid.UUID or \
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
                    if t in (int, float, uuid.UUID, path):
                        splits[i] = f"{t.__name__.lower()}:{spec}>{remainder}"  # type: ignore
                    else:
                        splits[i] = f"string:{spec}>{remainder}"
                # else spec includes a type that we keep…
        newpath = "<".join(splits)

        # special shortcut, override the user function entirely
        if predef == "CLOSE":

            @functools.wraps(view_func)  # type: ignore
            def r403():
                self._local.routed = True
                return "currently closed route", 403

            return flask.Flask.add_url_rule(self._app, newpath, endpoint=endpoint, view_func=r403, **options)

        fun = view_func
        assert fun is not None

        # else only add needed filters on top of "fun", in reverse order
        need_authenticate = predef == "AUTH"
        need_parameters = len(fun.__code__.co_varnames) > 0

        # build handling layers in reverse order:
        # routed / authenticate / (oauth|group|no|) / params / perms / hooks / fun
        if self._qm._before_exec_hooks:
            fun = self._qm._execute_hooks(newpath, "before exec hook", fun, self._qm._before_exec_hooks)

        if perms:
            if not need_parameters:
                raise self._Bad("permissions require some parameters")
            assert need_authenticate and need_parameters
            first = fun.__code__.co_varnames[0]  # type: ignore
            fun = self._zm._perm_authz(newpath, first, *perms)(fun)

        if need_parameters:
            fun = self._pm._parameters(newpath, predef == "OPEN")(fun)
        else:
            fun = self._pm._noparams(newpath)(fun)

        if groups:
            assert need_authenticate
            if isinstance(authn, list) and "oauth" in authn:
                fun = self._zm._oauth_authz(newpath, *groups)(fun)
            else:
                fun = self._zm._group_authz(newpath, *groups)(fun)
        elif predef == "OPEN":
            assert not groups and not perms
            fun = self._zm._no_authz(newpath, *groups)(fun)
        elif predef == "AUTH":
            assert need_authenticate
            if not perms and not groups:
                fun = self._zm._no_authz(newpath, *groups)(fun)
        else:  # pragma: no cover # no authorization at this level
            assert perms

        if need_authenticate:
            assert perms or groups or predef == "AUTH"
            fun = self._am._authenticate(newpath, auth=authn, realm=realm)(fun)  # type: ignore
        else:  # "OPEN" case deserves a warning
            log.warning(f"no authenticate on {','.join(options.get('methods', []))} {newpath}")

        assert fun != view_func, "some wrapping added"

        # last wrapper to signal a "routed" function
        @functools.wraps(fun)
        def entry(*args, **kwargs):
            self._local.routed = True
            return fun(*args, **kwargs)

        return flask.Flask.add_url_rule(self._app, newpath, endpoint=endpoint, view_func=entry, **options)

    def route(self, rule, **options):
        """Extended `route` decorator provided by FlaskSimpleAuth.

        This decorator is also available on the Flask wrapper, please use it from there.

        Parameters:

        - ``rule``: the path, possibly including path parameters.
        - ``authz``: mandatory permissions required, eg groups or object perms.
        - ``authn``: authentication scheme(s) allowed on this route.
        - ``realm``: authentication realm on this particular route.
        """
        if "authz" not in options and "authorize" not in options:
            log.warning(f'missing authz on route "{rule}" makes it 403 Forbidden')

        def decorate(fun: Callable):
            return self.add_url_rule(rule, view_func=fun, **options)

        return decorate

    # support Flask 2.0 per-method decorator shortcuts
    # NOTE app.get("/", methods=["POST"], …) would do a POST.
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
        self._initialize()

        # although self is not a Flask instance, it should be good enough
        flask.Flask.register_blueprint(self, blueprint, **options)  # type: ignore
