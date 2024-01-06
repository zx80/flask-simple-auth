% Sample FlaskSimpleAuth Configuration

All configuration directives are documented
[here](https://zx80.github.io/flask-simple-auth/autoapi/FlaskSimpleAuth/index.html#FlaskSimpleAuth.Directives)
Here is a sample configuration file for FlaskSimpleAuth application:

```python
#
# General
#

# by increasing verbosity: prod (default), dev (recommanded), debug1 to debug4
FSA_MODE = "dev"

# logging verbosity
# FSA_LOGGING_LEVEL = logging.INFO

# require TLS
# FSA_SECURE = True 

# error handling:
# FSA_SERVER_ERROR = 500
# FSA_NOT_FOUND_ERROR = 404
# FSA_HANDLE_ALL_ERRORS = True
# FSA_KEEP_USER_ERRORS = False
# FSA_401_REDIRECT = None  # URL for web authn redirection
# FSA_URL_NAME = "URL"  # parameter for url return target
# FSA_CORS = False  # CORS handling
# FSA_CORS_OPTS = {}  # initialization parameters

# plain, json, json:property-name
FSA_ERROR_RESPONSE = "json:error"

# FSA_DEFAULT_CONTENT_TYPE = None

# variable isolation: process, thread, werkzeug, gevent, eventlet
# FSA_LOCAL = "thread"

#
# Authentication
#

# authn: none, httpd, basic, param, password, token, fake, oauth…
# FSA_AUTH = "none"
# FSA_REALM = <application-name>

# Authn Hooks
# FSA_GET_USER_PASS = None
# advanced hooks to add new authentication methods…
# FSA_AUTHENTICATION = {}

# parameter name for fake authentication
#
# FSA_FAKE_LOGIN = "LOGIN"

# parameter names for param authentication
#
# FSA_PARAM_USER = "USER"
# FSA_PARAM_PASS = "PASS"

# token authentication
#
# token type is "fsa" or "jwt"
# FSA_TOKEN_TYPE = "fsa"
# token signature, value depends on token type
# FSA_TOKEN_ALGO = "blake2s"
# where to find the token: bearer, cookie, header, param
# FSA_TOKEN_CARRIER = "bearer"
# additional parameter for token carrier
# FSA_TOKEN_NAME = "Bearer"
# FSA_TOKEN_DELAY = 60.0  # minutes of validity
# FSA_TOKEN_GRACE = 0.0
# FSA_TOKEN_LENGTH = 16  # signature length kept for hashes
# FSA_TOKEN_SECRET = <256-bits-random>
# FSA_TOKEN_SIGN = None  # private key for JWT pubkey schemes
# FSA_TOKEN_RENEWAL = 0.0
# FSA_TOKEN_ISSUER = None

# password authentication
#
# FSA_PASSWORD_SCHEME = "bcrypt"
# FSA_PASSWORD_OPTS = {}  # passlib initialization

# password quality settings
#
# FSA_PASSWORD_LENGTH = 0  # minimal length
# FSA_PASSWORD_RE = []  # re to match
# FSA_PASSWORD_QUALITY = None  # external hook
# FSA_PASSWORD_CHECK = None  # alternate password checking hook

# HTTPAuth authentication
# FSA_HTTP_AUTH_OPTS = {}

#
# Authorizations
#

# Authz Hooks
# FSA_USER_IN_GROUP = None
# FSA_GROUP_CHECK = {}
# FSA_OBJECT_PERMS = {}
# FSA_AUTHZ_GROUPS = []  # declare groups
# FSA_AUTHZ_SCOPES = []  # declare scopes (for oauth)

# 
# Parameters
#

# parameter hooks
# FSA_CAST = {}
# FSA_SPECIAL_PARAMETERS = {}
# FSA_REJECT_UNEXPECTED_PARAMS = True

#
# Cache
#

# from cachetools, also redis and memcached
# FSA_CACHE = "ttl"
# FSA_CACHE_OPTS = {}  # initialization options
# FSA_CACHE_SIZE = 262144
# FSA_CACHE_PREFIX = None
# 

#
# Other Hooks and directives
#

# FSA_BEFORE_REQUEST = []
# FSA_BEFORE_EXEC = []
# FSA_AFTER_REQUEST = []
# FSA_ADD_HEADERS = {}
```
