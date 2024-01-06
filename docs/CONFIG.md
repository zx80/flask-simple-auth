# Sample FlaskSimpleAuth Configuration

All configuration directives are documented
[there](https://zx80.github.io/flask-simple-auth/autoapi/FlaskSimpleAuth/index.html#FlaskSimpleAuth.Directives).

Here is a sample configuration file for FlaskSimpleAuth application:

```python
#
# GENERAL
#

FSA_MODE = "dev"                    # by increasing verbosity: prod (default), dev (recommended), debug1-4
# FSA_LOGGING_LEVEL = logging.INFO  # logging verbosity, set to logging.DEBUG for debug
# FSA_SECURE = True                 # require TLS
# FSA_CORS = False                  # CORS handling
# FSA_CORS_OPTS = {}                # initialization parameters
# FSA_DEFAULT_CONTENT_TYPE = None   # set content type if unknown
# FSA_LOCAL = "thread"              # isolation: process, thread, werkzeug, gevent, eventlet

#
# ERROR HANDLING
#
# FSA_SERVER_ERROR = 500
# FSA_NOT_FOUND_ERROR = 404
# FSA_HANDLE_ALL_ERRORS = True
# FSA_KEEP_USER_ERRORS = False
# FSA_401_REDIRECT = None          # URL for web authn redirection
# FSA_URL_NAME = "URL"             # parameter for url return target
FSA_ERROR_RESPONSE = "json:error"  # plain (default), json, json:<property-name>

#
# AUTHENTICATION
#

# FSA_AUTH = "none"         # list: none, httpd, basic, param, password, token, fake, oauth…
# FSA_REALM = <app-name>

# parameter names
#
# FSA_FAKE_LOGIN = "LOGIN"  # parameter name for fake authn
# FSA_PARAM_USER = "USER"   # user parameter name for param authn
# FSA_PARAM_PASS = "PASS"   # password parameter name for param authn

# token authentication
#
# FSA_TOKEN_TYPE = "fsa"        # token type is "fsa" or "jwt"
# FSA_TOKEN_ALGO = "blake2s"    # for signature, value depends on token type
# FSA_TOKEN_CARRIER = "bearer"  # where to find the token: bearer, cookie, header, param
# FSA_TOKEN_NAME = "Bearer"     # additional parameter for token carrier
# FSA_TOKEN_DELAY = 60.0        # minutes of validity
# FSA_TOKEN_GRACE = 0.0         # minutes of grace
# FSA_TOKEN_LENGTH = 16         # signature length kept for hashes
# FSA_TOKEN_SECRET = <256-bits-random>
# FSA_TOKEN_SIGN = None         # private key for JWT pubkey schemes
# FSA_TOKEN_RENEWAL = 0.0
# FSA_TOKEN_ISSUER = None

# password authentication
#
# FSA_GET_USER_PASS = None        # hook, login -> password hash
# FSA_PASSWORD_SCHEME = "bcrypt"  # passlib algorithm
# FSA_PASSWORD_OPTS = {}  i       # passlib initialization

# password quality settings
#
FSA_PASSWORD_LENGTH = 8           # minimal length, default is 0
# FSA_PASSWORD_RE = []            # re to match
# FSA_PASSWORD_QUALITY = None     # external hook
# FSA_PASSWORD_CHECK = None       # alternate password checking hook

# misc
#
# FSA_HTTP_AUTH_OPTS = {}  # external HTTPAuth authn
# FSA_AUTHENTICATION = {}  # advanced hooks to add new authn methods…

#
# AUTHORIZATIONS
#

# FSA_GROUP_CHECK = {}       # groupe-name -> membership check fun
# FSA_OBJECT_PERMS = {}      # domain -> permission check fun
# FSA_USER_IN_GROUP = None   # generic hook for groups
# FSA_AUTHZ_GROUPS = []      # declare group names
# FSA_AUTHZ_SCOPES = []      # declare scope names (for oauth)

#
# PARAMETERS
#

# FSA_CAST = {}                        # type -> callable[[str], any]
# FSA_SPECIAL_PARAMETERS = {}          # type -> callable
# FSA_REJECT_UNEXPECTED_PARAMS = True  # strict more

#
# CACHE
#

# FSA_CACHE = "ttl"         # none, dict, or from cachetools, or redis, or memcached
# FSA_CACHE_OPTS = {}       # initialization options
# FSA_CACHE_SIZE = 262144   # a few MiB
# FSA_CACHE_PREFIX = None   # if shared cache

#
# MISCELLANEOUS
#

# FSA_BEFORE_REQUEST = []
# FSA_BEFORE_EXEC = []
# FSA_AFTER_REQUEST = []
# FSA_ADD_HEADERS = {}
```
