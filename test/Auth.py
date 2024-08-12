#
# authentication data for testing purpose, without reliance on the app.
#

from typing import Dict
import bcrypt

#
# GROUPS
#
ADMIN, WRITE, READ = 0, 1, 2
GROUPS = {
    ADMIN: {"dad"},
    WRITE: {"dad", "calvin"},
    READ: {"calvin", "hobbes"},
}

def user_in_group(user, group):
    return user in GROUPS.get(group, [])

def hashpw(password: str):
    return bcrypt.hashpw(password.encode("UTF8"), bcrypt.gensalt(rounds=4, prefix=b"2b")).decode("ascii")

#
# PASSWORDS
#
UP = { "calvin": "hobbes", "hobbes": "susie", "dad": "mum" }
UHP = { u: hashpw(p) for u, p in UP.items() }

get_user_pass = UHP.get
