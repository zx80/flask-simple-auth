#
# authentication data for testing purpose
#

from typing import Dict
from passlib.context import CryptContext  # type: ignore

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

#
# PASSWORDS
#
pm = CryptContext(schemes=["bcrypt"], bcrypt__default_rounds=4, bcrypt__default_ident='2y')
UP = { "calvin": "hobbes", "hobbes": "susie", "dad": "mum" }
UHP = { u: pm.hash(p) for u, p in UP.items() }

get_user_pass = UHP.get
