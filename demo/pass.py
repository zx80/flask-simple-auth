#! /usr/bin/env python3
#
# generate password authenticated users
#

import sys
import bcrypt

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} [login1:pass1:secret1] …")
    sys.exit(0)

def hashpw(password: str):
    # rounds=4: about 2 ms
    return bcrypt.hashpw(password.encode("UTF8"), bcrypt.gensalt(rounds=4, prefix=b"2b")).decode("ascii")

sep = " "
print("INSERT INTO Auth(login, email, upass, admin, secret) VALUES")
for login, mdp, sec in [lp.split(":", 2) for lp in sys.argv[1:]]:
    print(f"{sep} ('{login}', '{login}@school.org', '{hashpw(mdp)}', TRUE, '{sec}')")
    sep = ","
print(";")
