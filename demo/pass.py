#! /usr/bin/env python3
#
# generate password authenticated users
#

import sys
from passlib.context import CryptContext  # types: ignore

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} bcrypt|plaintext|… [login1:pass1] …")
    sys.exit(0)

pm = CryptContext(schemes=[sys.argv[1]],
                  bcrypt__default_rounds=4,    # about 2 ms
                  bcrypt__default_ident='2y')  # apache compatible
sep = " "
print("INSERT INTO Auth(login, email, upass, admin) VALUES")
for login, mdp in [lp.split(":", 1) for lp in sys.argv[2:]]:
    print(f"{sep} ('{login}', '{login}@school.org', '{pm.hash(mdp)}', TRUE)")
    sep = ","
print(";")
