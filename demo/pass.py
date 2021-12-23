#! /usr/bin/env python3

import sys
from passlib.context import CryptContext

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} bcrypt|plaintext|… [login1:pass1] …")
    sys.exit(0)

scheme = sys.argv[1]

pm = CryptContext(schemes=[scheme],
                  bcrypt__default_rounds=4,    # about 2 ms
                  bcrypt__default_ident='2y')  # apache compatible
sep = " "
print("INSERT INTO Auth(login, upass, admin) VALUES")
for lp in sys.argv[2:]:
    login, mdp = lp.split(":", 1)
    print(f"{sep} ('{login}', '{pm.hash(mdp)}', TRUE)")
    sep = ","
print(";")
