CREATE TABLE Stuff(
  sid INTEGER PRIMARY KEY,
  sname TEXT NOT NULL
);

CREATE TABLE Auth(
  aid INTEGER PRIMARY KEY,
  login TEXT UNIQUE NOT NULL CHECK (login NOT LIKE '%@%'),
  email TEXT UNIQUE NOT NULL CHECK (email LIKE '%@%'),
  admin BOOLEAN NOT NULL DEFAULT FALSE,
  upass TEXT NOT NULL,  -- hashed user password
  -- MFA 80-160 bits base32 OTP secret
  secret TEXT NOT NULL, -- CHECK(secret ~ '^[A-Z2-7]{16,32}$')
  last_otp TEXT,
  -- MFA temporary code and its when it is set
  code TEXT,
  codets TIMESTAMPTZ,
  CHECK (code IS NULL AND codets IS NULL OR
         code IS NOT NULL AND codets IS NOT NULL)
);
