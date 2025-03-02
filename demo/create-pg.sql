CREATE TABLE Stuff(
  sid SERIAL8 PRIMARY KEY,
  sname TEXT NOT NULL
);

CREATE TABLE Auth(
  aid SERIAL8 PRIMARY KEY,
  login TEXT UNIQUE NOT NULL CHECK (login NOT LIKE '%@%'),
  email TEXT UNIQUE NOT NULL CHECK (email LIKE '%@%'),
  admin BOOLEAN NOT NULL DEFAULT FALSE,
  -- Authentication: hashed user password
  upass TEXT NOT NULL,
  -- Authentication: MFA 80-160 bits base32 OTP secret
  -- NOTE this should be kept somewhere else
  secret TEXT NOT NULL CHECK(secret ~ '^[A-Z2-7]{16,32}$'),
  -- NOTE beware that OTP requires mitigating replay and enumeration attacks
  last_otp TEXT,
  -- Authentication: MFA temporary code and its expiration
  -- NOTE this should probably be in some other table
  code TEXT,
  codets TIMESTAMPTZ,
  CHECK (code IS NULL AND codets IS NULL OR
         code IS NOT NULL AND codets IS NOT NULL)
);
