-- NOTE RETURNING requires SQLite 3.35

-- name: now()$
SELECT CURRENT_TIMESTAMP;

-- name: get_stuff_all()
SELECT sid, sname
  FROM Stuff
  ORDER BY 1;

-- name: get_stuff_like(pattern)
SELECT sid, sname
  FROM Stuff
  WHERE sname LIKE :pattern
  ORDER BY 1;

-- name: get_stuff_sid(sid)^
SELECT sname
  FROM Stuff
  WHERE sid = :sid;

-- name: add_stuff(sname)$
INSERT INTO Stuff(sname)
  VALUES (:sname)
  RETURNING sid;

-- name: del_stuff_sid(sid)!
DELETE FROM Stuff
  WHERE sid = :sid;

-- name: upd_stuff_sid(sid, sname)!
UPDATE Stuff
  SET sname = :sname
  WHERE sid = :sid;

-- we accept the email as an alternate login… with implication of caching
-- name: get_user_data(login)^
SELECT login, email, upass, admin
  FROM Auth
  WHERE :login IN (login, email);

-- name: get_user_all()
SELECT login, email, upass, admin
  FROM Auth
  ORDER BY 1;

-- name: add_user(login, email, upass, admin, secret)$
INSERT INTO Auth(login, email, upass, admin, secret)
  VALUES (:login, :email, :upass, :admin, :secret)
  RETURNING aid;

-- name: del_user_login(login)!
DELETE FROM Auth
  WHERE :login IN (login, email);

-- name: upd_user_password(login, upass)!
UPDATE Auth
  SET upass = :upass
  WHERE :login IN (login, email);

-- name: upd_user_email(login, email)!
UPDATE Auth
  SET email = :email
  WHERE :login IN (login, email);

-- name: upd_user_admin(login, admin)!
UPDATE Auth
  SET admin = :admin
  WHERE :login IN (login, email);

-- name: upd_user_secret(login, secret)!
UPDATE Auth
  SET admin = :secret
  WHERE :login IN (login, email);

-- name: get_auth_all()
SELECT aid, login, email, upass, admin, secret
  FROM Auth
  ORDER BY 2;

-- name: get_auth_login(login)^
SELECT aid, login, email, upass, admin, secret
  FROM Auth
  WHERE login = :login;

-- FIXME should be "FOR UPDATE" but I'm not so sure about sqlite3
-- name: get_auth_aid(aid)^
SELECT aid, login, email, upass, admin, secret
  FROM Auth
  WHERE aid = :aid;

-- name: add_auth(a)$
INSERT INTO Auth(login, email, upass, admin, secret)
  VALUES (:a.login, :a.email, :a.upass, :a.admin, :a.secret)
  ON CONFLICT DO NOTHING
  RETURNING aid;

-- name: change_auth(a)!
UPDATE Auth
  SET login = :a.login,
      email = :a.email,
      upass = :a.upass,
      admin = :a.admin,
      secret = :a.secret
  WHERE aid = :a.aid;

-- MFA temporary code stuff
-- name: set_user_code(login, code)!
UPDATE Auth
  SET code = :code,
      codets = NOW()
  WHERE login = :login
    -- avoid resetting user code if too short
    AND (codets IS NULL OR NOW() - codets < INTERVAL '5 seconds');

-- name: reset_user_code(login)!
UPDATE Auth
  SET code = NULL,
      codets = NULL
  WHERE login = :login;

-- name: get_user_code(login)$
SELECT code
  FROM Auth
  WHERE login = :login
    AND codets IS NOT NULL
    AND NOW() - codets < INTERVAL '1 minute';

-- MFA time-based OTP stuff
-- name: get_user_otp_data(login)^
SELECT secret, last_otp
  FROM Auth
  WHERE login = :login;

-- name: set_user_otp_last(login, last_otp)!
UPDATE Auth
  SET last_otp = :last_otp
  WHERE login = :login;
