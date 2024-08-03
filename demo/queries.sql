-- NOTE RETURNING below requires SQLite 3.35

-- name: now$
SELECT CURRENT_TIMESTAMP;

-- name: get_stuff_all
SELECT sid, sname FROM Stuff ORDER BY 1;

-- name: get_stuff_like
SELECT sid, sname FROM Stuff WHERE sname LIKE :pattern ORDER BY 1;

-- name: get_stuff_sid^
SELECT sname FROM Stuff WHERE sid = :sid;

-- name: add_stuff$
INSERT INTO Stuff(sname) VALUES (:sname) RETURNING sid;

-- name: del_stuff_sid!
DELETE FROM Stuff WHERE sid = :sid;

-- name: upd_stuff_sid!
UPDATE Stuff SET sname = :sname WHERE sid = :sid;

-- we accept the email as an alternate login… with implication of caching
-- name: get_user_data^
SELECT login, email, upass, admin
FROM Auth WHERE :login IN (login, email);

-- name: get_user_all
SELECT login, email, upass, admin FROM Auth ORDER BY 1;

-- name: add_user$
INSERT INTO Auth(login, email, upass, admin)
VALUES (:login, :email, :upass, :admin)
RETURNING aid;

-- name: del_user_login!
DELETE FROM Auth WHERE :login IN (login, email);

-- name: upd_user_password!
UPDATE Auth SET upass = :upass WHERE :login IN (login, email);

-- name: upd_user_email!
UPDATE Auth SET email = :email WHERE :login IN (login, email);

-- name: upd_user_admin!
UPDATE Auth SET admin = :admin WHERE :login IN (login, email);

-- name: get_auth_all
SELECT aid, login, email, upass, admin
FROM Auth
ORDER BY 2;

-- name: get_auth_login^
SELECT aid, login, email, upass, admin
FROM Auth
WHERE login = :login;

-- FIXME should be "FOR UPDATE" but I'm not so sure about sqlite3
-- name: get_auth_aid^
SELECT aid, login, email, upass, admin
FROM Auth
WHERE aid = :aid;

-- name: add_auth$
INSERT INTO Auth(login, email, upass, admin)
  VALUES (:a.login, :a.email, :a.upass, :a.admin)
  ON CONFLICT DO NOTHING
  RETURNING aid;

-- name: change_auth!
UPDATE Auth SET
  login = :a.login,
  email = :a.email,
  upass = :a.upass,
  admin = :a.admin
WHERE aid = :a.aid;
