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
