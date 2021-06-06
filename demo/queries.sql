-- name: now^
SELECT CURRENT_TIMESTAMP;

-- name: get_stuff_all
SELECT sid, sname FROM Stuff ORDER BY 1;

-- name: get_stuff_like
SELECT sid, sname FROM Stuff WHERE sname LIKE :pattern ORDER BY 1;

-- name: get_stuff_sid^
SELECT sname FROM Stuff WHERE sid = :sid;

-- name: add_stuff!
INSERT INTO Stuff(sname) VALUES (:sname);

-- name: del_stuff_sid!
DELETE FROM Stuff WHERE sid = :sid;

-- name: upd_stuff_sid!
UPDATE Stuff SET sname = :sname WHERE sid = :sid;

-- name: get_user_data^
SELECT login, upass, admin FROM Auth WHERE login = :login;

-- name: get_user_all
SELECT login, upass, admin FROM Auth ORDER BY 1;

-- name: add_user!
INSERT INTO Auth(login, upass, admin) VALUES (:login, :upass, :admin);

-- name: add_user_login!
INSERT INTO Auth(login, upass) VALUES (:login, :upass);

-- name: del_user_login!
DELETE FROM Auth WHERE login = :login;

-- name: upd_user_password!
UPDATE Auth SET upass = :upass WHERE login = :login;

-- name: upd_user_admin!
UPDATE Auth SET admin = :admin WHERE login = :login;
