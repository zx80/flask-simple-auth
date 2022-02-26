#! /bin/bash

URL="http://0.0.0.0:5000"

# test routes
curl -i -X GET $URL/version  # 200
curl -i -X GET $URL/now      # 200

# authenticated user
curl -i -X GET            $URL/who  # null, 200
curl -i -X GET -u foo:bla $URL/who  # foo, 200

# /stuff
curl -i -X GET                            $URL/stuff  # 401
curl -i -X GET  -u foo:bla                $URL/stuff  # list, 200
curl -i -X GET  -u foo:bla -d pattern=H%  $URL/stuff  # sub-list, 200
curl -i -X POST -u foo:bla -d sname=Chair $URL/stuff  # sid, 201

# /stuff/<sid>
curl -i -X GET    -u foo:bla                $URL/stuff/1  # 200
curl -i -X PATCH  -u foo:bla -d sname=Table $URL/stuff/4  # 204
curl -i -X DELETE -u foo:bla                $URL/stuff/4  # 204

# /users
curl -i -X GET  -u foo:bla $URL/users  # list, 200
curl -i -X POST -u foo:bla -d login=zeo -d email=z@d -d pass=zz -d admin=false $URL/users

# /users/<uid>
curl -i -X GET    -u foo:bla               $URL/users/zeo  # 200
curl -i -X GET    -u zeo:zz                $URL/users/zeo  # 200
curl -i -X PATCH  -u foo:bla -d email=zz@d $URL/users/zeo  # 204
curl -i -X GET    -u foo:bla               $URL/users/zeo  # 200
curl -i -X GET    -u zeo:zz                $URL/users/foo  # 403
curl -i -X DELETE -u foo:bla               $URL/users/foo  # 204
