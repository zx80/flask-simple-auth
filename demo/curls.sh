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
curl -i -X POST -u foo:bla -d login=z1 -d email=z@d -d pass=zz -d admin=false $URL/users
curl -i -X POST -u foo:bla -d login=z2 -d email=y@d -d pass=yy -d admin=true  $URL/users

# /users/<uid>
curl -i -X GET    -u z2:yy               $URL/users/z1  # 200
curl -i -X PATCH  -u z2:yy -d email=z1@d $URL/users/z1  # 204
curl -i -X GET    -u z1:zz               $URL/users/z1  # 200
curl -i -X PATCH  -u z1:zz -d email=z2@d $URL/users/z1  # 403
curl -i -X PATCH  -u z2:yy -d email=z2@d $URL/users/z1  # 204
curl -i -X GET    -u z1:zz               $URL/users/z1  # 200
curl -i -X GET    -u z1:zz               $URL/users/z2  # 403
curl -i -X DELETE -u z1:zz               $URL/users/z2  # 403
curl -i -X DELETE -u z1:zz               $URL/users/z1  # 204
curl -i -X DELETE -u z2:yy               $URL/users/z2  # 204

# /scare
curl -i -X POST            -d login=zz -d email=z@d -d pass=zz $URL/scare
curl -i -X GET    -u zz:zz                                     $URL/scare
curl -i -X PATCH  -u zz:zz -d opass=zz -d npass=yy             $URL/scare
curl -i -X GET    -u zz:yy                                     $URL/scare/token
curl -i -X DELETE -u zz:yy                                     $URL/scare

# /types/*
curl -i -X GET -d i=-12                        $URL/types/scalars
curl -i -X GET -d f=5432.1                     $URL/types/scalars
curl -i -X GET -d b=true                       $URL/types/scalars
curl -i -X GET -d s=hello                      $URL/types/scalars
curl -i -X GET -d j='[{"a":1},{"b":2}]'        $URL/types/json
curl -i -X GET -d j='{"pi":3.14159,"e":2.718}' $URL/types/json
curl -i -X GET -d j=12                         $URL/types/json
curl -i -X GET -d j=-12.34                     $URL/types/json
curl -i -X GET -d j=false                      $URL/types/json
