#! /bin/bash

URL="http://0.0.0.0:5000"

# run curl and get the status on the last line
function curl()
{
  local status="$1"
  shift 1
  code=$(command curl -w "\\n%{http_code}" "$@" | tee /dev/tty | tail -1)
  if [ "$code" != "$status" ] ; then
    echo "on: curl $@"
    echo "unexpected $code for $status"
  fi >&2
}

# test routes
curl 200 -si -X GET $URL/version
curl 200 -si -X GET $URL/now

# authenticated user
curl 200 -si -X GET            $URL/who  # null
curl 200 -si -X GET -u foo:bla $URL/who  # foo

# /stuff
curl 401 -si -X GET                            $URL/stuff
curl 200 -si -X GET  -u foo:bla                $URL/stuff  # list
curl 200 -si -X GET  -u foo:bla -d pattern=H%  $URL/stuff  # sub-list
curl 201 -si -X POST -u foo:bla -d sname=Chair $URL/stuff  # sid

# /stuff/<sid>
curl 200 -si -X GET    -u foo:bla                $URL/stuff/1
curl 204 -si -X PATCH  -u foo:bla -d sname=Table $URL/stuff/4
curl 204 -si -X DELETE -u foo:bla                $URL/stuff/4

# /users
curl 200 -si -X GET  -u foo:bla $URL/users  # list
curl 201 -si -X POST -u foo:bla -d login=z1 -d email=z@d -d pass=zz -d admin=false $URL/users
curl 201 -si -X POST -u foo:bla -d login=z2 -d email=y@d -d pass=yy -d admin=true  $URL/users

# /users/<uid>
curl 200 -si -X GET    -u z2:yy               $URL/users/z1
curl 204 -si -X PATCH  -u z2:yy -d email=z1@d $URL/users/z1
curl 200 -si -X GET    -u z1:zz               $URL/users/z1
curl 403 -si -X PATCH  -u z1:zz -d email=z2@d $URL/users/z1
curl 204 -si -X PATCH  -u z2:yy -d email=z2@d $URL/users/z1
curl 200 -si -X GET    -u z1:zz               $URL/users/z1
curl 403 -si -X GET    -u z1:zz               $URL/users/z2
curl 403 -si -X DELETE -u z1:zz               $URL/users/z2
curl 204 -si -X DELETE -u z1:zz               $URL/users/z1
curl 204 -si -X DELETE -u z2:yy               $URL/users/z2

# /scare
curl 201 -si -X POST            -d login=zz -d email=z@d -d pass=zz $URL/scare
curl 200 -si -X GET    -u zz:zz                                     $URL/scare
curl 204 -si -X PATCH  -u zz:zz -d opass=zz -d npass=yy             $URL/scare
curl 200 -si -X GET    -u zz:yy                                     $URL/scare/token
curl 204 -si -X DELETE -u zz:yy                                     $URL/scare

# /types/*
curl 200 -si -X GET -d i=-12                        $URL/types/scalars
curl 200 -si -X GET -d f=5432.1                     $URL/types/scalars
curl 200 -si -X GET -d b=true                       $URL/types/scalars
curl 200 -si -X GET -d s=hello                      $URL/types/scalars
curl 200 -si -X GET -d j='[{"a":1},{"b":2}]'        $URL/types/json
curl 200 -si -X GET -d j='{"pi":3.14159,"e":2.718}' $URL/types/json
curl 200 -si -X GET -d j=12                         $URL/types/json
curl 200 -si -X GET -d j=-12.34                     $URL/types/json
curl 200 -si -X GET -d j=false                      $URL/types/json
