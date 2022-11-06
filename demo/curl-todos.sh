#! /bin/bash

req="curl -i -u calvin:sesame -X"
URL="http://0.0.0.0:5000"

# check for errors
curl -i -X GET $URL/todos/todo1            # 401
$req DELETE $URL/todos/todo0               # 404
$req POST -d stuff="WIP" $URL/todos        # 400

# exercise all methods and path
$req POST -d task="WIP 1" $URL/todos       # 201
$req GET $URL/todos/todo1                  # 200
$req DELETE $URL/todos/todo1               # 204
$req PUT -d task="WIP 2" $URL/todos/todo2  # 204
$req GET $URL/todos                        # 200
