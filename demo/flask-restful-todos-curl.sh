#! /bin/bash
#
# run tests on todos application
#
# NOTE fails with todos-frf because "task" is expected in json

URL="http://0.0.0.0:5000"

function req()
{
  curl -si -u calvin:sesame -X "$@"
  echo
}



# check for errors
curl -si -X GET $URL/todos/todo1          # 401
req DELETE $URL/todos/todo0               # 404
req POST -d stuff="WIP 0" $URL/todos      # 400

# exercise all methods and path
req POST -d task="WIP 1" $URL/todos       # 201
req GET $URL/todos/todo1                  # 200
req DELETE $URL/todos/todo1               # 204
req PUT -d task="WIP 2" $URL/todos/todo2  # 204
req GET $URL/todos                        # 200
