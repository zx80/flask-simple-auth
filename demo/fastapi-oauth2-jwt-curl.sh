#! /bin/bash

URL=http://localhost:5000

jwt_token=$(
  curl -s -X POST -d username=johndoe -d password=secret $URL/token |
  tee /dev/tty | jq .access_token | tr -d '"')

echo "# JWT Token: $jwt_token"

curl -si -X GET -H "Authorization: Bearer $jwt_token" $URL/users/me
curl -si -X GET -H "Authorization: Bearer $jwt_token" $URL/users/me/items
