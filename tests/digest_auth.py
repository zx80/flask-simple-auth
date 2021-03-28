import AppHttpAuth as aha
app = aha.create_app_digest(SECRET_KEY="Hello World!")
# example manual test:
# make APP=digest_auth run
# curl -i -X GET --digest -u dad:mum -c cookie.txt http://0.0.0.0:5000/digest
