## Python Flask API that consumes Azure AD B2C access tokens and validates them using the public key from the discovery endpoint.

Partial fork from:
https://github.com/mattfeltonma/python-b2c-sample

### How to run

1. Create an `.env` file and fill in the required values. You can use the `.env.sample` file as a template.
2. Install the needed dependencies with `pip install -r requirements.txt`
3. Start the server with `python server.py`

### Testing the API

Try calling
```
http://localhost:3333/api/public
```

This should result in a `200 OK`.

You can then try to do a GET to
```
http://localhost:3333/api/private
```
which will throw an error if you don't send an access token signed with RS256 with the appropriate issuer and audience in the Authorization header. 

You can also try to do a GET to 
```
http://localhost:3333/api/private-scoped
```
which will throw an error if you don't send an access token with the scope `demo.write` signed with RS256 with the appropriate issuer and audience in the Authorization header.

A `test.rest` file is included that you can use to test the API with `curl` or [VS Code REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client).