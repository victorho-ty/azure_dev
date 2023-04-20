import requests
import jwt
import json
# pip install pyjwt
#import msal

"""
Note: Programmatic validation of Azure JWT must NOT contain 'nonce' field in Jwt.Header
      'nonce' is added for MS Graph scope when requesting for JWT.
A good example:
    {
      "typ": "JWT",
      "alg": "RS256",
      "x5t": "-KI3Q9nNR7bRofxmeZoXqbHZGew",
      "kid": "-KI3Q9nNR7bRofxmeZoXqbHZGew"
    }
"""

def get_public_key(token, token_kid):
    from cryptography.hazmat.primitives import serialization

    jwk = None
    response = requests.get("https://login.microsoftonline.com/common/discovery/keys")
    jwks = response.json()['keys']
    for key in jwks:
        # grep the public key matching on "kid" key id
        if key['kid'] == token_kid:
            jwk = key
    if jwk is None:
        raise Exception('kid not recognized')

    print("Matching JWK: %s" % jwk)
    rsa_pem_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    rsa_pem_key_bytes = rsa_pem_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return rsa_pem_key_bytes


def validate(access_token):
    token_headers = jwt.get_unverified_header(access_token)
    token_alg = token_headers['alg']
    token_kid = token_headers['kid']
    print("Token algo: %s" % token_alg)
    print("Token kid: %s" % token_kid)

    public_key = get_public_key(access_token, token_kid)

    print("Pub Key Found, decoding JWT...")
    # aud = Azure App Id
    decoded_token = jwt.decode(
        access_token,
        key=public_key,
        verify=True,
        algorithms=[token_alg],
        audience=["api://facfe467-8660-40f9-acd0-c397d9088168"]
    )

    print("SUCCESS in decoding, verified Signature")
    print(decoded_token)


if __name__ == '__main__':
    access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyIsImtpZCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyJ9.eyJhdWQiOiJhcGk6Ly9mYWNmZTQ2Ny04NjYwLTQwZjktYWNkMC1jMzk3ZDkwODgxNjgiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82MjlhZjU0NS04NjExLTQ0YWYtOWZlYy05YTA5OGQzZTgwY2EvIiwiaWF0IjoxNjgxOTc1MjA0LCJuYmYiOjE2ODE5NzUyMDQsImV4cCI6MTY4MTk3OTEwNCwiYWlvIjoiRTJaZ1lQaW1sZjBzcWZsYThvK2JGbytmaFlmZUJRQT0iLCJhcHBpZCI6ImZhY2ZlNDY3LTg2NjAtNDBmOS1hY2QwLWMzOTdkOTA4ODE2OCIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzYyOWFmNTQ1LTg2MTEtNDRhZi05ZmVjLTlhMDk4ZDNlODBjYS8iLCJvaWQiOiI2N2UyNTdkYy01NWFkLTQ0OTQtODVjMy1kZmEwZGNmOWY0N2YiLCJyaCI6IjAuQVVvQVJmV2FZaEdHcjBTZjdKb0pqVDZBeW1ma3pfcGdodmxBck5ERGw5a0lnV2lKQUFBLiIsInN1YiI6IjY3ZTI1N2RjLTU1YWQtNDQ5NC04NWMzLWRmYTBkY2Y5ZjQ3ZiIsInRpZCI6IjYyOWFmNTQ1LTg2MTEtNDRhZi05ZmVjLTlhMDk4ZDNlODBjYSIsInV0aSI6IlNVQ1E0VVdWSmtHQWNMODR2SWRMQUEiLCJ2ZXIiOiIxLjAifQ.Qc0-NwBhoFmXEbtsxYVN2N8pcbISjP12cjRhxm6FJ1KdaVwHaH1iCvshOej0rrfN8dd_kG--wJW9aqp1f5RdYc9iDlkAlYdDgJB-UvRhLSgSezt_XRocO-G0IcU4dwHt6r_nCuJfC3jupHjQ6RpqjYhT4az3iJ_LxTo5Njks7sKye-43Mr5lDULDgyT1C-gYptjjs0pHaco3e6Rnsy5Y2FqP-R2ekgDBg9douC9r29sVHMT-g6aGsPOfHiC4xvjOqYllpHN8jWL6z2tl9p0lJv77B4ee_s7LyQ6pjkyXyo8Q05FTRSIC7J4MX4i2IydOmpXU25TVlBsZpcearSMXOQ'
    validate(access_token)
