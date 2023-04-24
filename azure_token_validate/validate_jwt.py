import requests
import jwt
import json
from datetime import datetime, timedelta
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
    print("Header algo: %s" % token_alg)
    print("Header kid: %s" % token_kid)

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

    print("SUCCESS. Decodeds, verified Signature")
    return decoded_token


def has_token_expired(exp_value):
    """
    Check if JWT has expired
    :param exp_value:
    :return: True/False
    """
    expiration_time = datetime.utcfromtimestamp(exp)
    print("Token expiry (UTC): %s" % str(expiration_time))
    return datetime.utcnow() > expiration_time


if __name__ == '__main__':
    access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyIsImtpZCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyJ9.eyJhdWQiOiJhcGk6Ly9mYWNmZTQ2Ny04NjYwLTQwZjktYWNkMC1jMzk3ZDkwODgxNjgiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82MjlhZjU0NS04NjExLTQ0YWYtOWZlYy05YTA5OGQzZTgwY2EvIiwiaWF0IjoxNjgyMzEzMjYyLCJuYmYiOjE2ODIzMTMyNjIsImV4cCI6MTY4MjMxNzE2MiwiYWlvIjoiRTJaZ1lHRE04VERwK05yQ3VITWhqM0hLMDdvREFBPT0iLCJhcHBpZCI6ImZhY2ZlNDY3LTg2NjAtNDBmOS1hY2QwLWMzOTdkOTA4ODE2OCIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzYyOWFmNTQ1LTg2MTEtNDRhZi05ZmVjLTlhMDk4ZDNlODBjYS8iLCJvaWQiOiI2N2UyNTdkYy01NWFkLTQ0OTQtODVjMy1kZmEwZGNmOWY0N2YiLCJyaCI6IjAuQVVvQVJmV2FZaEdHcjBTZjdKb0pqVDZBeW1ma3pfcGdodmxBck5ERGw5a0lnV2lKQUFBLiIsInN1YiI6IjY3ZTI1N2RjLTU1YWQtNDQ5NC04NWMzLWRmYTBkY2Y5ZjQ3ZiIsInRpZCI6IjYyOWFmNTQ1LTg2MTEtNDRhZi05ZmVjLTlhMDk4ZDNlODBjYSIsInV0aSI6IkxQUzJpY2syVVVtSUJURWM0NmxFQUEiLCJ2ZXIiOiIxLjAifQ.f6xH-pTCHRaWRB1muzfbmszCYSjzM1874-wJ6ylCRl1w03nnfzSsEs296efRV_zqVgayQ_kpMjbjsZlh8C9hWoMRtjQdFskC_gyvnEgf58VMlZPJiBTv37k6lZ3OzSN8uPaeiF1DlnT5EocD0gjt9w6SP-ognW_tI4iJG1aOLFkUQWOOYtMU3ByaifYSrs_5WbQ1BMKELIOGqIvQ_brfgvIBWBclzSwF0AMovw5WMpN_KuVEOqT9B5aKcp24cHm6xWPV8shSURf9TsbTliDYj64p6CKboTY1i3aTwtsa3Q98q6H9BCwCjVxSZKjXkN22HKIqjVr7GY5M_ItYAHvFnA'
    decoded_token = validate(access_token)

    aud = decoded_token.get('aud', None)
    exp = decoded_token.get('exp', None)
    # Check if the token has expired
    if has_token_expired(exp):
        print("Error: JWT token has expired")

    print("audience: %s" % aud)


