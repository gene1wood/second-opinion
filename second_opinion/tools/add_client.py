from __future__ import print_function
from builtins import input
from oic import rndstr
from oic.oic.provider import secret
from future.backports.urllib.parse import urlparse
from future.backports.urllib.parse import splitquery
from future.moves.urllib.parse import parse_qs
import sys
import json
from credstash import putSecret

# This is based off of client_management from pyoidc
# https://github.com/OpenIDC/pyoidc/blob/master/src/oic/utils/client_management.py

REGION="us-west-2"

def pack_redirect_uri(redirect_uris):
    ruri = []
    for uri in redirect_uris:
        if urlparse(uri).fragment:
            print("Faulty redirect uri, contains fragment", file=sys.stderr)
        base, query = splitquery(uri)
        if query:
            ruri.append([base, parse_qs(query)])
        else:
            ruri.append([base, query])

    return ruri


print(
    'Enter redirect_uris one at the time, end with a blank line: ')
redirect_uris = []
while True:
    redirect_uri = input('?: ')
    if redirect_uri:
        redirect_uris.append(redirect_uri)
    else:
        break

policy_uri = input("Enter policy_uri or just return: ")

logo_uri = input("Enter logo_uri or just return: ")

jwks_uri = input("Enter jwks_uri or just return: ")

# No protection here against a collision with an existing client_id
client_id = rndstr(12)

client_secret = secret(
    rndstr(32).encode("utf-8"),
    client_id
)

info = {
    "client_id": client_id,
    "client_salt": rndstr(8),
    "redirect_uris": pack_redirect_uri(redirect_uris),
    "token_endpoint_authn_method": "client_secret_post"
}

if policy_uri:
    info["policy_uri"] = policy_uri
if logo_uri:
    info["logo_uri"] = logo_uri
if jwks_uri:
    info['jwks_uri'] = jwks_uri

print("")
print("Share the following information with the client through a secure "
      "channel")
print("")
print("Client ID : %s" % client_id)
print("Client Secret : %s" % client_secret)
print("Allowed redirect URIs: %s" % info['redirect_uris'])
print("")
print("Add the following new client information to the config")
print(json.dumps({'OP_CLIENT_DB': {client_id: info}}, indent=2))
print("")
input("Would you like to store the client secret in credstash in %s?" % REGION)

name = "second-opinion:client_secret:%s" % client_id
if putSecret(
    name=name,
    secret=client_secret,
    region=REGION,
    context={"application": "second-opinion"}
):
    print("%s has been stored" % name)
else:
    print("storing to credstash failed")