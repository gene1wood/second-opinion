import json
from oic.utils.keyio import build_keyjar

key_conf = [
    {'use': ['enc', 'sig'],
     'type': 'RSA'},
    {'use': ['sig'],
     'type': 'EC',
     'crv': 'P-256'},
    {'use': ['enc'],
     'type': 'EC',
     'crv': 'P-256'}
]

_, keyjar, _ = build_keyjar(key_conf)
print(json.dumps(keyjar.export_jwks(private=True)))