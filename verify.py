import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

sig = base64.b64decode("base64EncodedSignature==")

payload = '{"id":"01/IL/ABCD1234ABCD1234ABCD1234ABCD1234#ABCD1234","et":1,"ct":1,"c":"IL MOH","cn":null,"fn":null,"g":null,"f":null,"gl":null,"fl":null,"idp":null,"idl":null,"b":"0001-01-01","e":"0001-01-01","a":"0001-01-01","p":[{"idl":"0123456789","e":"2021-01-01"}]}'

h = hashes.Hash(hashes.SHA256())
h.update(payload.encode("utf-8"))
digest = h.finalize()

with open("certs/RamzorQRPubKey.pem", "rb") as f:
    k = serialization.load_pem_public_key(f.read())
    k.verify(
        sig,
        digest,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


data = json.loads(payload)
print(f"Israeli ID Number {data['p'][0]['idl']}")
print(f"ID valid by {data['p'][0]['e']}")
print(f"Cert Unique ID {data['id']}")
