import argparse
import pathlib
import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from PIL import Image
from pyzbar import pyzbar


def cert(name):
    this_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(this_dir, 'certs', name)


def verify(qr_code_bytes):
    b64, payload = qr_code_bytes.split(b'#', maxsplit=1)
    sig = base64.decodebytes(b64)

    h = hashes.Hash(hashes.SHA256())
    h.update(payload.decode().encode('utf8'))
    digest = h.finalize()

    with open(cert("RamzorQRPubKey.pem"), "rb") as f:
        k = serialization.load_pem_public_key(f.read())
        k.verify(
            sig,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    data = json.loads(payload)

    print("Valid signature!")
    print(f"Israeli ID Number {data['p'][0]['idl']}")
    print(f"ID valid by {data['p'][0]['e']}")
    print(f"Cert Unique ID {data['id']}")


def read_qr_code(image_path):
    return pyzbar.decode(Image.open(image_path))[0].data


def parse_args():
    args = argparse.ArgumentParser("GreenPass QR code verifier")
    args.add_argument("image_path", type=pathlib.Path)
    return args.parse_args()


if __name__ == '__main__':
    args = parse_args()
    verify(read_qr_code(args.image_path))
