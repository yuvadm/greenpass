import argparse
import base64
import json

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from PIL import Image
from pyzbar import pyzbar


def cert(name):
    return Path(__file__).absolute().parent / 'certs' / name


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


def create_arg_parser():
    parser = argparse.ArgumentParser("GreenPass QR code verifier")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i", "--image_path", type=Path, help="Path to an image with the QR code", default=None)
    group.add_argument(
        "-t", "--txt_path", type=Path, help="Path to decoded QR code textual content", default=None)
    return parser


if __name__ == '__main__':
    # Parse arguments
    parser = create_arg_parser()
    args = parser.parse_args()

    # Choose correct input
    if args.image_path:
        verify(read_qr_code(args.image_path))
    elif args.txt_path:
        with open(args.txt_path, 'rb') as f:
            verify(f.read().strip())
