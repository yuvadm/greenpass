import argparse
import base64
import fitz
import json

from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from PIL import Image
from pyzbar import pyzbar


def cert(name):
    return Path(__file__).absolute().parent / "certs" / name


def verify(qr_code_bytes):
    b64, payload = qr_code_bytes.split(b"#", maxsplit=1)
    sig = base64.decodebytes(b64)

    data = json.loads(payload)
    payload = payload.decode().encode("utf8")
    if data["ct"] == 1:
        digest = payload
        for i in range(len(data["p"])):
            print(f"Details of person number {i+1}:")
            print(f"\tIsraeli ID Number {data['p'][i]['idl']}")
            print(f"\tID valid by {data['p'][i]['e']}")
        print(f"Cert Unique ID {data['id']}")
    elif data["ct"] == 2:
        h = hashes.Hash(hashes.SHA256())
        h.update(payload)
        digest = h.finalize()
        print(f"Israeli ID Number {data['idl']}")
        print(f"ID valid by {data['e']}")
        print(f"Cert Unique ID {data['id']}")
    else:
        print("Unsupported certificate type")

    with open(cert("RamzorQRPubKey.pem"), "rb") as f:
        k = serialization.load_pem_public_key(f.read())
        k.verify(
            sig,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    print("Valid signature!")


def read_qr_code(image_path):
    return pyzbar.decode(Image.open(image_path))[0].data


def read_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    for i in range(len(doc)):
        for img in doc.get_page_images(i):
            xref, width = img[0], img[2]
            if width in (
                3720,  # in green pass
                4200,  # in vaccination certificate
            ):
                img = fitz.Pixmap(doc, xref)
                data = img.getImageData(output="png")
                return read_qr_code(BytesIO(data))


def create_arg_parser():
    parser = argparse.ArgumentParser("Green Pass QR code verifier")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i",
        "--image-path",
        type=Path,
        help="Path to an image with the QR code",
        default=None,
    )
    group.add_argument(
        "-p",
        "--pdf-path",
        type=Path,
        help="Path to PDF file",
        default=None,
    )
    group.add_argument(
        "-t",
        "--txt-path",
        type=Path,
        help="Path to decoded QR code textual content",
        default=None,
    )
    return parser


if __name__ == "__main__":
    parser = create_arg_parser()
    args = parser.parse_args()

    if args.image_path:
        verify(read_qr_code(args.image_path))
    elif args.pdf_path:
        verify(read_pdf(args.pdf_path))
    elif args.txt_path:
        with open(args.txt_path, "rb") as f:
            verify(f.read().strip())
