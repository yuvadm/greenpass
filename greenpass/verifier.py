import base64
import fitz
import json

from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.exceptions import InvalidSignature
from PIL import Image
from pyzbar import pyzbar


class GreenPassVerifier(object):
    def __init__(self, data_bytes):
        self.validate_bytes(data_bytes)

        sig, self.payload = data_bytes.split(b"#", maxsplit=1)
        self.signature = base64.decodebytes(sig)
        self.data = json.loads(self.payload)

        self.validate_data()
        self.details = self.get_details()
        self.digest = self.get_digest()

        self.ec_cert = self.get_cert_path("IL-NB-DSC-01.pem")
        self.rsa_cert = self.get_cert_path("RamzorQRPubKey.pem")

    @classmethod
    def from_payload(cls, path):
        with open(path, "rb") as f:
            return cls(f.read().strip())

    @classmethod
    def from_qr(cls, path):
        return cls(pyzbar.decode(Image.open(path))[0].data)

    @classmethod
    def from_pdf(cls, path):
        doc = fitz.open(path)
        for i in range(len(doc)):
            for img in doc.get_page_images(i):
                xref, width = img[0], img[2]
                try:
                    img = fitz.Pixmap(doc, xref)
                    data = img.tobytes(output="png")
                    with open(f"/tmp/greenpass/{xref}.png", "wb") as f:
                        f.write(data)
                    return cls.from_qr(BytesIO(data))
                except IndexError:
                    pass
            else:
                raise Exception("No QR found")

    def validate_bytes(self, bs):
        if bs.decode().startswith("GreenPass"):
            raise Exception("Green pass QR code contains no signature to verify")
            # click.secho(
            #     "⚠️  ",
            #     fg="yellow",
            #     bold=True,
            # )
            # click.get_current_context().exit()

    def validate_data(self):
        ct = self.data["ct"]
        if ct not in (1, 2):
            raise Exception(f"Unknown certificate type {ct=}")

    def get_cert_path(self, name):
        return Path(__file__).absolute().parent / "certs" / name

    def get_details(self):
        details = []
        data = self.data
        if data["ct"] == 1:
            for i in range(len(data["p"])):
                details.append(
                    {
                        "id_num": data["p"][i]["idl"],
                        "valid_by": data["p"][i]["e"],
                        "cert_id": data["id"],
                    }
                )
        elif data["ct"] == 2:
            details.append(
                {
                    "id_num": data["idl"],
                    "valid_by": data["e"],
                    "cert_id": data["id"],
                }
            )
        return details

    def get_digest(self):
        ct = self.data["ct"]
        if ct == 1:
            digest = self.payload.decode().encode("utf8")
        elif ct == 2:
            h = hashes.Hash(hashes.SHA256())
            h.update(self.payload)
            digest = h.finalize()
        return digest

    def verify(self):
        for d in self.details:
            print(f"\tIsraeli ID Number {d['id_num']}")
            print(f"\tID valid by {d['valid_by']}")
            print(f"\tCert Unique ID {d['cert_id']}")

        certs = [
            [
                self.rsa_cert,
                [
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                ],
            ],
            [self.ec_cert, [ec.ECDSA(hashes.SHA256())]],
        ]
        for cert, method in certs:
            with open(cert, "rb") as f:
                k = serialization.load_pem_public_key(f.read())
                try:
                    k.verify(self.signature, self.digest, *method)
                    return True
                except InvalidSignature:
                    pass
        else:
            return False
