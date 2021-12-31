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

from .verifiers.il import IsraeliVerifier
from .verifiers.eu import EuroVerifier


class CertificateData(object):
    def __init__(self, data):
        self.data = data

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
                    return cls.from_qr(BytesIO(data))
                except IndexError:
                    pass
            else:
                raise Exception("No QR found")

    def verify(self):
        # EU certs start with HC1
        if self.data.startswith("HC1:"):
            return EuroVerifier(self.data)
        else:
            try:
                # Legacy IL certs split the sig and the payload with '#'
                _sig, _payload = self.data.split(b"#", maxsplit=1)
                return IsraeliVerifier(self.data)
            except ValueError:
                raise Exception(f"Unknown certificate data: {self.data}")
